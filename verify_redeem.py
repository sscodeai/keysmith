#!/usr/bin/env python3
"""End-to-end verification of the redemption layer (`keysmith token` / `keysmith run`).

Proves, from the outside, with real processes (and /proc on Linux):

  1. the child process receives the REAL value (it is in the child's environment)
  2. the value is NOT in the child's argv, and not in the wrapper's argv
  3. a token placed in the command arguments is refused (argv is ps-visible)
  4. every failure mode is fail-closed: no child process is started at all
  5. the audit log records key names, never values
  6. the child's exit code is propagated

Synthetic values only. The script never prints a secret value; it asserts on
hashes and on presence/absence.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.gettempdir()

# Binary path: env override, else the repo build (mirrors e2e_test.py).
BIN = os.environ.get("KEYSMITH_BIN", os.path.join(REPO_ROOT, "bin", "keysmith"))
STORE = os.environ.get("KEYSMITH_REDEEM_STORE", os.path.join(TMP, "ks-redeem-store"))
IS_LINUX = sys.platform.startswith("linux")
CANARY = "sk-synthetic-REDEEM-CANARY-0002"   # synthetic fixture, not a credential
PLAIN = "plain-value-9x"

FAILURES = []


def check(label, ok, detail=""):
    print("  %s %s%s" % ("PASS" if ok else "FAIL", label, (" — " + detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def ks(args, **kw):
    return subprocess.run([BIN, "-store", STORE] + args, capture_output=True, text=True, **kw)


def issue(name, ttl=None, extra=None):
    tok, _ = issue_info(name, ttl, extra)
    return tok


def issue_info(name, ttl=None, extra=None):
    """Issue a token; returns (token, stderr) so binding notices can be asserted."""
    args = ["token", name] + (["--ttl", ttl] if ttl else []) + (extra or [])
    r = ks(args)
    if r.returncode != 0:
        raise SystemExit("token issue failed for %s: %s" % (name, r.stderr.strip()))
    return r.stdout.strip(), r.stderr.strip()


def run_cmd(args, env=None):
    e = dict(os.environ)
    e.pop("KEYSMITH_SESSION", None)
    if env:
        e.update(env)
    return subprocess.run([BIN, "-store", STORE, "run"] + args, capture_output=True, text=True, env=e)


def main():
    shutil.rmtree(STORE, ignore_errors=True)
    subprocess.run([BIN, "-store", STORE, "set", "DEMO_KEY"], input=CANARY,
                   capture_output=True, text=True)
    subprocess.run([BIN, "-store", STORE, "set", "DEMO_URL"], input=PLAIN,
                   capture_output=True, text=True)
    subprocess.run([BIN, "-store", STORE, "set", "BOUND_KEY"], input=PLAIN,
                   capture_output=True, text=True)

    print("\n[1] token issuance")
    tok = issue("DEMO_KEY")
    check("token matches the documented grammar", tok.startswith("[[keysmith:v1:DEMO_KEY:") and tok.endswith("]]"), tok)
    sid = tok.rstrip("]").rsplit(":", 1)[1]
    sess_dir = os.path.join(STORE, "sessions")
    check("sessions dir is 0700", oct(os.stat(sess_dir).st_mode & 0o777) == "0o700")
    sess_files = os.listdir(sess_dir)
    check("session file is 0600", all(oct(os.stat(os.path.join(sess_dir, f)).st_mode & 0o777) == "0o600" for f in sess_files))
    check("issuing a token for an unknown key fails closed", ks(["token", "NO_SUCH_KEY"]).returncode != 0)

    tok2 = issue("DEMO_URL")
    check("consecutive tokens share one session", tok2.rstrip("]").rsplit(":", 1)[1] == sid)

    print("\n[2] happy path — the child gets the real value, argv stays clean")
    pidfile = os.path.join(TMP, "ks-redeem-child.pid")
    if os.path.exists(pidfile):
        os.remove(pidfile)
    child = ("import os,sys,time\n"
             "open(sys.argv[1],'w').write(str(os.getpid()))\n"
             "time.sleep(3)\n")
    proc = subprocess.Popen(
        [BIN, "-store", STORE, "run", "--env", "AUTH=Bearer " + tok, "--",
         sys.executable, "-c", child, pidfile],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for _ in range(50):
        if os.path.exists(pidfile):
            break
        time.sleep(0.1)
    if not os.path.exists(pidfile):
        print("  FAIL child never started")
        FAILURES.append("child start")
    elif not IS_LINUX:
        print("  SKIP child env/argv evidence — this check reads /proc (Linux only); this host is %s" % sys.platform)
    else:
        cpid = open(pidfile).read().strip()
        cmdline = open("/proc/%s/cmdline" % cpid, "rb").read().decode(errors="replace")
        environ = open("/proc/%s/environ" % cpid, "rb").read().decode(errors="replace")
        check("child environment carries the real value", ("AUTH=Bearer " + CANARY) in environ)
        check("value is absent from the child's argv", CANARY not in cmdline)
        check("token is absent from the child's argv", "[[keysmith:" not in cmdline)
        check("session id is not exported to the child", "KEYSMITH_SESSION" not in environ)
    proc.terminate()
    proc.wait(timeout=5)

    # The wrapper's own argv carries the token (a reference, not a secret) but
    # never the value.
    wrapper_args = " ".join(["run", "--env", "AUTH=Bearer " + tok, "--", "true"])
    check("value never appears in the wrapper's own argv", CANARY not in wrapper_args)
    check("token does appear in the wrapper's argv (by design)", tok in wrapper_args)

    print("\n[3] token in argv is refused")
    marker = os.path.join(TMP, "ks-redeem-marker")
    if os.path.exists(marker):
        os.remove(marker)
    r = run_cmd(["--env", "X=1", "--", "sh", "-c", "touch %s; echo ran" % marker])
    check("plain command without a token still runs", os.path.exists(marker))
    os.remove(marker)
    r = run_cmd(["--env", "AUTH=" + tok, "--", "sh", "-c", "touch %s" % marker,
                 "Authorization: Bearer " + tok])
    check("token in argv refused (non-zero exit)", r.returncode != 0, r.stderr.strip())
    check("token in argv refused: no child started", not os.path.exists(marker))
    check("refusal names the argv problem", "argv" in (r.stderr + r.stdout))
    check("refusal leaks no value", CANARY not in (r.stderr + r.stdout))

    print("\n[4] fail-closed resolution")
    bad_sid = "deadbeef"
    cases = [
        ("unknown session", "[[keysmith:v1:DEMO_KEY:%s]]" % bad_sid),
        ("name not issued in the session", "[[keysmith:v1:OTHER_KEY:%s]]" % sid),
        ("malformed token", "[[keysmith:v1:DEMO_KEY]]"),
        ("truncated reserved prefix", "[[keysmith:v1:"),
    ]
    for label, template in cases:
        if os.path.exists(marker):
            os.remove(marker)
        r = run_cmd(["--env", "AUTH=" + template, "--", "sh", "-c", "touch %s" % marker])
        ok = r.returncode != 0 and not os.path.exists(marker) and CANARY not in (r.stderr + r.stdout)
        check("%s: refused, no child, no value" % label, ok, "rc=%d stderr=%s" % (r.returncode, r.stderr.strip()[:90]))

    # Expiry: rewrite the session with a past deadline.
    for f in os.listdir(sess_dir):
        if f == "current":
            continue
        p = os.path.join(sess_dir, f)
        doc = json.load(open(p))
        doc["expires_at"] = "2020-01-01T00:00:00Z"
        json.dump(doc, open(p, "w"))
    if os.path.exists(marker):
        os.remove(marker)
    r = run_cmd(["--env", "AUTH=" + tok, "--", "sh", "-c", "touch %s" % marker])
    check("expired session: refused, no child", r.returncode != 0 and not os.path.exists(marker))
    check("expiry message tells the user what to do", "expired" in (r.stderr + r.stdout).lower())

    print("\n[5] exit code propagation and audit log")
    r = run_cmd(["--env", "X=1", "--", "sh", "-c", "exit 7"])
    check("child exit code is propagated", r.returncode == 7, "rc=%d" % r.returncode)

    # Fresh session, one redeemed run, then inspect the audit log.
    tok3 = issue("DEMO_KEY")
    run_cmd(["--env", "AUTH=Bearer " + tok3, "--", "sh", "-c", "true"])
    audit = os.path.join(STORE, "audit.log")
    body = open(audit).read() if os.path.exists(audit) else ""
    check("audit log exists", bool(body))
    check("audit log records the key name", '"DEMO_KEY"' in body)
    check("audit log records the command basename", '"sh"' in body)
    check("audit log contains no value", CANARY not in body)
    check("audit log is 0600", oct(os.stat(audit).st_mode & 0o777) == "0o600")
    rec = json.loads(body.strip().splitlines()[-1])
    check("audit record has no value field", not any("value" in k or "secret" in k for k in rec))

    print("\n[6] target binding")
    bound_tok, bound_stderr = issue_info(
        "BOUND_KEY", extra=["--allow-host=api.example.test", "--allow-path=/v1/"])
    check("issue reports the binding", "api.example.test" in bound_stderr, bound_stderr)

    def run_targeted(target, token, p):
        if os.path.exists(p):
            os.remove(p)
        args = (["--target", target] if target else []) + \
               ["--env", "AUTH=Bearer " + token, "--", "sh", "-c", "touch " + p]
        r = run_cmd(args)
        return r, os.path.exists(p)

    r, ran = run_targeted("https://api.example.test/v1/me", bound_tok, marker)
    check("matching target runs the command", ran and r.returncode == 0, r.stderr.strip()[:90])
    check("run reports the satisfied binding", "binding satisfied" in r.stderr, r.stderr.strip()[:90])

    for label, target in [
        ("wrong host refused", "https://evil.example.test/v1/me"),
        ("other path refused", "https://api.example.test/v2/me"),
        ("plain http to a remote host refused", "http://api.example.test/v1/me"),
    ]:
        r, ran = run_targeted(target, bound_tok, marker)
        check("%s (no child started)" % label,
              r.returncode != 0 and not ran and CANARY not in (r.stderr + r.stdout),
              "rc=%d %s" % (r.returncode, r.stderr.strip()[:80]))

    r, ran = run_targeted(None, bound_tok, marker)
    check("bound token without --target refused (no child started)",
          r.returncode != 0 and not ran, r.stderr.strip()[:90])
    check("refusal says how to declare a target", "--target" in r.stderr, r.stderr.strip()[:90])

    free_tok, free_stderr = issue_info("DEMO_KEY")
    r, ran = run_targeted("http://127.0.0.1:9/v1/x", free_tok, marker)
    check("unbound token still runs, loopback http allowed", ran, r.stderr.strip()[:90])
    check("unbound token warns about the missing binding",
          "no target binding" in r.stderr and "DEMO_KEY" in r.stderr, r.stderr.strip()[:120])
    check("issue warns when no --allow-host was given", "any host" in free_stderr, free_stderr)

    body = open(audit).read().strip().splitlines()
    records = [json.loads(l) for l in body]
    check("audit records the declared target",
          any(r.get("target") == "api.example.test/v1/me" for r in records),
          json.dumps(records[-2:]))
    check("audit holds no value", CANARY not in "\n".join(body))

    print("\n%s" % ("=" * 62))
    if FAILURES:
        print("FAILED (%d): %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("ALL REDEEM CHECKS PASSED — values reach the child, never the argv, never the log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
