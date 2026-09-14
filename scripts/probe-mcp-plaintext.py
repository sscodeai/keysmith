#!/usr/bin/env python3
"""Probe: can an AI agent obtain a PLAINTEXT secret from the MCP layer?

Drives the real binary over MCP stdio (the agent's path) and over the CLI (the
human's path), and checks the on-disk blob. Uses synthetic values only and never
prints a value.

    python3 scripts/probe-mcp-plaintext.py

Exit code is 0 when no plaintext path exists over MCP; 1 if one is found.
"""
import json
import os
import shutil
import subprocess
import sys

BIN = os.environ.get("KEYSMITH_BIN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "keysmith"))
STORE = os.environ.get("KEYSMITH_PROBE_STORE", "/tmp/ks-probe-store")
CANARY = "sk-synthetic-CANARY-0001"   # synthetic fixture, not a real credential


def send(p, msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()


def recv(p):
    line = p.stdout.readline()
    return json.loads(line) if line else None


def rpc(p, rid, method, params):
    send(p, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    return recv(p)


def main():
    shutil.rmtree(STORE, ignore_errors=True)
    seed = subprocess.run([BIN, "-store", STORE, "set", "DEMO_KEY"],
                          input=CANARY, capture_output=True, text=True)
    print("[seed] exit=%d stdout=%r" % (seed.returncode, seed.stdout.strip()))

    p = subprocess.Popen([BIN, "-store", STORE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    rpc(p, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "audit", "version": "1.0"}})
    send(p, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    tools = rpc(p, 2, "tools/list", {})["result"]["tools"]
    print("\n[MCP] tools exposed to an agent:")
    for t in tools:
        props = sorted(((t.get("inputSchema") or {}).get("properties") or {}).keys())
        print("  - %-8s params=%s" % (t["name"], props))

    leaks = []
    attempts = [
        ("get", {"key": "DEMO_KEY"}),
        ("get", {"key": "DEMO_KEY", "unsafe": True}),
        ("get", {"key": "DEMO_KEY", "--unsafe": True}),
        ("list", {}),
        ("list", {"unsafe": True}),
    ]
    print("\n[MCP] attempts to reach plaintext:")
    for i, (name, args) in enumerate(attempts, start=10):
        r = rpc(p, i, "tools/call", {"name": name, "arguments": args})
        body = (r.get("result") or {}).get("content", [{}])[0].get("text", "")
        err = (r.get("error") or {}).get("message", "")
        out = body or err
        if CANARY in out or CANARY in json.dumps(r):
            leaks.append((name, args))
        print("  %-8s args=%-34s -> %s" % (name, json.dumps(args), out.strip().replace("\n", " | ")[:110]))

    res = rpc(p, 20, "resources/read", {"uri": "secret://secrets"})
    rtext = res["result"]["contents"][0]["text"]
    print("\n[MCP] resources/read secret://secrets -> %s" % rtext.strip().replace("\n", " | "))
    if CANARY in rtext:
        leaks.append(("resource", "secret://secrets"))

    p.terminate()
    p.wait(timeout=5)

    cli_unsafe = subprocess.run([BIN, "-store", STORE, "get", "DEMO_KEY", "--unsafe"],
                                capture_output=True, text=True)
    blob = open(os.path.join(STORE, "secrets.enc"), "rb").read()

    print("\n[CLI] get DEMO_KEY --unsafe -> plaintext returned: %s" % (CANARY in cli_unsafe.stdout))
    print("[disk] secrets.enc contains the canary: %s" % (CANARY.encode() in blob))
    print("\n=== RESULT: MCP plaintext leaks = %d %s" % (len(leaks), leaks if leaks else "(none)"))
    print("=== RESULT: plaintext reachable only outside MCP: %s" % (CANARY in cli_unsafe.stdout))
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
