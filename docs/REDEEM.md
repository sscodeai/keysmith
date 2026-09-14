# Redemption: use a secret without reading it

Masked views keep a value out of the agent's context, but they also make the
value unusable: `sk******ij` cannot be sent anywhere. The alternative people
reach for is `get --unsafe`, which puts the plaintext into the transcript — the
exact outcome the store exists to prevent.

Redemption closes that gap. The agent works with a **token**, and the real value
is substituted **on this machine**, into the environment of a command that
keysmith starts. The value never enters a model request, a tool result, a
transcript, or an argument list.

```text
agent writes:   keysmith run --env AUTH='Bearer [[keysmith:v1:DEMO_KEY:8f3a2b1c]]' -- sh -c 'curl -H "Authorization: $AUTH" https://api.example.test'
what runs:      AUTH=Bearer <the real value>   (in the child's environment)
what is visible anywhere else: the token — a reference, not a secret
```

## Token format

```text
[[keysmith:v1:NAME:sid8]]
```

| Part | Meaning |
|---|---|
| `v1` | Encoding and session-semantics version. A future change ships as `v2`; unknown versions are refused, never guessed. |
| `NAME` | The store key name, `[A-Za-z0-9_.-]{1,64}`. Readable on purpose: the agent can reason about *which* credential it is handling without holding it. |
| `sid8` | First 8 hex characters of the issuing session id. The token is honoured only while that session exists, is unexpired, and had `NAME` issued in it. |

A token is not ciphertext. There is nothing secret in it — it is a capability
that only this store can redeem, only for a limited time, and only for the names
listed in its session.

## Sessions

```sh
TOKEN=$(keysmith token DEMO_KEY)          # stdout: the token. stderr: session + expiry.
TOKEN=$(keysmith token DEMO_KEY --ttl 15m)
```

- Issuing reuses the current session while it is valid, so several tokens issued
  in a row share one session and one expiry. `--ttl` (default `1h`) extends it.
- Issuing fails closed: a token is never created for a name the store cannot
  resolve.
- Session state lives in `<store>/sessions/` (dir `0700`, files `0600`). A
  session id is not a secret, but it is scoped: the value still has to come from
  the encrypted store.
- Replay is bounded by the session: a token copied out of an old transcript, a
  committed file, or a previous session is refused.

## `keysmith run`

```sh
keysmith run [--session SID] --env KEY='<template>' [--env ...] -- <command> [args...]
```

Each `--env` value is a template. Tokens inside it are replaced before the
command starts, and the result goes into the child's environment under `KEY`.

Because `argv` is readable by every user on the machine through `ps`, a token in
the command arguments is **refused**. The error message shows the safe pattern
instead of quietly doing the risky thing:

```sh
# refused
keysmith run --env X=1 -- curl -H "Authorization: Bearer [[keysmith:v1:DEMO_KEY:8f3a2b1c]]" https://…

# accepted — the shell expands $AUTH inside the child, so argv stays clean
keysmith run --env AUTH='Bearer [[keysmith:v1:DEMO_KEY:8f3a2b1c]]' -- sh -c 'curl -H "Authorization: $AUTH" https://…'
```

The child's exit code is propagated, so `run` is safe in scripts and pipelines.
`KEYSMITH_SESSION` is stripped from the child's environment.

## Fail-closed rules

Every one of these aborts **before the child process starts**. There is no
fallback that forwards a literal token, and no fallback that sends the value.

| Condition | Result |
|---|---|
| Unknown session id in the token | refuse |
| Expired session | refuse |
| Name not issued in that session | refuse |
| Name absent from the store, or stored value is empty | refuse |
| Malformed or truncated reserved prefix (`[[keysmith:` present but no valid token) | refuse |
| Token anywhere in the command arguments | refuse |
| Audit record cannot be written | refuse |
| Any resolution error in one `--env` while another resolved fine | refuse — nothing is exported and nothing runs |

## Audit log

`<store>/audit.log` (mode `0600`) gets one JSON line per redeemed command:

```json
{"ts":"2026-09-14T02:11:07Z","session":"8f3a2b1c","keys":["DEMO_KEY"],"command":"curl","argc":3,"pid":41231}
```

Key *names*, session, command basename, argument count, pid. Deliberately no
values — and no full argument list either, because an argument list can itself
contain a secret someone inlined by hand.

## What this does not do (yet)

- **No multi-target policy.** A token can be redeemed into any command. A
  binding of "this token may only go to host X" is the next step, and it is the
  control that stops a compromised agent from redeeming a value and posting it
  somewhere else.
- **No local HTTP proxy.** Only processes started through `keysmith run` are
  covered. A loopback proxy would cover tools that build their own requests.
- **No OS-level isolation.** A process running as your user can still read the
  store key and the session files. See `docs/THREAT-MODEL.md` for what is
  explicitly out of scope.
- **No nesting.** A stored value that itself contains a token is inserted
  literally.

## Verifying it yourself

```sh
go test ./...            # unit tests, including the fail-closed cases
python3 verify_redeem.py # real processes: child env vs /proc/<pid>/cmdline and audit log
```

`verify_redeem.py` uses synthetic values, reads the live child's `/proc/<pid>/cmdline`
and `/proc/<pid>/environ` to prove the value reached the child and never reached
`argv`, and asserts that the audit log contains no value. It prints no secret.
