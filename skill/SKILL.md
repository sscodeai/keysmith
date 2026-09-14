---
name: keysmith
description: "Route ALL secret operations through the keysmith MCP server — never read .env/secret files directly. Values stay masked; plaintext never enters context; use `keysmith run` to use a value without reading it."
version: 1.1.0
---

# keysmith — Agent-safe Secret Handling

## When to use
Any time the agent needs to read, write, list, rotate, or **use** a credential
(API key, token, password, DSN, .env value) — either in this codebase or
in a project where the keysmith server is configured.

## Scope (read this first)
These rules are guidance for a cooperative agent. They are not an access-control
boundary: nothing here stops you from reading a file that was never in the store.
The enforced paths are the store API, the masked views, and `keysmith run`.
Prefer them because they work, not because they are enforced.

## Hard rules (non-negotiable)
1. **NEVER `cat` a `.env` file, `secrets.enc`, or any secret-bearing file.**
   The whole point of this server is that those files must not enter context.
2. **NEVER echo a secret value into a reply, log, commit, or tool result.**
3. Prefer **masked output** (`sk******ij`) for every display. Plaintext is
   only ever acceptable inside the store, decrypted transiently in memory.
4. If you truly must see a plaintext value, treat it as a last resort and
   never repeat it — prefer `rotate` to replace it instead.

## Tool usage (via MCP)
- **`list`** — see all keys with masked values. Use first to orient.
- **`get <key>`** — read one masked value.
- **`put <key> <value_file>`** — store a new value. Write the value to a
  temp file first (`echo -n "$VAL" > /tmp/x`), pass the PATH as `value_file`,
  and the server deletes the file after. Never pass the value as an argument.
- **`rotate <key> [length]`** — generate a new strong random value and store
  it. Returns masked.
- **`delete <key>`** — remove.

## Using a credential without reading it (preferred)
Never ask for plaintext just to make a call. Issue a token and let keysmith
substitute the real value locally, into the child's environment:

```sh
TOKEN=$(keysmith token API_KEY)
keysmith run --env AUTH="Bearer $TOKEN" -- sh -c 'curl -s -H "Authorization: $AUTH" https://api.example.test/me'
```

- A token looks like `[[keysmith:v1:API_KEY:8f3a2b1c]]`. It is a reference, not
  a secret, and it only resolves on this machine, in this session.
- A token in the command arguments (`argv`) is refused on purpose: `argv` is
  readable by every user through `ps`. Put it in `--env` and let the child's
  shell expand `$AUTH` inside the child.
- Redemption fails closed. If it refuses, do **not** retry with `--unsafe` —
  fix the cause: issue a fresh token (`keysmith token NAME`), check the name is
  in the session, or check the session has not expired (default TTL 1h).
- The command's exit code is propagated, so `run` is script-safe.

## Pitfalls
- Passing the plaintext value as the `put` argument defeats the design —
  it lands in the transcript. Always use `value_file`.
- The store dir (`~/.keysmith` by default) contains `key.txt` (the age
  private key). Never read, copy, or commit it.
- `secrets.enc` is an armored age blob — it is SAFE to read into context
  (ciphertext), but don't, because it bloats context for no value.
- Rotated values are returned masked; if you need the new plaintext (e.g. to
  update an external service), use `get` with an explicit `--unsafe`-style
  intent and handle it as a secret immediately — never log it.

## Verification
- After any secret operation, confirm the output shows `******` (masked)
  and no plaintext appears in your own reasoning or reply.
