---
name: keysmith
description: "Route ALL secret operations through the keysmith MCP server — never read .env/secret files directly. Values stay masked; plaintext never enters context."
version: 1.0.0
---

# keysmith — Agent-safe Secret Handling

## When to use
Any time the agent needs to read, write, list, or rotate a credential
(API key, token, password, DSN, .env value) — either in this codebase or
in a project where the keysmith server is configured.

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
