# AGENTS.md — Rules for AI agents working in this repo

This repository builds a security tool. The same discipline applies to
agents that develop it.

## Secret handling (hard rules)
- **Never read `key.txt` or `secrets.enc` directly** (test fixtures excepted,
  and even then only via the store package API).
- **Never print, log, or commit a secret value** — including in test output.
- When debugging the store, use the store's own `List()` (masked) or assert
  on masked forms, not raw `Get()`.
- `e2e_test.py` intentionally asserts plaintext does NOT appear in MCP
  output. Keep it that way.
- If you must inspect an on-disk blob, read it as bytes and check only for
  the armor markers / absence of plaintext — never dump the decrypted data.

## Security invariants (do not regress)
1. `secrets.enc` must never contain plaintext key material (age-encrypted).
2. `key.txt` must be `0600`, store dir `0700`.
3. Every MCP tool result and resource must be masked — no plaintext in
   tool results, ever.
4. `put` must accept a `value_file` path, read it, and delete it after.
5. Masking rules live in `internal/mask` — keep the entropy/prefix/URL
   segmentation tests green.

## Workflow
- Run `go test ./...` before committing — all packages must pass.
- Run `go vet ./...` — no warnings.
- Run `python3 e2e_test.py` after any change to `internal/mcp` or
  `internal/store` — the protocol round-trip must stay green.
- Keep the Go SDK (github.com/modelcontextprotocol/go-sdk) on a version
  with no open OSV advisories; bump deliberately.
