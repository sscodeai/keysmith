# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (unreleased)

### Added
- Redemption target binding: a token can be restricted to specific hosts, path
  prefixes and headers at issue time, and `keysmith run --target` refuses a
  redemption aimed anywhere else (default: deny when a token is bound).

### Changed
- `LICENSE` now carries the full Apache-2.0 text; the copyright statement moved
  to `NOTICE`. GitHub previously reported `NOASSERTION` for this repository.
- The MCP server reports the real build version in `serverInfo.version`
  (it advertised a hardcoded `0.1.0` regardless of the binary).
- `keysmith run` no longer leaves a duplicate entry behind when a redeemed
  variable name is already present in the environment.
- Test coverage: `cmd/keysmith` argument parsing, validation and environment
  merging now have unit tests; CI runs `gofmt`, `go vet`, `go test`,
  `e2e_test.py`, `verify_redeem.py` and the doc-parity check on every push.

### Fixed
- Masking now uses the key name: `DB_PASSWORD=correcthorsebatterystaple` is
  masked by `get`, `list`, the MCP `get` tool and the MCP resource, instead of
  being returned verbatim. `KeyNameIsSensitive` had no callers before.
- `put` only accepts a `value_file` inside `<store>/inbox`; an agent-supplied
  path outside it was an arbitrary-file read and unlink. `keysmith inbox`
  prints the directory, and symlink escapes are refused.
- Store writes take an exclusive lock (`<store>/store.lock`), so the MCP server
  and the CLI can no longer lose each other's updates (20 concurrent `set`
  calls used to store 12 keys).
- `--target` paths containing `.`/`..` segments, encoded slashes or
  backslashes are refused, closing a `--allow-path` prefix escape such as
  `/services/../../admin`.
- An HTTP listener on a non-loopback address requires `-http-token`; requests
  without a matching `Authorization: Bearer` get 401.
- `keysmith scan` no longer prints the leaked value itself in its report.
- `randomSecret` uses rejection sampling instead of a biased modulo.

## 0.4.0 — 2026-09-14

### Added
- Redemption layer (`internal/redeem`): session-bound placeholder tokens
  (`[[keysmith:v1:NAME:sid8]]`) resolved locally, plus the `keysmith token` and
  `keysmith run` commands. Values reach a child process environment without
  entering a model request, a transcript or an argument list. Every failure mode
  is fail-closed, and `<store>/audit.log` records key names only.
- `docs/THREAT-MODEL.md` (adversaries in scope, and explicitly out of scope),
  `docs/REDEEM.md`, and `docs/audit-2026-09-14.md` with captured evidence.
- `verify_redeem.py`: end-to-end checks that read a live child's `/proc` entries.
- Japanese mirrors for the new material in `README.ja.md`, `AGENTS.ja.md`,
  `docs/architecture.ja.md` and `skill/SKILL.ja.md`.

### Fixed
- The `get` and `rotate` MCP tool descriptions told agents to use `--unsafe`,
  a flag that does not exist on the MCP transport; following that advice
  produced a protocol validation error. They now describe the real behaviour and
  point at the redemption layer.

## 0.3.0 and earlier — 2026-08-31

Store (age-encrypted residency), masked views, handle passing, leak-scan with
self-healing rotation, the Vault backend with dynamic short-TTL credentials, the
three MCP transports (stdio, HTTP/SSE, Streamable HTTP), the CLI subcommands,
the bundled agent skill, and the Japanese translations. See the git history for
the individual changes.
