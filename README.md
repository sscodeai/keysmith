# keysmith 🔑

[日本語](README.ja.md)

**The key-smith for AI agents** — forge, guard, and rotate secrets so plaintext
never enters the agent's context.

Keysmith is an MCP server + CLI for AI-agent-safe secret management. It treats
masking as the last line of defense and works structurally to keep secrets
from leaking: encrypted residency, masked views, handle-passing, self-healing
rotation, and short-TTL dynamic credentials.

Built with Go. Single static binary, zero runtime dependencies.

## Why

AI agents increasingly need credentials (API keys, tokens, DB URLs) to do
their work. But every time an agent reads a `.env` file, the plaintext leaks
into its context, logs, and session history — permanently.

Keysmith fixes this with a **layered security model**:

| Layer | Mechanism | What it prevents |
|---|---|---|
| Encrypted residency | age (X25519) encrypted store at rest | Plaintext on disk; even a leaked context is harmless (blobs are ciphertext) |
| Masked views | resources/tools return `sk******ij` form | Credentials entering agent context |
| Handle-passing | `put` reads value from a temp file arg, not the transcript | Plaintext in tool-call transcripts |
| Self-healing rotation | `scan --rotate` detects leaks, kills the leaked value | Stale leaked credentials keep working |
| Short-TTL (Vault) | dynamic DB creds expire in 1h | Leaked credentials become worthless |

## Install

```sh
go install github.com/sscodeai/keysmith/cmd/keysmith@latest
# or build from source
go build -o bin/keysmith ./cmd/keysmith
```

## Usage

Run the server on stdio transport (the standard MCP server mode):

```sh
keysmith -store ~/.keysmith
# or via env:
KEYSMITH_STORE=/path/to/store keysmith
```

Serve over HTTP/SSE for remote agents:

```sh
keysmith -store ~/.keysmith -http :8080
# endpoint: http://localhost:8080/sse
```

Serve MCP 2025 Streamable HTTP (single POST endpoint, stateless):

```sh
keysmith -store ~/.keysmith -http :8080 -streamable
# endpoint: http://localhost:8080/mcp
```

Use HashiCorp Vault as the backend (dynamic short-TTL secrets):

```sh
export VAULT_TOKEN=<token>
keysmith -store ~/.keysmith -vault http://127.0.0.1:8200
```

Configure it in your MCP client (Claude Code, Cursor, etc.):

```json
{
  "mcpServers": {
    "keysmith": {
      "command": "keysmith",
      "args": ["-store", "~/.keysmith"]
    }
  }
}
```

The store directory is created on first run with `0600` permissions, holding:

- `key.txt` — your age private key (NEVER share; keep `0600`)
- `secrets.enc` — armored age-encrypted secrets blob

## CLI

In addition to the MCP server, `keysmith` works as a standalone CLI sharing the same store:

```sh
keysmith list                        # all keys, masked values
keysmith get API_KEY                 # masked value
keysmith get API_KEY --unsafe        # plaintext (last resort)
keysmith set API_KEY < value.txt     # value from stdin, no shell-history leak
keysmith rotate API_KEY 32           # generate + store new strong secret
keysmith delete API_KEY              # remove a key
keysmith scan [--rotate] [repo-dir]  # scan git history for leaked secrets
```

Vault-backed commands (with `-vault`):

```sh
keysmith -vault http://127.0.0.1:8200 vault-kv-set API_KEY < value.txt
keysmith -vault http://127.0.0.1:8200 vault-kv-get API_KEY          # masked
keysmith -vault http://127.0.0.1:8200 vault-kv-list
keysmith -vault http://127.0.0.1:8200 vault-db-creds app-role       # dynamic short-TTL DB creds
```

## Tools

| Tool | Description | Security property |
|---|---|---|
| `list` | All keys with masked values | Values never plaintext |
| `get` | Single key, masked value | Values never plaintext |
| `put` | Store a secret | Value read from `value_file` arg, temp file auto-removed |
| `rotate` | Generate + store a new strong random secret | Returns masked value only |
| `delete` | Remove a key | — |

## Resources

| URI | Description |
|---|---|
| `secret://secrets` | Masked view of all secrets (safe to read into context) |

## Agent skills

The bundled `SKILL.md` (in `skill/`) teaches agents to route ALL secret
operations through this server — never `cat` a `.env`, never echo a token.
The `AGENTS.md` at the repo root encodes the same rules for agents working
on this codebase itself.

## Capability map

How the pieces relate — core primitives vs the automation/transport layers
built on top of them:

```mermaid
flowchart TB
    subgraph Core["Core primitives"]
        STORE[age encrypted store<br/>internal/store]
        MASK[masking rules<br/>internal/mask]
        SCAN[leak-scan + self-healing<br/>keysmith scan --rotate]
        VAULT[Vault short-TTL creds<br/>internal/vault]
    end

    subgraph Auto["Automation"]
        CRON[scheduled leak-scan<br/>scripts/scan-cron.sh]
    end

    subgraph Access["Access"]
        STDIO[stdio]
        SSE[SSE -http]
        STREAM[Streamable -streamable]
    end

    SCAN -->|scheduled| CRON
    STORE --> SCAN
    MASK --> STORE
    VAULT -.->|optional backend| STORE
    STDIO -.-> SSE
    SSE -.-> STREAM
```

| Layer | Capability | Relationship |
|---|---|---|
| Core | age store + mask + rotate + scan | foundational primitives |
| Automation | `scripts/scan-cron.sh` | schedules `scan --rotate` |
| Access | stdio / SSE / Streamable | three transports, one server |

**One line**: core primitives provide the power, automation makes it run by
itself, transports decide how agents connect.

## Security model

- **At rest**: always age-encrypted (X25519), armor format. A plaintext file
  never exists on disk. Atomic writes (temp + rename), `0600` perms.
- **In context**: masked values only. Masking keeps first/last 2 chars
  (`sk******ij`) so credentials are distinguishable without being revealed.
- **In transcripts**: `put` never takes the plaintext as an argument — it
  reads a temp file path and deletes the file after.
- **Masking rules**: key-name markers (SECRET/TOKEN/PASSWORD/API_KEY/DSN...),
  known value prefixes (sk-, ghp_, glpat-, xoxb-, JWT...), and high-entropy
  alphanumeric runs (≥20 chars mixing letters+digits, Shannon entropy ≥3.5).
  URL-shaped values are masked per-segment: userinfo password always masked,
  high-entropy path/query runs masked, host/port stay clear. Pure-numeric
  values (timeouts, retries) are never masked.

## Development

```sh
go test ./...        # unit tests (mask + store + vault + leakscan)
go vet ./...         # static checks
python3 e2e_test.py  # full MCP protocol round-trip
```

## Scheduled leak-scan (cron self-healing)

The bundled `scripts/scan-cron.sh` runs `keysmith scan --rotate` on one or
more repos, printing one line only when leaks are found (and rotated) —
silent when clean. Wire it into any cron:

```sh
# every 6 hours, scan two repos; only alerts when leaks found+rotated
0 */6 * * * /path/to/keysmith/scripts/scan-cron.sh ~/.keysmith /repo1 /repo2
```

## Roadmap

- [x] Vault backend (dynamic short-TTL secrets — leaked credentials expire)
- [x] HTTP/SSE transport (for remote agent scenarios)
- [x] CLI subcommands (add/get/rotate/scan without MCP)
- [x] Streamable HTTP transport (MCP 2025 standard, single POST endpoint)
- [x] Scheduled leak-scan watchdog script (cron-driven self-healing)
- [ ] Multi-tenant / team mode (share store across agents with audit log)
- [ ] Cloud credentials (AWS STS / GCP short-lived)

## License

Apache-2.0
