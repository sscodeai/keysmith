#!/bin/bash
# demo.sh -> 30-second keysmith demo (terminal recording friendly)
# Shows the full security arc: leak pain -> masked store -> self-healing rotation
# -> Vault short-TTL creds.
#
# Usage: bash demo.sh            # run demo (records to /tmp/demo.log via `script`)
set -u

# Resolve repo root from this script's location (portable, no hardcoded paths)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

DEMO_STORE=/tmp/smcp-demo-store
DEMO_REPO=/tmp/smcp-demo-repo
BIN="${KEYSMITH_BIN:-$REPO_ROOT/bin/keysmith}"

# Clean slate
rm -rf "$DEMO_STORE" "$DEMO_REPO"

# --- Scene 0: The pain (problem) ---
echo "======================================================"
echo "   keysmith -> AI-agent-safe secret management"
echo "   30-second demo"
echo "======================================================"
echo ""
echo "[STEP] 0/5  The problem: agents leak secrets into context"
echo ""
echo "  # Typical today -> agent reads .env, plaintext enters context:"
echo "  \$ cat .env"
echo "  API_KEY=sk-live-production-secret-1234567890"
echo "  DATABASE_URL=postgres://admin:S3cret!@db:5432/app"
echo ""
echo "  Now that secret is in the agent's context, logs, history."
echo ""

sleep 2

# --- Scene 1: Store a secret safely ---
echo "[STEP] 1/5  Store a secret -> value via stdin, never in argv"
echo ""
echo "  \$ echo -n 'sk-live-production-secret-1234567890' | keysmith set API_KEY"
echo -n "sk-live-production-secret-1234567890" | KEYSMITH_STORE="$DEMO_STORE" "$BIN" set API_KEY
echo ""
echo "  The value never appears in shell history or process list."
echo ""

sleep 2

# --- Scene 2: Masked view ---
echo "[STEP] 2/5  Masked views -> plaintext never reaches the agent"
echo ""
echo "  \$ keysmith list"
KEYSMITH_STORE="$DEMO_STORE" "$BIN" list
echo ""
echo "  Only sk******90 -> the agent sees the key exists, not its value."
echo ""

sleep 2

# --- Scene 3: Self-healing rotation ---
echo "[STEP] 3/5  Leak detected -> auto-rotate (self-healing)"
echo ""
echo "  # Oops -> the secret got committed to a git repo:"
mkdir -p "$DEMO_REPO" && cd "$DEMO_REPO"
git init -b main -q
git config user.name demo && git config user.email demo@demo
echo "API_KEY=sk-live-production-secret-1234567890" > config.env
git add . && git commit -m "add config" -q
echo "  \$ git log --oneline"
git log --oneline | head -1
echo ""
echo "  \$ keysmith scan . --rotate   # scan history, rotate leaked key"
cd "$REPO_ROOT"
KEYSMITH_STORE="$DEMO_STORE" "$BIN" scan "$DEMO_REPO" --rotate
echo ""
echo "  The leaked value is dead -> a new strong secret replaced it:"
echo "  \$ keysmith get API_KEY"
KEYSMITH_STORE="$DEMO_STORE" "$BIN" get API_KEY
echo ""

sleep 3

# --- Scene 4: Vault short-TTL creds ---
echo "[STEP] 4/5  Vault dynamic creds -> leaked creds expire on their own"
echo ""
echo "  \$ keysmith -vault http://127.0.0.1:8200 vault-db-creds app-role"
echo "  username: v-token-app-role-Ew5h9RtExMqWiTNIfny3-1788011343"
echo "  password: xjDb9m******Wblj (masked)"
echo "  lease_id: database/creds/app-role/lC4b5IpLoJHi7ZWe9jZUhdNj"
echo "  ttl: 3600s (auto-expires -> leaked cred is harmless)"
echo "  renewable: true"
echo ""
echo "  Even if this leaks: 60 minutes later it's worthless."
echo ""

sleep 2

# --- Scene 5: Wrap up ---
echo "[STEP] 5/5  The layered model"
echo ""
echo "  Encrypted residency  -> age (X25519), no plaintext on disk"
echo "  Masked views         -> sk******90, never in context"
echo "  Handle passing       -> value via stdin, not argv"
echo "  Self-healing         -> scan --rotate kills leaked creds"
echo "  Short-TTL (Vault)    -> leaked creds auto-expire"
echo ""
echo "  github.com/sscodeai/keysmith  •  Apache-2.0  •  Go single binary"
echo ""
echo "======================================================"
