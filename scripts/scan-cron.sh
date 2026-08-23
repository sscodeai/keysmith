#!/bin/bash
# scan-cron.sh — scheduled leak-scan watchdog for keysmith.
#
# Runs `keysmith scan --rotate` on the given repo(s). Prints ONE line per
# repo ONLY when leaks were found (and rotated); stays silent when clean,
# so it can be used as a Hermes cron watchdog (no_agent=true, empty stdout =
# silent tick).
#
# Usage:
#   scan-cron.sh <store-dir> <repo-dir> [more-repos...]
#
# Env:
#   KEYSMITH_BIN   path to keysmith binary (default: ./bin/keysmith)
set -u

STORE="${1:-}"
if [ -z "$STORE" ]; then
  echo "scan-cron: usage: scan-cron.sh <store-dir> <repo-dir> [...]" >&2
  exit 2
fi
shift

# Resolve repo root from this script's location (portable)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BIN="${KEYSMITH_BIN:-$REPO_ROOT/bin/keysmith}"
if [ ! -x "$BIN" ]; then
  echo "scan-cron: binary not found: $BIN" >&2
  exit 2
fi

found_any=0
for repo in "$@"; do
  [ -d "$repo/.git" ] || continue
  out=$(KEYSMITH_STORE="$STORE" "$BIN" scan --rotate "$repo" 2>&1)
  if echo "$out" | grep -q "potential leak"; then
    echo "🔓 $repo: $(echo "$out" | head -1) — auto-rotated"
    found_any=1
  fi
done

exit 0
