#!/bin/bash
# fix-chrome-libs.sh — install Chrome's missing shared libs without root.
# Downloads .deb packages, extracts .so files to ~/.local/lib/chrome-deps,
# prints the LD_LIBRARY_PATH to export.
set -e

DEPS_DIR="$HOME/.local/lib/chrome-deps"
WORKDIR="/tmp/chrome-libs-work"
mkdir -p "$DEPS_DIR" "$WORKDIR"
cd "$WORKDIR"

# Debian bookworm packages for Chrome's missing libs (no t64 suffix in bookworm)
PACKAGES="libnspr4 libnss3 libnssutil3 libsmime3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxcomposite1 libxdamage1 libatspi2.0-0"

echo "=== Downloading packages ==="
for pkg in $PACKAGES; do
  apt-get download "$pkg" 2>&1 | grep -E "Get:|Err" | tail -1
done

echo "=== Extracting .so ==="
for deb in *.deb; do
  dpkg-deb -x "$deb" "$WORKDIR/extract" 2>/dev/null || true
done

echo "=== Collecting .so into $DEPS_DIR ==="
find "$WORKDIR/extract" -name "*.so*" -type f -o -name "*.so" 2>/dev/null | while read f; do
  cp -n "$f" "$DEPS_DIR/" 2>/dev/null || true
done

# Also grab symlinks (libnss3.so -> libnss3.so.3)
find "$WORKDIR/extract" -name "*.so*" -type l 2>/dev/null | while read l; do
  base=$(basename "$l")
  target=$(readlink "$l")
  # recreate relative symlink in deps dir
  if [ ! -e "$DEPS_DIR/$base" ]; then
    ln -sf "$target" "$DEPS_DIR/$base" 2>/dev/null || true
  fi
done

echo "=== Result ==="
ls -la "$DEPS_DIR" | head -20
echo "=== Verifying missing libs ==="
# Auto-detect a chrome binary (env override, playwright cache, or PATH)
CHROME="${CHROME_BIN:-}"
if [ -z "$CHROME" ]; then
  CHROME=$(find "$HOME/.cache/ms-playwright" -name chrome -type f 2>/dev/null | head -1)
fi
if [ -z "$CHROME" ]; then
  CHROME=$(command -v google-chrome || command -v chromium || echo "")
fi
if [ -n "$CHROME" ]; then
  LD_LIBRARY_PATH="$DEPS_DIR" ldd "$CHROME" 2>/dev/null | grep "not found" | head -10
  echo "(empty above = all resolved)"
else
  echo "No chrome binary found; set CHROME_BIN to verify."
fi
echo
echo "=== Usage ==="
echo "export LD_LIBRARY_PATH=$DEPS_DIR"
