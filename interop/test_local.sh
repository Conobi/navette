#!/usr/bin/env bash
set -euo pipefail

echo "=== QUIC Interop Runner Local Test ==="
echo "NOTE: Requires root (port 443 + /www /certs /downloads paths)"
echo "      Run with: sudo bash interop/test_local.sh"
echo "      Or use Docker for a rootless alternative."
echo ""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Setup temp directories ---
mkdir -p /tmp/interop_local/{www,downloads,certs}

# --- Symlink interop runner paths (requires root) ---
ln -sfn /tmp/interop_local/www /www
ln -sfn /tmp/interop_local/certs /certs
mkdir -p /downloads

# --- Generate self-signed EC cert ---
echo "[setup] Generating self-signed EC certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/interop_local/certs/priv.key \
    -out /tmp/interop_local/certs/cert.pem \
    -days 1 -nodes -subj "/CN=server" 2>/dev/null
cp /tmp/interop_local/certs/cert.pem /tmp/interop_local/certs/ca.pem
echo "[setup] Cert written to /tmp/interop_local/certs/"

# --- Create test files ---
echo "[setup] Creating test files..."
dd if=/dev/urandom of=/tmp/interop_local/www/small.bin bs=1024 count=1 2>/dev/null
echo "[setup] Test files written to /tmp/interop_local/www/"

# --- Build binaries (if not already built) ---
if [ ! -f /tmp/interop-server ]; then
    echo "[build] Building interop server..."
    cd "$REPO_ROOT"
    LD_LIBRARY_PATH=lib uv run mojo build -I . interop/server.mojo -o /tmp/interop-server
else
    echo "[build] Skipping server build (already exists at /tmp/interop-server)"
fi

if [ ! -f /tmp/interop-client ]; then
    echo "[build] Building interop client..."
    cd "$REPO_ROOT"
    LD_LIBRARY_PATH=lib uv run mojo build -I . interop/client.mojo -o /tmp/interop-client
else
    echo "[build] Skipping client build (already exists at /tmp/interop-client)"
fi

# --- Test 1: Unsupported TESTCASE should exit 127 ---
echo ""
echo "[test] TESTCASE=zerortt (unsupported) should exit 127..."
EXIT=0
TESTCASE=zerortt LD_LIBRARY_PATH="$REPO_ROOT/lib" /tmp/interop-server || EXIT=$?
if [ "$EXIT" = "127" ]; then
    echo "[test] PASS: unsupported testcase exited 127"
else
    echo "[test] FAIL: expected exit 127, got $EXIT"
fi

# --- Test 2: handshake ---
echo ""
echo "[test] TESTCASE=handshake: server + client download..."

# Clean previous download result
rm -f /downloads/small.bin /tmp/interop_local/downloads/small.bin

# Start server in background
TESTCASE=handshake LD_LIBRARY_PATH="$REPO_ROOT/lib" /tmp/interop-server &
SERVER_PID=$!

sleep 1

# Run client
TESTCASE=handshake REQUESTS="https://127.0.0.1:443/small.bin" \
    LD_LIBRARY_PATH="$REPO_ROOT/lib" /tmp/interop-client || true

# Stop server
kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true

# The client saves to /downloads; copy result for comparison
if [ -f /downloads/small.bin ]; then
    cp /downloads/small.bin /tmp/interop_local/downloads/small.bin
fi

if cmp -s /tmp/interop_local/www/small.bin /tmp/interop_local/downloads/small.bin; then
    echo "[test] PASS: downloaded file matches original"
else
    echo "[test] FAIL: file mismatch or download missing"
fi

echo ""
echo "=== Done ==="
