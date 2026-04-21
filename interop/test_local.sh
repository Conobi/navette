#!/usr/bin/env bash
set -euo pipefail

echo "=== QUIC Interop Runner Local Test ==="
echo ""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="/tmp/interop_local"
PORT=4433

# --- Setup temp directories ---
mkdir -p "$TEST_DIR"/{www,downloads,certs}

# --- Generate self-signed EC cert ---
echo "[setup] Generating self-signed EC certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TEST_DIR/certs/priv.key" \
    -out "$TEST_DIR/certs/cert.pem" \
    -days 1 -nodes -subj "/CN=server" 2>/dev/null
cp "$TEST_DIR/certs/cert.pem" "$TEST_DIR/certs/ca.pem"

# --- Create test files ---
echo "[setup] Creating test files..."
dd if=/dev/urandom of="$TEST_DIR/www/small.bin" bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of="$TEST_DIR/www/medium.bin" bs=1024 count=100 2>/dev/null

# --- Build binaries ---
echo "[build] Building interop server..."
cd "$REPO_ROOT"
LD_LIBRARY_PATH=lib uv run mojo build -I . interop/server.mojo -o /tmp/interop-server

echo "[build] Building interop client..."
LD_LIBRARY_PATH=lib uv run mojo build -I . interop/client.mojo -o /tmp/interop-client

# --- Test 1: Unsupported TESTCASE exits 127 ---
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
rm -f "$TEST_DIR/downloads/small.bin"

TESTCASE=handshake \
    WWW_DIR="$TEST_DIR/www" \
    CERTS_DIR="$TEST_DIR/certs" \
    PORT=$PORT \
    LD_LIBRARY_PATH="$REPO_ROOT/lib" \
    /tmp/interop-server &
SERVER_PID=$!
sleep 1

TESTCASE=handshake \
    REQUESTS="https://127.0.0.1:$PORT/small.bin" \
    CERTS_DIR="$TEST_DIR/certs" \
    DOWNLOADS_DIR="$TEST_DIR/downloads" \
    LD_LIBRARY_PATH="$REPO_ROOT/lib" \
    /tmp/interop-client || true

kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true

if cmp -s "$TEST_DIR/www/small.bin" "$TEST_DIR/downloads/small.bin"; then
    echo "[test] PASS: downloaded file matches original"
else
    echo "[test] FAIL: file mismatch or download missing"
fi

# --- Test 3: transfer (multiple files) ---
echo ""
echo "[test] TESTCASE=transfer: multiple file download..."
rm -f "$TEST_DIR/downloads/small.bin" "$TEST_DIR/downloads/medium.bin"

TESTCASE=transfer \
    WWW_DIR="$TEST_DIR/www" \
    CERTS_DIR="$TEST_DIR/certs" \
    PORT=$PORT \
    LD_LIBRARY_PATH="$REPO_ROOT/lib" \
    /tmp/interop-server &
SERVER_PID=$!
sleep 1

TESTCASE=transfer \
    REQUESTS="https://127.0.0.1:$PORT/small.bin https://127.0.0.1:$PORT/medium.bin" \
    CERTS_DIR="$TEST_DIR/certs" \
    DOWNLOADS_DIR="$TEST_DIR/downloads" \
    LD_LIBRARY_PATH="$REPO_ROOT/lib" \
    /tmp/interop-client || true

kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null || true

TRANSFER_OK=true
if ! cmp -s "$TEST_DIR/www/small.bin" "$TEST_DIR/downloads/small.bin"; then
    TRANSFER_OK=false
fi
if ! cmp -s "$TEST_DIR/www/medium.bin" "$TEST_DIR/downloads/medium.bin"; then
    TRANSFER_OK=false
fi

if [ "$TRANSFER_OK" = true ]; then
    echo "[test] PASS: both files match"
else
    echo "[test] FAIL: file mismatch or download missing"
fi

# --- Cleanup ---
rm -rf "$TEST_DIR"

echo ""
echo "=== Done ==="
