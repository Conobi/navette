#!/usr/bin/env bash
set -euo pipefail

echo "=== Docker Interop E2E Test ==="

TEST_DIR="/tmp/interop_docker_test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"/{www,downloads,certs}

# Generate CA + leaf cert chain
echo "[setup] Generating certificates..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TEST_DIR/certs/ca.key" \
    -out "$TEST_DIR/certs/ca.pem" \
    -days 1 -nodes -subj "/CN=Test CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TEST_DIR/certs/priv.key" \
    -out "$TEST_DIR/certs/leaf.csr" \
    -nodes -subj "/CN=server" 2>/dev/null
openssl x509 -req -in "$TEST_DIR/certs/leaf.csr" \
    -CA "$TEST_DIR/certs/ca.pem" -CAkey "$TEST_DIR/certs/ca.key" -CAcreateserial \
    -out "$TEST_DIR/certs/cert.pem" -days 1 \
    -extfile <(echo "subjectAltName=DNS:server,DNS:localhost,DNS:interop-server,IP:127.0.0.1") 2>/dev/null

# Create test files
echo "[setup] Creating test files..."
dd if=/dev/urandom of="$TEST_DIR/www/small.bin" bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of="$TEST_DIR/www/medium.bin" bs=1024 count=100 2>/dev/null

# --- Test 1: unsupported testcase exits 127 ---
echo ""
echo "[test] TESTCASE=zerortt (unsupported) should exit 127..."
EXIT=0
docker run --rm -e TESTCASE=zerortt -e ROLE=server mojo-net-interop:latest || EXIT=$?
if [ "$EXIT" = "127" ]; then
    echo "[test] PASS: unsupported testcase exited 127"
else
    echo "[test] FAIL: expected exit 127, got $EXIT"
fi

# --- Test 2: handshake via Docker network ---
echo ""
echo "[test] TESTCASE=handshake: Docker server + client..."

docker network create interop-test 2>/dev/null || true

docker run --rm -d --name interop-server \
    --network interop-test \
    -e TESTCASE=handshake \
    -e ROLE=server \
    -v "$TEST_DIR/www:/www:ro" \
    -v "$TEST_DIR/certs:/certs:ro" \
    mojo-net-interop:latest
sleep 2

docker run --rm --name interop-client \
    --network interop-test \
    -e TESTCASE=handshake \
    -e ROLE=client \
    -e "REQUESTS=https://interop-server:443/small.bin" \
    -v "$TEST_DIR/certs:/certs:ro" \
    -v "$TEST_DIR/downloads:/downloads" \
    mojo-net-interop:latest || true

docker stop interop-server 2>/dev/null || true

if cmp -s "$TEST_DIR/www/small.bin" "$TEST_DIR/downloads/small.bin"; then
    echo "[test] PASS: downloaded file matches original"
else
    echo "[test] FAIL: file mismatch or download missing"
    ls -la "$TEST_DIR/downloads/" 2>/dev/null || echo "  (downloads dir empty)"
fi

# --- Test 3: transfer (multiple files) ---
echo ""
echo "[test] TESTCASE=transfer: multiple file download..."
rm -f "$TEST_DIR/downloads/small.bin" "$TEST_DIR/downloads/medium.bin"

docker run --rm -d --name interop-server \
    --network interop-test \
    -e TESTCASE=transfer \
    -e ROLE=server \
    -v "$TEST_DIR/www:/www:ro" \
    -v "$TEST_DIR/certs:/certs:ro" \
    mojo-net-interop:latest
sleep 2

docker run --rm --name interop-client \
    --network interop-test \
    -e TESTCASE=transfer \
    -e ROLE=client \
    -e "REQUESTS=https://interop-server:443/small.bin https://interop-server:443/medium.bin" \
    -v "$TEST_DIR/certs:/certs:ro" \
    -v "$TEST_DIR/downloads:/downloads" \
    mojo-net-interop:latest || true

docker stop interop-server 2>/dev/null || true

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
    ls -la "$TEST_DIR/downloads/" 2>/dev/null
fi

# Cleanup
docker network rm interop-test 2>/dev/null || true
rm -rf "$TEST_DIR"

echo ""
echo "=== Done ==="
