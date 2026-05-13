#!/usr/bin/env bash
# scripts/test_reverse_proxy.sh — End-to-end reverse proxy smoke test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

PROXY_PORT=8443
BACKEND_PORT=9443
CERT_DIR="examples/reverse_proxy/certs"
BOUCLE_DIR="${BOUCLE_DIR:-$HOME/Projets/perso/boucle}"

# Ensure certs exist
if [ ! -f "$CERT_DIR/proxy_cert.pem" ] || [ ! -f "$CERT_DIR/backend_cert.pem" ]; then
    echo "Generating test certificates..."
    bash scripts/gen_test_certs.sh
fi

BACKEND_LOG="$(mktemp -t mojo-proxy-backend.XXXXXX.log)"
PROXY_LOG="$(mktemp -t mojo-proxy-proxy.XXXXXX.log)"
BACKEND_PID=""
PROXY_PID=""

cleanup() {
    local rc=$?
    echo "Cleaning up..."
    [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
        echo ""
        echo "=== Backend log ($BACKEND_LOG) ==="
        cat "$BACKEND_LOG" 2>/dev/null || true
        echo ""
        echo "=== Proxy log ($PROXY_LOG) ==="
        cat "$PROXY_LOG" 2>/dev/null || true
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

# 1. Start Python HTTPS backend
echo "Starting backend on port $BACKEND_PORT..."
python3 scripts/test_backend.py >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
sleep 1

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "FAIL: Backend failed to start"
    exit 1
fi

# 2. Build and start the reverse proxy
echo "Building reverse proxy..."
rm -f ./*.mojopkg 2>/dev/null || true
LD_LIBRARY_PATH=lib uv run --project examples/reverse_proxy mojox build \
    examples/reverse_proxy/main.mojo -o /tmp/mojo_reverse_proxy \
    >"$PROXY_LOG" 2>&1

echo "Starting reverse proxy on port $PROXY_PORT..."
LD_LIBRARY_PATH=lib /tmp/mojo_reverse_proxy >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: Proxy failed to start"
    exit 1
fi

# 3. Send a GET request through the proxy
echo "Sending GET request..."
set +e
RESPONSE=$(curl -sk --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/test-path" \
    -H "X-Test-Header: hello" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: curl request failed (rc=$CURL_RC)"
    echo "$RESPONSE"
    exit 1
fi

echo "Response: $RESPONSE"

if echo "$RESPONSE" | python3 -c "
import json, sys
data = json.load(sys.stdin)
headers = data.get('headers', {})
via = headers.get('via', headers.get('Via', ''))
xff = headers.get('x-forwarded-for', headers.get('X-Forwarded-For', ''))
assert '1.1 mojo-proxy' in via, f'Missing Via header, got: {via}'
assert xff, f'Missing X-Forwarded-For header'
assert data['path'] == '/test-path', f'Wrong path: {data[\"path\"]}'
print('All assertions passed')
"; then
    echo ""
    echo "=== PASS: Reverse proxy GET smoke test ==="
else
    echo ""
    echo "=== FAIL: GET response validation failed ==="
    exit 1
fi

# 4. Test POST with body
echo ""
echo "Sending POST request..."
set +e
POST_RESPONSE=$(curl -sk --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/post-test" \
    -X POST -d "hello=world" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: POST curl request failed (rc=$CURL_RC)"
    echo "$POST_RESPONSE"
    exit 1
fi

echo "POST Response: $POST_RESPONSE"

if echo "$POST_RESPONSE" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert data['method'] == 'POST', f'Wrong method: {data[\"method\"]}'
assert data['body'] == 'hello=world', f'Wrong body: {data[\"body\"]}'
headers = data['headers']
via = headers.get('via', headers.get('Via', ''))
assert '1.1 mojo-proxy' in via, 'Missing Via header'
print('POST assertions passed')
"; then
    echo "=== PASS: POST test ==="
else
    echo "=== FAIL: POST validation failed ==="
    exit 1
fi

echo ""
echo "=== ALL E2E TESTS PASSED ==="
