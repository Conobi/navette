#!/usr/bin/env bash
# scripts/test_h2_reverse_proxy.sh — End-to-end H2 reverse proxy smoke test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

PROXY_PORT=8444
BACKEND_PORT=9444
CERT_DIR="examples/reverse_proxy/certs"
BOUCLE_DIR="${BOUCLE_DIR:-$HOME/Projets/perso/boucle}"

# Ensure certs exist
if [ ! -f "$CERT_DIR/proxy_cert.pem" ] || [ ! -f "$CERT_DIR/backend_cert.pem" ]; then
    echo "Generating test certificates..."
    bash scripts/gen_test_certs.sh
fi

BACKEND_LOG="$(mktemp -t mojo-h2-proxy-backend.XXXXXX.log)"
PROXY_LOG="$(mktemp -t mojo-h2-proxy-proxy.XXXXXX.log)"
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

# 1. Start Python H2 HTTPS backend
echo "Starting H2 backend on port $BACKEND_PORT..."
uv run python3 scripts/test_h2_backend.py >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
sleep 1

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "FAIL: H2 backend failed to start"
    exit 1
fi

# 2. Build and start the H2 reverse proxy
echo "Building H2 reverse proxy..."
rm -f ./*.mojopkg 2>/dev/null || true
LD_LIBRARY_PATH=lib uv run mojo build \
    -I . -I "$BOUCLE_DIR" -I conformance \
    examples/h2_reverse_proxy/main.mojo -o /tmp/mojo_h2_reverse_proxy \
    >"$PROXY_LOG" 2>&1

echo "Starting H2 reverse proxy on port $PROXY_PORT..."
LD_LIBRARY_PATH=lib /tmp/mojo_h2_reverse_proxy >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: H2 proxy failed to start"
    exit 1
fi

# 3. Send GET and POST requests through the proxy
#    The proxy is single-threaded, so we multiplex both requests on
#    a single H2 connection using curl --next to reuse the connection.
GET_RESP_FILE="$(mktemp -t mojo-h2-get.XXXXXX.json)"
POST_RESP_FILE="$(mktemp -t mojo-h2-post.XXXXXX.json)"

echo "Sending H2 GET + POST requests..."
set +e
curl --http2 -sk --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/test-path" \
    -H "X-Test-Header: hello" \
    -o "$GET_RESP_FILE" \
    --next \
    --http2 -sk --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/post-test" \
    -X POST -d "hello=world" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -o "$POST_RESP_FILE" 2>&1
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: curl request failed (rc=$CURL_RC)"
    cat "$GET_RESP_FILE" 2>/dev/null || true
    cat "$POST_RESP_FILE" 2>/dev/null || true
    exit 1
fi

# 4. Validate GET response
RESPONSE=$(cat "$GET_RESP_FILE")
echo "GET Response: $RESPONSE"

if echo "$RESPONSE" | python3 -c "
import json, sys
data = json.load(sys.stdin)
headers = data.get('headers', {})
via = headers.get('via', headers.get('Via', ''))
xff = headers.get('x-forwarded-for', headers.get('X-Forwarded-For', ''))
assert 'mojo-proxy' in via, f'Missing Via header, got: {via}'
assert xff, f'Missing X-Forwarded-For header'
assert data['path'] == '/test-path', f'Wrong path: {data[\"path\"]}'
print('All assertions passed')
"; then
    echo ""
    echo "=== PASS: H2 reverse proxy GET smoke test ==="
else
    echo ""
    echo "=== FAIL: GET response validation failed ==="
    exit 1
fi

# 5. Validate POST response
echo ""
POST_RESPONSE=$(cat "$POST_RESP_FILE")
echo "POST Response: $POST_RESPONSE"

if echo "$POST_RESPONSE" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert data['method'] == 'POST', f'Wrong method: {data[\"method\"]}'
assert data['body'] == 'hello=world', f'Wrong body: {data[\"body\"]}'
headers = data['headers']
via = headers.get('via', headers.get('Via', ''))
assert 'mojo-proxy' in via, 'Missing Via header'
print('POST assertions passed')
"; then
    echo "=== PASS: H2 POST test ==="
else
    echo "=== FAIL: POST validation failed ==="
    exit 1
fi

rm -f "$GET_RESP_FILE" "$POST_RESP_FILE"

echo ""
echo "=== ALL H2 E2E TESTS PASSED ==="
