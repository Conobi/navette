#!/usr/bin/env bash
# scripts/test_reverse_proxy.sh — Unified ALPN-dispatched reverse proxy smoke
#
# Starts:
#   - Python H1 backend on port 9443
#   - Python H2 backend on port 9444
#   - The unified Mojo reverse proxy on port 8443 with
#         H1_BACKEND_PORT=9443
#         H2_BACKEND_PORT=9444
# Probes both ALPNs via curl and validates Via + body round-tripping.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

PROXY_PORT=8443
H1_BACKEND_PORT=9443
H2_BACKEND_PORT=9444
CERT_DIR="examples/reverse_proxy/certs"

if [ ! -f "$CERT_DIR/proxy_cert.pem" ] || [ ! -f "$CERT_DIR/backend_cert.pem" ]; then
    echo "Generating test certificates..."
    bash scripts/gen_test_certs.sh
fi

H1_BACKEND_LOG="$(mktemp -t mojo-proxy-h1-backend.XXXXXX.log)"
H2_BACKEND_LOG="$(mktemp -t mojo-proxy-h2-backend.XXXXXX.log)"
PROXY_LOG="$(mktemp -t mojo-proxy-proxy.XXXXXX.log)"
H1_BACKEND_PID=""
H2_BACKEND_PID=""
PROXY_PID=""

cleanup() {
    local rc=$?
    echo "Cleaning up..."
    [ -n "${H1_BACKEND_PID:-}" ] && kill "$H1_BACKEND_PID" 2>/dev/null || true
    [ -n "${H2_BACKEND_PID:-}" ] && kill "$H2_BACKEND_PID" 2>/dev/null || true
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
        echo ""
        echo "=== H1 backend log ($H1_BACKEND_LOG) ==="
        cat "$H1_BACKEND_LOG" 2>/dev/null || true
        echo ""
        echo "=== H2 backend log ($H2_BACKEND_LOG) ==="
        cat "$H2_BACKEND_LOG" 2>/dev/null || true
        echo ""
        echo "=== Proxy log ($PROXY_LOG) ==="
        cat "$PROXY_LOG" 2>/dev/null || true
    fi
    exit $rc
}
trap cleanup EXIT INT TERM

# 1. Start both backends. The H2 backend needs the `h2` library (dev group);
#    use `uv run --group dev` so the dev venv is on the import path. The H1
#    backend is stdlib-only but go through uv too for consistency.
echo "Starting H1 backend on port $H1_BACKEND_PORT..."
uv run --group dev python3 scripts/test_backend.py >"$H1_BACKEND_LOG" 2>&1 &
H1_BACKEND_PID=$!

echo "Starting H2 backend on port $H2_BACKEND_PORT..."
uv run --group dev python3 scripts/test_h2_backend.py >"$H2_BACKEND_LOG" 2>&1 &
H2_BACKEND_PID=$!

sleep 1

if ! kill -0 "$H1_BACKEND_PID" 2>/dev/null; then
    echo "FAIL: H1 backend failed to start"
    exit 1
fi
if ! kill -0 "$H2_BACKEND_PID" 2>/dev/null; then
    echo "FAIL: H2 backend failed to start"
    exit 1
fi

# 2. Build and start the unified reverse proxy
echo "Building unified reverse proxy..."
rm -f ./*.mojopkg 2>/dev/null || true
LD_LIBRARY_PATH=lib uv run --project examples/reverse_proxy mojox build \
    examples/reverse_proxy/main.mojo -o /tmp/mojo_reverse_proxy \
    >"$PROXY_LOG" 2>&1

echo "Starting reverse proxy on port $PROXY_PORT (H1→$H1_BACKEND_PORT, H2→$H2_BACKEND_PORT)..."
LISTEN_PORT="$PROXY_PORT" \
H1_BACKEND_PORT="$H1_BACKEND_PORT" \
H2_BACKEND_PORT="$H2_BACKEND_PORT" \
LD_LIBRARY_PATH=lib /tmp/mojo_reverse_proxy >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: Proxy failed to start"
    exit 1
fi

# 3. GET via HTTP/1.1
echo ""
echo "Sending HTTP/1.1 GET..."
set +e
H1_GET=$(curl -sk --http1.1 --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/h1-test" \
    -H "X-Test-Header: hello" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: HTTP/1.1 GET failed (rc=$CURL_RC)"
    echo "$H1_GET"
    exit 1
fi
echo "H1 GET response: $H1_GET"

echo "$H1_GET" | python3 -c "
import json, sys
data = json.load(sys.stdin)
headers = data.get('headers', {})
via = headers.get('via', headers.get('Via', ''))
xff = headers.get('x-forwarded-for', headers.get('X-Forwarded-For', ''))
assert '1.1 mojo-proxy' in via, f'Missing/wrong H1 Via header: {via!r}'
assert xff, 'Missing X-Forwarded-For header'
assert data['path'] == '/h1-test', f'Wrong path: {data[\"path\"]!r}'
print('H1 GET assertions passed')
"
echo "=== PASS: HTTP/1.1 GET ==="

# 4. POST via HTTP/1.1
echo ""
echo "Sending HTTP/1.1 POST..."
set +e
H1_POST=$(curl -sk --http1.1 --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/h1-post" \
    -X POST -d "hello=world" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: HTTP/1.1 POST failed (rc=$CURL_RC)"
    echo "$H1_POST"
    exit 1
fi
echo "H1 POST response: $H1_POST"

echo "$H1_POST" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert data['method'] == 'POST', f'Wrong method: {data[\"method\"]!r}'
assert data['body'] == 'hello=world', f'Wrong body: {data[\"body\"]!r}'
via = data['headers'].get('via', data['headers'].get('Via', ''))
assert '1.1 mojo-proxy' in via, f'Missing/wrong H1 Via header: {via!r}'
print('H1 POST assertions passed')
"
echo "=== PASS: HTTP/1.1 POST ==="

# 5. GET via HTTP/2
echo ""
echo "Sending HTTP/2 GET..."
set +e
H2_GET=$(curl -sk --http2 --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/h2-test" \
    -H "X-Test-Header: hello" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: HTTP/2 GET failed (rc=$CURL_RC)"
    echo "$H2_GET"
    exit 1
fi
echo "H2 GET response: $H2_GET"

echo "$H2_GET" | python3 -c "
import json, sys
data = json.load(sys.stdin)
headers = data.get('headers', {})
via = headers.get('via', headers.get('Via', ''))
assert '2.0 mojo-proxy' in via, f'Missing/wrong H2 Via header: {via!r}'
assert data['path'] == '/h2-test', f'Wrong path: {data[\"path\"]!r}'
print('H2 GET assertions passed')
"
echo "=== PASS: HTTP/2 GET ==="

# 6. POST via HTTP/2
echo ""
echo "Sending HTTP/2 POST..."
set +e
H2_POST=$(curl -sk --http2 --max-time 10 \
    "https://127.0.0.1:$PROXY_PORT/h2-post" \
    -X POST -d "h2=yes" \
    -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
CURL_RC=$?
set -e

if [ $CURL_RC -ne 0 ]; then
    echo "FAIL: HTTP/2 POST failed (rc=$CURL_RC)"
    echo "$H2_POST"
    exit 1
fi
echo "H2 POST response: $H2_POST"

echo "$H2_POST" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert data['method'] == 'POST', f'Wrong method: {data[\"method\"]!r}'
assert data['body'] == 'h2=yes', f'Wrong body: {data[\"body\"]!r}'
via = data['headers'].get('via', data['headers'].get('Via', ''))
assert '2.0 mojo-proxy' in via, f'Missing/wrong H2 Via header: {via!r}'
print('H2 POST assertions passed')
"
echo "=== PASS: HTTP/2 POST ==="

echo ""
echo "=== ALL E2E TESTS PASSED ==="
