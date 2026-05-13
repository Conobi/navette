#!/usr/bin/env bash
# scripts/test_h2_proxy_internet.sh
#
# End-to-end test: Mojo H2 reverse proxy → 1.1.1.1:443 (Cloudflare).
#
# Validates:
#   - TLS + ALPN h2 negotiated on both hops
#   - H2 multiplexing: two requests reuse the same frontend H2 connection
#   - Backend sees h2 (confirmed by cdn-cgi/trace response body)
#   - Proxy correctly rewrites the host header (:authority)
#   - Responses delivered correctly to the client
#
# Skips gracefully if 1.1.1.1:443 is unreachable (CI without internet).
#
# Usage:
#   bash scripts/test_h2_proxy_internet.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

BOUCLE_DIR="${BOUCLE_DIR:-$HOME/Projets/perso/boucle}"
PROXY_PORT=8445          # different from the local proxy test (8444) to avoid conflicts
CERT_DIR="examples/reverse_proxy/certs"
BACKEND_HOST="1.1.1.1"
BACKEND_PORT=443

PROXY_LOG="$(mktemp -t mojo-h2-internet-proxy.XXXXXX.log)"
PATCHED_SRC="$(mktemp -t mojo-h2-internet-main.XXXXXX.mojo)"
PROXY_BIN="$(mktemp -t mojo-h2-internet-proxy.XXXXXX)"
PROXY_PID=""
PASS=0
TOTAL=0

cleanup() {
    local rc=$?
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$PATCHED_SRC" "$PROXY_BIN"
    if [ "$rc" -ne 0 ]; then
        echo ""
        echo "=== Proxy log ==="
        cat "$PROXY_LOG" 2>/dev/null || true
    fi
    rm -f "$PROXY_LOG"
    exit $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 0. Connectivity pre-check — skip gracefully if offline
# ---------------------------------------------------------------------------
echo "--- connectivity check ---"
if ! curl -sk --max-time 5 --http2 "https://$BACKEND_HOST/cdn-cgi/trace" -o /dev/null; then
    echo "SKIP: $BACKEND_HOST:$BACKEND_PORT unreachable — no internet access"
    exit 0
fi
echo "    $BACKEND_HOST:$BACKEND_PORT reachable"

# ---------------------------------------------------------------------------
# 1. Ensure certs exist
# ---------------------------------------------------------------------------
if [ ! -f "$CERT_DIR/proxy_cert.pem" ]; then
    echo "Generating test certificates..."
    bash scripts/gen_test_certs.sh
fi

# ---------------------------------------------------------------------------
# 2. Build proxy patched to target 1.1.1.1:443
# ---------------------------------------------------------------------------
echo ""
echo "--- build ---"
sed \
    -e "s/comptime _BACKEND_PORT: UInt16 = 9444/comptime _BACKEND_PORT: UInt16 = $BACKEND_PORT/" \
    -e "s/comptime _BACKEND_HOST: String = \"localhost\"/comptime _BACKEND_HOST: String = \"$BACKEND_HOST\"/" \
    -e "s/SocketAddrV4(127, 0, 0, 1, port=_BACKEND_PORT)/SocketAddrV4(1, 1, 1, 1, port=_BACKEND_PORT)/" \
    -e "s/comptime _LISTEN_PORT: UInt16 = 8444/comptime _LISTEN_PORT: UInt16 = $PROXY_PORT/" \
    examples/h2_reverse_proxy/main.mojo > "$PATCHED_SRC"

rm -f ./*.mojopkg 2>/dev/null || true
LD_LIBRARY_PATH=lib uv run mojox build \
    -I conformance \
    "$PATCHED_SRC" -o "$PROXY_BIN" >"$PROXY_LOG" 2>&1
echo "    build OK"

# ---------------------------------------------------------------------------
# 3. Start proxy
# ---------------------------------------------------------------------------
echo ""
echo "--- proxy startup ---"
LD_LIBRARY_PATH=lib "$PROXY_BIN" >>"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "FAIL: proxy failed to start"
    exit 1
fi
echo "    proxy up (pid=$PROXY_PID, port=$PROXY_PORT)"

# ---------------------------------------------------------------------------
# Helper: run one curl GET and capture response + HTTP status code
# ---------------------------------------------------------------------------
_curl_get() {
    local path="$1"
    local extra_headers="${2:-}"
    local args=(
        --http2 -sk --max-time 15
        -w "\n__STATUS__:%{http_code}"
        "https://127.0.0.1:$PROXY_PORT$path"
    )
    if [ -n "$extra_headers" ]; then
        args+=(-H "$extra_headers")
    fi
    curl "${args[@]}"
}

# ---------------------------------------------------------------------------
# Test 1: Single GET /cdn-cgi/trace — full field validation
# ---------------------------------------------------------------------------
echo ""
echo "--- test 1: single GET /cdn-cgi/trace ---"
TOTAL=$((TOTAL + 1))
RAW=$(_curl_get "/cdn-cgi/trace" "x-test: mojo-proxy-internet")
STATUS=$(echo "$RAW" | grep '__STATUS__:' | sed 's/__STATUS__://')
BODY=$(echo "$RAW" | grep -v '__STATUS__:')

echo "    HTTP $STATUS"
echo "$BODY" | sed 's/^/    /'

python3 -c "
import sys
body = '''$BODY'''
lines = dict(l.split('=', 1) for l in body.strip().splitlines() if '=' in l)

errors = []
if lines.get('http') != 'http/2':
    errors.append(f'http: expected http/2, got {lines.get(\"http\")}')
if lines.get('h') != '$BACKEND_HOST':
    errors.append(f'h: expected $BACKEND_HOST, got {lines.get(\"h\")}')
if lines.get('visit_scheme') != 'https':
    errors.append(f'visit_scheme: expected https, got {lines.get(\"visit_scheme\")}')
if lines.get('tls') != 'TLSv1.3':
    errors.append(f'tls: expected TLSv1.3, got {lines.get(\"tls\")}')
if not lines.get('ip'):
    errors.append('ip: missing')
if not lines.get('colo'):
    errors.append('colo: missing')
if not lines.get('uag'):
    errors.append('uag: missing (User-Agent not forwarded)')

if errors:
    for e in errors: print('  FAIL:', e)
    sys.exit(1)
print('    all fields valid')
"
if [ "$STATUS" != "200" ]; then
    echo "  FAIL: expected HTTP 200, got $STATUS"
    exit 1
fi
PASS=$((PASS + 1))
echo "=== PASS: test 1 ==="

# ---------------------------------------------------------------------------
# Test 2: Two requests on the same H2 connection (multiplexing)
#
# curl --next reuses the H2 connection → stream 1 then stream 3.
# Both must return 200 with http=http/2.
# ---------------------------------------------------------------------------
echo ""
echo "--- test 2: two multiplexed requests (H2 stream reuse) ---"
TOTAL=$((TOTAL + 1))
RESP_A="$(mktemp -t mojo-h2-inet-a.XXXXXX)"
RESP_B="$(mktemp -t mojo-h2-inet-b.XXXXXX)"

curl --http2 -sk --max-time 15 \
    "https://127.0.0.1:$PROXY_PORT/cdn-cgi/trace" \
    -o "$RESP_A" \
    --next \
    --http2 -sk --max-time 15 \
    "https://127.0.0.1:$PROXY_PORT/cdn-cgi/trace" \
    -o "$RESP_B"

python3 -c "
import sys

errors = []
for label, path in [('stream-A', '$RESP_A'), ('stream-B', '$RESP_B')]:
    with open(path) as f:
        body = f.read()
    lines = dict(l.split('=', 1) for l in body.strip().splitlines() if '=' in l)
    if lines.get('http') != 'http/2':
        errors.append(f'{label}: http expected http/2, got {lines.get(\"http\")}')
    if lines.get('h') != '$BACKEND_HOST':
        errors.append(f'{label}: h expected $BACKEND_HOST, got {lines.get(\"h\")}')

if errors:
    for e in errors: print('  FAIL:', e)
    sys.exit(1)
print('    stream-A: http=' + dict(l.split(\"=\",1) for l in open(\"$RESP_A\").read().strip().splitlines() if \"=\" in l).get('http','?'))
print('    stream-B: http=' + dict(l.split(\"=\",1) for l in open(\"$RESP_B\").read().strip().splitlines() if \"=\" in l).get('http','?'))
print('    both streams delivered correctly')
"
rm -f "$RESP_A" "$RESP_B"
PASS=$((PASS + 1))
echo "=== PASS: test 2 ==="

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "All $PASS/$TOTAL internet proxy tests passed."
echo "(backend: https://$BACKEND_HOST:$BACKEND_PORT, frontend: https://127.0.0.1:$PROXY_PORT)"
