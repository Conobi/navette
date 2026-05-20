#!/usr/bin/env bash
# Wait for the server on $BENCH_PORT to respond to /plaintext with the
# expected 13-byte body. Used by every baseline run.sh — keeps the
# bring-up health probe identical across targets.
set -uo pipefail
PORT="${BENCH_PORT:-8080}"
URL="http://127.0.0.1:${PORT}/plaintext"
EXPECTED="Hello, World!"
TIMEOUT_S="${BENCH_BRINGUP_TIMEOUT:-30}"

end=$((SECONDS + TIMEOUT_S))
while [ $SECONDS -lt $end ]; do
    body="$(curl -sS -m 2 "$URL" 2>/dev/null || true)"
    if [ "$body" = "$EXPECTED" ]; then
        exit 0
    fi
    sleep 0.2
done
echo "check.sh: timeout waiting for $URL to return '$EXPECTED' within ${TIMEOUT_S}s" >&2
exit 1
