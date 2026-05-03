#!/usr/bin/env bash
# Drive the server with tquic_client, multi-threaded, duration-based.
# Usage: run-tquic-client.sh <payload> <scenario> <duration_seconds>
# Captures stdout to /tmp/client-stdout.log for the parser.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: run-tquic-client.sh <payload> <scenario> <duration>" >&2
    exit 2
fi

PAYLOAD="$1"
SCENARIO="$2"
DURATION="$3"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$HERE/configs/${SCENARIO}.env"

# Optional session-file for TLS 1.3 resumption (P2). Each scenario config
# may set SESSION_FILE; bind-mount its directory into the container so the
# file persists across invocations on the same scenario.
SESSION_ARGS=()
SESSION_MOUNT=()
if [[ -n "${SESSION_FILE:-}" ]]; then
    SESSION_DIR="$(dirname "$SESSION_FILE")"
    mkdir -p "$SESSION_DIR"
    SESSION_MOUNT=(-v "$SESSION_DIR:$SESSION_DIR")
    SESSION_ARGS=(--session-file "$SESSION_FILE")
fi

docker run --rm --network host --cpuset-cpus=2-5 \
    "${SESSION_MOUNT[@]}" \
    --entrypoint /usr/local/bin/tquic_client tquic-bench:latest \
    --threads 4 \
    --max-concurrent-conns 25 \
    --max-requests-per-conn "$MAX_REQUESTS_PER_CONN" \
    --max-concurrent-requests "$MAX_CONCURRENT_REQUESTS" \
    --total-requests-per-thread 0 \
    --send-udp-payload-size 1350 \
    --duration "$DURATION" \
    "${SESSION_ARGS[@]}" \
    --connect-to 127.0.0.1:8443 \
    "https://127.0.0.1:8443/static/${PAYLOAD}.bin" \
    > /tmp/client-stdout.log 2>&1 || true

# tquic_client may exit non-zero when --duration ends; we still want stdout.
echo "[run-tquic-client] $PAYLOAD/$SCENARIO/${DURATION}s: stdout in /tmp/client-stdout.log"
