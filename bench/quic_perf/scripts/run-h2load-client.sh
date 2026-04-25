#!/usr/bin/env bash
# Drive the server with h2load-h3 (single-threaded, regression-tracking only).
# Usage: run-h2load-client.sh <payload> <scenario> <duration_seconds>

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: run-h2load-client.sh <payload> <scenario> <duration>" >&2
    exit 2
fi

PAYLOAD="$1"
SCENARIO="$2"
DURATION="$3"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$HERE/configs/${SCENARIO}.env"

docker run --rm --network host --cpuset-cpus=2-5 \
    h2load-h3:latest \
    -D "$DURATION" -c 100 -m "$H2LOAD_M" \
    --alpn-list=h3 \
    "https://127.0.0.1:8443/static/${PAYLOAD}.bin" \
    > /tmp/client-stdout.log 2>&1 || true

echo "[run-h2load-client] $PAYLOAD/$SCENARIO/${DURATION}s: stdout in /tmp/client-stdout.log"
