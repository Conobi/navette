#!/usr/bin/env bash
# Probe :8443 with a real QUIC handshake until the server responds, or fail.
# Used by start-server.sh after the server container is launched.
#
# Returns 0 on first successful probe; non-zero after 10 s of failures.

set -euo pipefail

MAX_TRIES=50           # 50 * 200 ms = 10 s
SLEEP_BETWEEN=0.2

for i in $(seq 1 $MAX_TRIES); do
    if timeout 5 docker run --rm --network host \
        --entrypoint /usr/local/bin/tquic_client tquic-bench:latest \
        --connect-to 127.0.0.1:8443 \
        --max-requests-per-conn 1 \
        https://127.0.0.1:8443/static/1k.bin \
        > /tmp/wait-ready.log 2>&1; then
        echo "[wait-ready] server responded on attempt $i"
        exit 0
    fi
    sleep "$SLEEP_BETWEEN"
done

echo "[wait-ready] timeout after $MAX_TRIES attempts"
echo "[wait-ready] last probe log:"
cat /tmp/wait-ready.log
exit 1
