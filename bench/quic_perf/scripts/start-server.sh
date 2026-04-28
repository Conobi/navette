#!/usr/bin/env bash
# Launch the server under test, pinned to core 0, with all volumes mounted.
# Calls wait-ready.sh after the container is up.
#
# Usage: start-server.sh <mojo-net|tquic>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: start-server.sh <mojo-net|tquic>" >&2
    exit 2
fi

SERVER="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"

# Image tag override (defaults preserve existing behaviour).
# Set when parallel workflows might overwrite mojo-net-bench:latest.
MOJO_NET_IMAGE="${MOJO_NET_IMAGE:-mojo-net-bench:latest}"
TQUIC_IMAGE="${TQUIC_IMAGE:-tquic-bench:latest}"

# Always start from a clean slate.
"$HERE/scripts/stop-server.sh"

case "$SERVER" in
    mojo-net)
        docker run -d --name bench-h3 \
            --network host \
            --security-opt seccomp=unconfined \
            --ulimit nofile=65536:65536 \
            --cpuset-cpus=0 \
            -v "$HERE/payloads:/data/static:ro" \
            -v "$REPO_ROOT/certs:/certs:ro" \
            --entrypoint /usr/local/bin/h3_server \
            "$MOJO_NET_IMAGE" --workers 1 \
            > /tmp/start-server.log
        CONTAINER=bench-h3
        ;;
    tquic)
        # Mount payloads under /data/static so tquic_server serves the same
        # URL shape as mojo-net's handler (which routes /static/<file> → cache).
        docker run -d --name bench-tquic \
            --network host \
            --cpuset-cpus=0 \
            -v "$HERE/payloads:/data/static:ro" \
            -v "$REPO_ROOT/certs:/certs:ro" \
            --entrypoint /usr/local/bin/tquic_server \
            "$TQUIC_IMAGE" \
            -l 0.0.0.0:8443 \
            -c /certs/server.crt \
            -k /certs/server.key \
            -r /data \
            --log-level OFF \
            > /tmp/start-server.log
        CONTAINER=bench-tquic
        ;;
    *)
        echo "[start-server] unknown server: $SERVER (expected mojo-net or tquic)" >&2
        exit 2
        ;;
esac

echo "[start-server] $SERVER container: $CONTAINER"

if ! "$HERE/scripts/wait-ready.sh"; then
    echo "[start-server] server failed to become ready; logs follow:"
    docker logs "$CONTAINER" 2>&1 | tail -30
    "$HERE/scripts/stop-server.sh"
    exit 1
fi

echo "$CONTAINER"
