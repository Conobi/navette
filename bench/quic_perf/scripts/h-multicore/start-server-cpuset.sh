#!/usr/bin/env bash
# H-multicore diagnostic variant of start-server.sh.
# Same as scripts/start-server.sh but accepts a CPUSET as 2nd arg.
#
# Usage: start-server-cpuset.sh <mojo-net|tquic> <cpuset>
#   cpuset examples: "0", "0-1", "0-3"
#
# DOES NOT MODIFY production scripts. Used by h-multicore bench harness only.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: start-server-cpuset.sh <mojo-net|tquic> <cpuset>" >&2
    exit 2
fi

SERVER="$1"
CPUSET="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"

MOJO_NET_IMAGE="${MOJO_NET_IMAGE:-mojo-net-bench:latest}"
TQUIC_IMAGE="${TQUIC_IMAGE:-tquic-bench:latest}"

"$HERE/scripts/stop-server.sh"

case "$SERVER" in
    mojo-net)
        mkdir -p "$REPO_ROOT/bench/quic_perf/results/profile"
        docker run -d --name bench-h3 \
            --network host \
            --security-opt seccomp=unconfined \
            --ulimit nofile=65536:65536 \
            --cpuset-cpus="$CPUSET" \
            -v "$HERE/payloads:/data/static:ro" \
            -v "$REPO_ROOT/certs:/certs:ro" \
            -v "$REPO_ROOT/bench/quic_perf/results/profile:/app/bench/quic_perf/results/profile" \
            --entrypoint /usr/local/bin/h3_server \
            "$MOJO_NET_IMAGE" --workers 1 \
            > /tmp/start-server.log
        CONTAINER=bench-h3
        ;;
    tquic)
        docker run -d --name bench-tquic \
            --network host \
            --cpuset-cpus="$CPUSET" \
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
        echo "[start-server-cpuset] unknown server: $SERVER" >&2
        exit 2
        ;;
esac

echo "[start-server-cpuset] $SERVER container: $CONTAINER (cpuset=$CPUSET)"

if ! "$HERE/scripts/wait-ready.sh"; then
    echo "[start-server-cpuset] server failed to become ready; logs follow:"
    docker logs "$CONTAINER" 2>&1 | tail -30
    "$HERE/scripts/stop-server.sh"
    exit 1
fi

echo "$CONTAINER"
