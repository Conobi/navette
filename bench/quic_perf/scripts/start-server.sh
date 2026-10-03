#!/usr/bin/env bash
# Launch the server under test, pinned to core 0, with all volumes mounted.
# Calls wait-ready.sh after the container is up.
#
# Usage: start-server.sh <navette|tquic|lsquic>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: start-server.sh <navette|tquic|lsquic>" >&2
    exit 2
fi

SERVER="$1"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"

# Image tag override (defaults preserve existing behaviour).
NAVETTE_IMAGE="${NAVETTE_IMAGE:-navette-runtime:latest}"
TQUIC_IMAGE="${TQUIC_IMAGE:-tquic-bench:latest}"
LSQUIC_IMAGE="${LSQUIC_IMAGE:-lsquic-bench:latest}"

# Always start from a clean slate.
"$HERE/scripts/stop-server.sh"

case "$SERVER" in
    navette)
        # Resolve the Mojo runtime lib directory.
        if [[ -n "${MOJO_LIB_DIR_OVERRIDE:-}" && -d "$MOJO_LIB_DIR_OVERRIDE" ]]; then
            MOJO_LIB_DIR="$MOJO_LIB_DIR_OVERRIDE"
        else
            MOJO_LIB_DIR="$(cd "$REPO_ROOT" && uv run python -c \
                "import importlib.util; spec = importlib.util.find_spec('modular'); print(spec.submodule_search_locations[0] + '/lib')" 2>/dev/null)"
        fi
        if [[ -z "$MOJO_LIB_DIR" || ! -d "$MOJO_LIB_DIR" ]]; then
            echo "[start-server] ERROR: Mojo runtime lib dir not found — run 'uv sync' or set MOJO_LIB_DIR_OVERRIDE" >&2
            exit 1
        fi

        # Require a locally-built server binary.
        BENCH_BIN="${BENCH_BIN:-$REPO_ROOT/bench/build/h3_server}"
        if [[ ! -x "$BENCH_BIN" ]]; then
            echo "[start-server] ERROR: $BENCH_BIN not found — run 'bench/quic_perf/scripts/build-local.sh h3' first" >&2
            exit 1
        fi

        # Require librustls_mojo.so.
        if [[ ! -f "$REPO_ROOT/lib/librustls_mojo.so" ]]; then
            echo "[start-server] ERROR: lib/librustls_mojo.so not found — run 'build-local.sh' first" >&2
            exit 1
        fi

        mkdir -p "$REPO_ROOT/bench/quic_perf/results/profile"
        WAIT_NR_ARG=()
        if [[ -n "${BENCH_WAIT_NR:-}" ]]; then
            WAIT_NR_ARG=(-e "BENCH_WAIT_NR=$BENCH_WAIT_NR")
        fi
        docker run -d --name bench-h3 \
            --network host \
            --security-opt seccomp=unconfined \
            --ulimit nofile=65536:65536 \
            --cpuset-cpus=0 \
            "${WAIT_NR_ARG[@]}" \
            -e "STATIC_CERT=/certs/server.crt" \
            -e "STATIC_KEY=/certs/server.key" \
            -e "STATIC_BODY_SIZE=${STATIC_BODY_SIZE:-1024}" \
            -e "STATIC_MAX_STREAMS=${STATIC_MAX_STREAMS:-}" \
            -e "STATIC_MAX_QUEUE_DELAY_US=${STATIC_MAX_QUEUE_DELAY_US:-}" \
            -e "STATIC_OVERLOAD_STATS=${STATIC_OVERLOAD_STATS:-}" \
            -v "$BENCH_BIN:/usr/local/bin/h3_server:ro" \
            -v "$REPO_ROOT/lib/librustls_mojo.so:/usr/local/lib/librustls_mojo.so:ro" \
            -v "$REPO_ROOT/lib/librustls_mojo.so:/app/lib/librustls_mojo.so:ro" \
            -v "$MOJO_LIB_DIR:/usr/local/lib/mojo:ro" \
            -e "LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/mojo" \
            -v "$HERE/payloads:/data/static:ro" \
            -v "$REPO_ROOT/certs:/certs:ro" \
            -v "$REPO_ROOT/bench/data/dataset.json:/data/dataset.json:ro" \
            -v "$REPO_ROOT/bench/quic_perf/results/profile:/app/bench/quic_perf/results/profile" \
            --entrypoint /usr/local/bin/h3_server \
            "$NAVETTE_IMAGE" --workers 1 \
            > /tmp/start-server.log
        CONTAINER=bench-h3
        ;;
    tquic)
        # Mount payloads under /data/static so tquic_server serves the same
        # URL shape as navette's handler (which routes /static/<file> → cache).
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
    lsquic)
        docker run -d --name bench-lsquic \
            --network host \
            --cpuset-cpus=0 \
            -v "$HERE/payloads:/data/static:ro" \
            -v "$REPO_ROOT/certs:/certs:ro" \
            --entrypoint /usr/local/bin/http_server \
            "$LSQUIC_IMAGE" \
            -s 0.0.0.0:8443 \
            -c localhost,/certs/server.crt,/certs/server.key \
            -r /data \
            -L crit \
            -g -j \
            -A 1 \
            > /tmp/start-server.log
        CONTAINER=bench-lsquic
        ;;
    *)
        echo "[start-server] unknown server: $SERVER (expected navette, tquic, or lsquic)" >&2
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
