#!/usr/bin/env bash
# h2-vs-others.sh — side-by-side HTTP/2 TLS comparison.
#
# Spins up each Docker image in turn, hammers /baseline2?a=1&b=2 with
# h2load over h2 TLS, and prints req/s + status code summary per server.
#
# Servers compared: navette (us), hyper, nginx, h2o.
# Build the images once before running:
#   bash bench/build.sh                                   # navette
#   bash bench/compare/build-comparators.sh               # everyone else
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARENA="$REPO_ROOT/bench/.httparena"
CERTS_DIR="$ARENA/certs"
DATA_DIR="$ARENA/data"

ENDPOINT='/baseline2?a=1&b=2'
WARMUP_REQS="${WARMUP_REQS:-5000}"
N="${N:-200000}"
C="${C:-50}"
M="${M:-16}"

if [ ! -d "$ARENA" ]; then
    echo "error: $ARENA not found. Clone HttpArena into bench/.httparena first."
    exit 1
fi

DOCKER_FLAGS=(
    -d --rm --network host
    --security-opt seccomp=unconfined
    --ulimit memlock=-1:-1
    --ulimit nofile=1048576:1048576
    -v "$DATA_DIR/dataset.json:/data/dataset.json:ro"
    -v "$DATA_DIR/static:/data/static:ro"
    -v "$CERTS_DIR:/certs:ro"
)

wait_for_h2() {
    local tries=20
    while ! docker run --rm --network host h2load:latest -n 10 -c 1 -m 1 \
        "https://127.0.0.1:8443$ENDPOINT" 2>&1 | grep -q "10 succeeded"; do
        tries=$((tries - 1))
        [ $tries -le 0 ] && return 1
        sleep 1
    done
    return 0
}

run_one() {
    local name="$1" image="$2"
    echo
    echo "============================================"
    echo "  $name"
    echo "============================================"
    docker rm -f "bench-$name" >/dev/null 2>&1 || true
    docker run --name "bench-$name" "${DOCKER_FLAGS[@]}" "$image" >/dev/null
    if ! wait_for_h2; then
        echo "[$name] FAIL: h2 didn't accept requests within 20s"
        docker rm -f "bench-$name" >/dev/null 2>&1 || true
        return
    fi
    docker run --rm --network host h2load:latest -n "$WARMUP_REQS" -c "$C" -m "$M" \
        "https://127.0.0.1:8443$ENDPOINT" >/dev/null 2>&1 || true
    echo "[$name] h2 TLS GET $ENDPOINT  -n $N -c $C -m $M"
    docker run --rm --network host h2load:latest -n "$N" -c "$C" -m "$M" \
        "https://127.0.0.1:8443$ENDPOINT" 2>&1 | \
        grep -E "^finished in|^requests:|^status codes:|req/s.*:" | head -4
    docker rm -f "bench-$name" >/dev/null 2>&1 || true
    sleep 2
}

run_one "navette" "httparena-navette"
run_one "hyper"    "httparena-hyper"
run_one "nginx"    "httparena-nginx"
run_one "h2o"      "httparena-h2o"
