#!/usr/bin/env bash
# h1-vs-others.sh — side-by-side HTTP/1.1 plain comparison via wrk.
#
# Spins up each Docker image in turn, hammers /baseline2?a=1&b=2 with
# wrk on port 8080, prints req/s + latency stats.
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
DURATION="${DURATION:-8s}"
THREADS="${THREADS:-4}"
CONNS="${CONNS:-200}"

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

wait_for_h1() {
    local tries=20
    while ! curl -s -m 2 -o /dev/null \
        "http://127.0.0.1:8080$ENDPOINT" 2>/dev/null; do
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
    if ! wait_for_h1; then
        echo "[$name] FAIL: h1 didn't accept requests in 20s"
        docker rm -f "bench-$name" >/dev/null 2>&1 || true
        return
    fi
    docker run --rm --network host wrk:latest -t2 -c50 -d2s \
        "http://127.0.0.1:8080$ENDPOINT" >/dev/null 2>&1 || true
    echo "[$name] h1 plain  wrk -t$THREADS -c$CONNS -d$DURATION  GET $ENDPOINT"
    docker run --rm --network host wrk:latest -t"$THREADS" -c"$CONNS" -d"$DURATION" \
        "http://127.0.0.1:8080$ENDPOINT" 2>&1
    docker rm -f "bench-$name" >/dev/null 2>&1 || true
    sleep 2
}

run_one "navette" "httparena-navette"
run_one "hyper"    "httparena-hyper"
run_one "nginx"    "httparena-nginx"
run_one "h2o"      "httparena-h2o"
