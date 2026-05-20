#!/usr/bin/env bash
# Bring up navette H1.1 plaintext server in 1-worker mode on $BENCH_PORT.
# The image is built once by scripts/build-baselines.sh (which calls
# bench/build.sh -- the same multi-stage Dockerfile used for every other
# navette bench).
set -uo pipefail
PORT="${BENCH_PORT:-8080}"
NAME="${BENCH_CONTAINER_NAME:-flare-cmp-navette}"
CPU="${BENCH_SERVER_CPU:-0}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
exec docker run --rm --name "$NAME" --network host \
    --security-opt seccomp=unconfined \
    --ulimit memlock=-1:-1 \
    --ulimit nofile=1048576:1048576 \
    --cpuset-cpus="$CPU" \
    -e BENCH_PROTOCOL=h1 \
    -e BENCH_WORKERS=1 \
    -e BENCH_H1_PORT="$PORT" \
    navette-bench:latest
