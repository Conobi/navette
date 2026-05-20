#!/usr/bin/env bash
set -uo pipefail
PORT="${BENCH_PORT:-8080}"
NAME="${BENCH_CONTAINER_NAME:-flare-cmp-flare}"
CPU="${BENCH_SERVER_CPU:-0}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
exec docker run --rm --name "$NAME" --network host \
    --ulimit nofile=1048576:1048576 \
    --cpuset-cpus="$CPU" \
    -e FLARE_BENCH_PORT="$PORT" \
    flare-cmp-flare:latest
