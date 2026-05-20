#!/usr/bin/env bash
# Convenience wrapper — builds every image (if missing) and runs the
# full single-worker matrix. Use on the bench VPS or any idle Linux
# host with Docker.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGETS="${TARGETS:-navette,nginx,go-nethttp,hyper,axum,actix-web}"
SERVER_CPU="${BENCH_SERVER_CPU:-0}"
CLIENT_CPU="${BENCH_CLIENT_CPU:-2}"

# Loadavg sanity — refuse to run if the host is busy.
loadavg=$(awk '{print $1}' /proc/loadavg)
if awk "BEGIN { exit !($loadavg > 2.0) }"; then
    echo "Host loadavg=${loadavg} (>2.0). Refusing to bench on a busy box." >&2
    exit 2
fi

# Build any missing images. Cached layers make this fast on a re-run.
bash "$ROOT/scripts/build-baselines.sh" "$TARGETS,wrk2"

# Run the bench.
BENCH_SERVER_CPU="$SERVER_CPU" BENCH_CLIENT_CPU="$CLIENT_CPU" \
    bash "$ROOT/scripts/bench_vs_baseline.sh" --only="$TARGETS"
