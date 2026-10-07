#!/usr/bin/env bash
# /loop iter perf bench — n=5, 30s pauses, PROFILE_ACCEPT=False.
# Loadavg gate waits up to 3min for host to settle (post-build).
set -euo pipefail
TAG="${1:?missing TAG}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$HERE/results/loop/$TAG"
mkdir -p "$OUT_DIR"

wait_for_quiet() {
    local i=$1
    for try in 1 2 3 4 5 6; do
        local la=$(awk "{print \$1}" /proc/loadavg)
        local foreign=$(pgrep -fc "mojo run" || true)
        if (( foreign > 0 )); then
            echo "[pre-iter $i] ABORT: $foreign foreign mojo run procs"; exit 3
        fi
        if awk "BEGIN{exit !($la <= 1.0)}"; then
            echo "[pre-iter $i] loadavg=$la foreign=0 OK"; return 0
        fi
        echo "[pre-iter $i] loadavg=$la > 1.0, waiting 30s (try $try/6)"
        sleep 30
    done
    echo "ABORT: loadavg never settled below 1.0"; exit 3
}

for i in 1 2 3 4 5; do
    wait_for_quiet "$i"
    echo "=== $TAG iter $i/5 ==="
    "$HERE/scripts/bench.sh" navette 1k short-conn tquic_client --iters 1
    LATEST=$(ls -1t "$HERE/results"/2026-*-navette-1k-short-conn-tquic_client-iter1.json | head -1)
    cp "$LATEST" "$OUT_DIR/iter-${i}.json"
    if (( i < 5 )); then sleep 30; fi
done
echo "[loop] $TAG: $(ls -1 "$OUT_DIR"/iter-*.json | wc -l) results"
