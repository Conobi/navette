#!/usr/bin/env bash
# H-multicore diagnostic driver: 6 cells × N iters with 30s pauses.
# Cells: {navette, tquic} × {0, 0-1, 0-3}
# Default ITERS=5, output dir: bench/quic_perf/results/baselines/h-multicore-scaling
#
# Usage: run-scaling.sh [ITERS]

set -euo pipefail

ITERS="${1:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="$HERE/results/baselines/h-multicore-scaling"
mkdir -p "$OUTDIR"

CELLS=(
    "navette 0"
    "navette 0-1"
    "navette 0-3"
    "tquic 0"
    "tquic 0-1"
    "tquic 0-3"
)

for cell in "${CELLS[@]}"; do
    SERVER=$(echo "$cell" | cut -d' ' -f1)
    CPUSET=$(echo "$cell" | cut -d' ' -f2)
    SAFE_CPUSET=$(echo "$CPUSET" | tr ',' '_')
    for iter in $(seq 1 "$ITERS"); do
        OUT="$OUTDIR/${SERVER}-cpuset${SAFE_CPUSET}-iter${iter}.json"
        echo "=== cell: $SERVER cpuset=$CPUSET iter=$iter/$ITERS ==="
        echo "    [host] loadavg: $(awk '{print $1}' /proc/loadavg) | top: $(ps -eo pcpu,comm --sort=-pcpu --no-headers | head -1)"
        HERE="$HERE" "$HERE/scripts/h-multicore/bench-cell.sh" "$SERVER" "$CPUSET" "$OUT"
        # 30s pause between iters per memory feedback_bench_iter_pacing.md
        if [[ "$iter" -lt "$ITERS" ]]; then
            echo "    [pause] 30s inter-iter"
            sleep 30
        fi
    done
    echo "    [pause] 30s inter-cell"
    sleep 30
done

echo "[h-multicore] all cells done. Results in $OUTDIR"
