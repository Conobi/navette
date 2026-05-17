#!/usr/bin/env bash
# H-multicore minimal confirmation: 4 cells (endpoints only) × n=2 iters.
# Used when host hygiene precludes full 6×5 sweep.

set -euo pipefail

ITERS="${1:-2}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="$HERE/results/baselines/h-multicore-scaling"
mkdir -p "$OUTDIR"

CELLS=(
    "navette 0"
    "navette 0-3"
    "tquic 0"
    "tquic 0-3"
)

for cell in "${CELLS[@]}"; do
    SERVER=$(echo "$cell" | cut -d' ' -f1)
    CPUSET=$(echo "$cell" | cut -d' ' -f2)
    SAFE_CPUSET=$(echo "$CPUSET" | tr ',' '_')
    for iter in $(seq 1 "$ITERS"); do
        OUT="$OUTDIR/${SERVER}-cpuset${SAFE_CPUSET}-iter${iter}.json"
        echo "=== $SERVER cpuset=$CPUSET iter=$iter/$ITERS load=$(awk '{print $1}' /proc/loadavg) top=$(ps -eo pcpu,comm --sort=-pcpu --no-headers | head -1 | tr -s ' ') ==="
        HERE="$HERE" "$HERE/scripts/h-multicore/bench-cell.sh" "$SERVER" "$CPUSET" "$OUT" 2>&1 | tail -3
        if [[ "$iter" -lt "$ITERS" ]]; then
            sleep 20
        fi
    done
    sleep 20
done

echo "[h-multicore] minimal confirmation done. $OUTDIR"
