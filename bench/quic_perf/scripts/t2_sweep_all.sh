#!/usr/bin/env bash
# T2 sweep orchestrator — runs t2_sweep.sh across all BENCH_WAIT_NR knobs.
# Spec: 2026-05-05-shortconn-io-path-investigation §6.
# Per-knob: 10 iters via t2_sweep.sh (which paces 30s between iters).
# Between knobs: 60s thermal-settle pause.
#
# Usage: t2_sweep_all.sh [iters]   (default iters=10)

set -uo pipefail

ITERS="${1:-10}"
HERE="$(cd "$(dirname "$0")" && pwd)"
KNOBS=(1 2 4 8 16 32)

echo "[t2-all] start $(date -Is); iters=$ITERS knobs=${KNOBS[*]}"

for WN in "${KNOBS[@]}"; do
    echo "[t2-all] === wn=$WN === $(date -Is)"
    bash "$HERE/t2_sweep.sh" "$WN" "$ITERS"
    echo "[t2-all] wn=$WN complete; inter-knob settle 60s"
    sleep 60
done

echo "[t2-all] all knobs complete $(date -Is)"
