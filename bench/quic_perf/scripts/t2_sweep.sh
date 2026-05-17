#!/usr/bin/env bash
# T2 sweep driver — runs short-conn / 1k / tquic_client at multiple
# BENCH_WAIT_NR values. Spec: 2026-05-05-shortconn-io-path-investigation §6.
# Each iter: hygiene check, bench.sh --iters 1, harvest result+sidecar, 30s pause.
#
# Usage: t2_sweep.sh <wait_nr> <iters>

set -uo pipefail

WN="$1"
ITERS="$2"

REPO="$(git rev-parse --show-toplevel)"
HERE="$REPO/bench/quic_perf"
DEST="$HERE/results/baselines/io-path-wait-nr/wn=$WN"

mkdir -p "$DEST/json"

for i in $(seq 1 "$ITERS"); do
    # Hygiene gate: 1-min loadavg ≤1.0 (relaxed 2026-05-11 to match host desktop
    # baseline of firefox+gnome+display-manager ~0.8; foreign-mojo=0 stays strict
    # per feedback_concurrent_mojo_sessions_perturb_bench.md).
    WAIT=0
    while [ $WAIT -lt 180 ]; do
        LOAD=$(awk '{print int($1*100)}' /proc/loadavg)
        FOREIGN=$(ps --sort=-pcpu -eo comm,pcpu | awk 'NR>1 && $2>20 && $1~/mojo/' | wc -l)
        if [ "$LOAD" -le 100 ] && [ "$FOREIGN" -eq 0 ]; then break; fi
        echo "[t2 wn=$WN iter=$i] busy (load=$LOAD foreign_mojo=$FOREIGN), wait 30s"
        sleep 30
        WAIT=$((WAIT+30))
    done
    if [ $WAIT -ge 180 ]; then
        echo "[t2 wn=$WN iter=$i] SKIPPED-BUSY"
        continue
    fi

    echo "[t2 wn=$WN iter=$i] running"
    BENCH_WAIT_NR="$WN" "$HERE/scripts/bench.sh" navette 1k short-conn tquic_client --iters 1 \
        > "$DEST/iter-$i.log" 2>&1
    BENCH_RC=$?

    # Capture latest result JSON written into bench/quic_perf/results/.
    LATEST_JSON=$(ls -t "$HERE/results"/*.json 2>/dev/null | head -1)
    if [ -n "$LATEST_JSON" ]; then
        cp "$LATEST_JSON" "$DEST/json/iter-$i.json"
    fi

    # Capture latest sidecar (server INSTRUMENTATION dump on stop).
    LATEST_SIDE=$(ls -t "$HERE/results/profile"/INSTRUMENTATION-*.json 2>/dev/null | head -1)
    if [ -n "$LATEST_SIDE" ]; then
        cp "$LATEST_SIDE" "$DEST/json/iter-$i-sidecar.json"
    fi

    echo "[t2 wn=$WN iter=$i] rc=$BENCH_RC; sleep 30 (pacing)"
    sleep 30
done

echo "[t2 wn=$WN] done"
