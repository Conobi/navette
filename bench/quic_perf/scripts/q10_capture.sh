#!/usr/bin/env bash
# Q10 T2 capture driver — n=10 short-conn iters with 30s inter-iter pauses.
# Per memory feedback_bench_iter_pacing.md (back-to-back --iters runs drift).
# Per memory feedback_concurrent_mojo_sessions_perturb_bench.md (audit foreign mojo).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$HERE/results/baselines/q10-flush-impl-subleg"
mkdir -p "$OUT_DIR"

# Audit host before EVERY iter (loadavg ≤1.0; zero foreign mojo).
audit() {
    local i=$1
    local la=$(awk "{print \$1}" /proc/loadavg)
    local foreign=$(pgrep -fc "mojo run" || true)
    echo "[pre-iter $i] loadavg=$la  foreign_mojo=$foreign"
    # awk-based gate (NixOS default user shell may not have `bc`).
    if awk "BEGIN{exit !($la > 1.0)}"; then
        echo "[pre-iter $i] ABORT: loadavg $la > 1.0"; exit 3
    fi
    if (( foreign > 0 )); then
        echo "[pre-iter $i] ABORT: $foreign foreign mojo run procs"; exit 3
    fi
}

for i in 1 2 3 4 5 6 7 8 9 10; do
    audit "$i"
    echo "=== Q10 capture iter $i/10 ==="
    "$HERE/scripts/bench.sh" mojo-net 1k short-conn tquic_client --iters 1
    # Move/rename instrumentation sidecar to keep them numbered.
    LATEST=$(ls -1t "$HERE/results/profile"/INSTRUMENTATION-*.json 2>/dev/null | head -1)
    if [[ -n "$LATEST" ]]; then
        mv "$LATEST" "$OUT_DIR/iter-${i}-sidecar.json"
        echo "  -> $OUT_DIR/iter-${i}-sidecar.json"
    else
        echo "  WARN: no instrumentation sidecar found"
    fi
    # Inter-iter pause (skip after last iter).
    if (( i < 10 )); then
        echo "[post-iter $i] sleep 30 (inter-iter pause)"
        sleep 30
    fi
done
echo "[q10] capture complete. n=$(ls -1 "$OUT_DIR"/iter-*-sidecar.json | wc -l) sidecars in $OUT_DIR"
