#!/usr/bin/env bash
# bench/ab/run_h3.sh — Interleaved A/B H3 regression benchmark
#
# Uses the quic_perf harness (CPU-pinned, 30s measurement, tquic_client)
# with MOJO_NET_IMAGE swapped between old and new.
#
# Usage:
#   bash bench/ab/run_h3.sh              # 5 iterations (each ~2.5 min = ~25 min total)
#   ITERS=3 bash bench/ab/run_h3.sh      # quick smoke
#
# Env:
#   ITERS        — iterations per image (default: 5)
#   PAUSE        — seconds between runs (default: 30)
#   PAYLOAD      — payload size (default: 5k)
#   SCENARIO     — long-conn or short-conn (default: long-conn)
#   CLIENT       — tquic_client or h2load (default: tquic_client)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
QUIC_PERF="$REPO_ROOT/bench/quic_perf"
BENCH_SH="$QUIC_PERF/scripts/bench.sh"

ITERS="${ITERS:-5}"
PAUSE="${PAUSE:-30}"
PAYLOAD="${PAYLOAD:-5k}"
SCENARIO="${SCENARIO:-long-conn}"
CLIENT="${CLIENT:-tquic_client}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$SCRIPT_DIR/results/$TIMESTAMP-h3"
mkdir -p "$OUTDIR"

OLD_TAG="${OLD_TAG:-navette-bench:old}"
NEW_TAG="${NEW_TAG:-navette-bench:new}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

check_host() {
    echo "  loadavg: $(cat /proc/loadavg)"
    local mojo_procs
    mojo_procs=$(pgrep -c -f 'mojo' 2>/dev/null || echo 0)
    if [ "$mojo_procs" -gt 0 ]; then
        echo "  WARNING: $mojo_procs mojo process(es) running"
    fi
}

log "A/B H3 Regression Benchmark"
log "  OLD: $OLD_TAG"
log "  NEW: $NEW_TAG"
log "  Payload: $PAYLOAD  Scenario: $SCENARIO  Client: $CLIENT"
log "  Iterations: $ITERS  Pause: ${PAUSE}s"
log "  Output: $OUTDIR"
log "  Harness: quic_perf (CPU-pinned core 0, 30s measurement, 5s warmup)"
echo ""

# Save metadata
cat > "$OUTDIR/meta.json" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "protocol": "h3",
  "payload": "$PAYLOAD",
  "scenario": "$SCENARIO",
  "client": "$CLIENT",
  "iterations": $ITERS,
  "pause_seconds": $PAUSE,
  "measurement_seconds": 30,
  "warmup_seconds": 5,
  "old_image": "$OLD_TAG",
  "new_image": "$NEW_TAG",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "cpu": "$(lscpu 2>/dev/null | grep 'Model name' | sed 's/.*: *//' || echo 'unknown')",
  "server_core": 0,
  "client_cores": [2, 3, 4, 5]
}
EOF

OLD_RESULTS=()
NEW_RESULTS=()

for i in $(seq 1 "$ITERS"); do
    log "=== Iteration $i/$ITERS ==="

    # Alternate start order
    if [ $((i % 2)) -eq 1 ]; then
        first_tag="$OLD_TAG"; first_label="OLD"
        second_tag="$NEW_TAG"; second_label="NEW"
    else
        first_tag="$NEW_TAG"; first_label="NEW"
        second_tag="$OLD_TAG"; second_label="OLD"
    fi

    for run_idx in 1 2; do
        if [ "$run_idx" -eq 1 ]; then
            tag="$first_tag"; label="$first_label"
        else
            tag="$second_tag"; label="$second_label"
        fi

        check_host
        log "  Running $label ($tag)..."

        # Run bench.sh with the right image — results go to quic_perf/results/
        MOJO_NET_IMAGE="$tag" "$BENCH_SH" navette "$PAYLOAD" "$SCENARIO" "$CLIENT" --iters 1 > "$OUTDIR/_bench.log" 2>&1
        tail -3 "$OUTDIR/_bench.log"

        # Find the most recent result file and copy it to our output dir
        latest=$(ls -t "$QUIC_PERF/results/"*.json 2>/dev/null | head -1 || true)
        if [ -n "$latest" ]; then
            dest="$OUTDIR/$(basename "$latest" .json)-${label,,}.json"
            cp "$latest" "$dest"
            # Extract rps
            rps=$(python3 -c "import json; d=json.load(open('$dest')); print(d['results'].get('rps', 'N/A'))")
            cpu=$(python3 -c "import json; d=json.load(open('$dest')); print(d['results'].get('server_cpu_percent', 'N/A'))")
            log "  $label: ${rps} req/s, ${cpu}% CPU"
        fi

        log "  $label done. Pausing ${PAUSE}s..."
        sleep "$PAUSE"
    done
done

log "All iterations complete."
log ""
log "Extracting results..."

# Parse all results and compute stats
python3 - "$OUTDIR" <<'PYEOF'
import json, statistics, sys
from pathlib import Path

outdir = Path(sys.argv[1])

old_rps, new_rps = [], []
old_cpu, new_cpu = [], []

for f in sorted(outdir.glob("*.json")):
    if f.name == "meta.json" or f.name == "summary.json":
        continue
    d = json.loads(f.read_text())
    rps = d.get("results", {}).get("rps")
    cpu = d.get("results", {}).get("server_cpu_percent")
    if rps is None:
        continue
    if f.name.endswith("-old.json"):
        old_rps.append(rps)
        if cpu is not None: old_cpu.append(cpu)
    elif f.name.endswith("-new.json"):
        new_rps.append(rps)
        if cpu is not None: new_cpu.append(cpu)

def stats(name, values, unit="req/s"):
    if len(values) < 2:
        print(f"  {name}: insufficient data ({len(values)} points)")
        return {}
    med = statistics.median(values)
    q1, q3 = statistics.quantiles(values, n=4)[0], statistics.quantiles(values, n=4)[2]
    iqr = q3 - q1
    sd = statistics.stdev(values)
    print(f"  {name}:")
    print(f"    n       = {len(values)}")
    print(f"    median  = {med:,.1f} {unit}")
    print(f"    IQR     = [{q1:,.1f}, {q3:,.1f}]  (width {iqr:,.1f})")
    print(f"    stdev   = {sd:,.1f}")
    print(f"    range   = [{min(values):,.1f}, {max(values):,.1f}]")
    return {"median": med, "iqr": iqr, "stdev": sd, "n": len(values)}

print("\n── H3 Throughput (req/s) ───────────────────────")
old_s = stats("OLD (origin/main, b2)", old_rps)
new_s = stats("NEW (HEAD, 1.0.0)", new_rps)

if old_s and new_s:
    diff_pct = ((new_s["median"] - old_s["median"]) / old_s["median"]) * 100
    threshold = max(5.0, 2 * old_s["iqr"] / old_s["median"] * 100)
    print(f"\n  Comparison:")
    print(f"    OLD median = {old_s['median']:,.1f}")
    print(f"    NEW median = {new_s['median']:,.1f}")
    print(f"    Δ          = {diff_pct:+.2f}%")
    print(f"    threshold  = ±{threshold:.1f}%")
    if abs(diff_pct) < threshold:
        verdict = "NEUTRAL"
    elif diff_pct > 0:
        verdict = f"IMPROVEMENT (+{diff_pct:.1f}%)"
    else:
        verdict = f"REGRESSION ({diff_pct:.1f}%)"
    print(f"    verdict    = {verdict}")

if old_cpu and new_cpu:
    print(f"\n── Server CPU% ────────────────────────────────")
    stats("OLD", old_cpu, unit="%")
    stats("NEW", new_cpu, unit="%")

# Paired ratio analysis
if len(old_rps) == len(new_rps) and len(old_rps) >= 2:
    ratios = [n / o for n, o in zip(new_rps, old_rps)]
    med_r = statistics.median(ratios)
    q1_r, q3_r = statistics.quantiles(ratios, n=4)[0], statistics.quantiles(ratios, n=4)[2]
    print(f"\n── Paired Ratio (NEW/OLD) ─────────────────────")
    print(f"    median  = {med_r:.4f}  ({(med_r-1)*100:+.1f}%)")
    print(f"    IQR     = [{q1_r:.4f}, {q3_r:.4f}]")
    if q1_r <= 1.0 <= q3_r:
        print(f"    verdict = NEUTRAL (1.0 within IQR)")
    elif 1.0 < q1_r:
        print(f"    verdict = IMPROVEMENT (even Q1 > 1.0)")
    else:
        print(f"    verdict = REGRESSION (even Q3 < 1.0)")

summary = {"old_rps": old_rps, "new_rps": new_rps, "old_cpu": old_cpu, "new_cpu": new_cpu}
(outdir / "summary.json").write_text(json.dumps(summary, indent=2))
print(f"\nSummary written to {outdir / 'summary.json'}")
PYEOF
