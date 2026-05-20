#!/usr/bin/env bash
# Flare-methodology benchmark orchestrator for navette + competitors.
#
# Drives wrk2 in calibrated-peak mode against each baseline serving
# GET /plaintext over HTTP/1.1 keep-alive on 127.0.0.1:$PORT. Every
# target runs in its own Docker container pinned to $BENCH_SERVER_CPU;
# wrk2 runs in its own container pinned to $BENCH_CLIENT_CPU. This is
# a self-contained Docker port of Flare's `benchmark/scripts/
# bench_vs_baseline.sh` — same calibrated-peak algorithm, same gates,
# no pixi / Mojo-nightly dependency.
#
# Methodology (per Flare's docs/benchmark.md):
#   1) settle 5s at -R<settle_rps>            (warm caches, slow-start)
#   2) overdrive probe <warmup>s at -R10M     (ceiling)
#   3) 5-step binary search [30%..100%] of ceiling for highest R where
#        p99 ≤ sustain_p99_budget_ms AND achieved ≥ 90% of R AND
#        p99.9 ≤ max(p99*3, p99+2) AND p99.99 ≤ max(p99*10, p99+5) AND
#        p99 ≤ max(p99_floor*2, p99_floor+2)
#      One retry per probe on transient CLIFF / P99_GREW.
#   4) post-search validation at sustain_rps_pct% of peak, back off 8% once.
#   5) <runs> × <wrk_duration>s measurement rounds at sustain rate, with
#      <quiet_seconds> pause between.
#   6) Drop min+max rps, median of middle = headline; stdev/mean<5% gate.
#
# Usage:
#   bench_vs_baseline.sh --only=navette,nginx [--configs=throughput-1w]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINES_DIR="$ROOT/baselines"
CONFIGS_DIR="$ROOT/configs"
SCRIPTS_DIR="$ROOT/scripts"

PORT="${BENCH_PORT:-8080}"
HOST_LABEL="${BENCH_HOST_LABEL:-bench-host}"
TS="$(date -u +'%Y-%m-%dT%H%M')"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
RESULTS_BASE="${BENCH_RESULTS_DIR:-$ROOT/results}"
RESULTS_DIR="$RESULTS_BASE/${TS}-${HOST_LABEL}-${COMMIT}"
mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/RAW"

SERVER_CPU="${BENCH_SERVER_CPU:-0}"
CLIENT_CPU="${BENCH_CLIENT_CPU:-2}"     # leave CPU 1 idle as a quiet buffer
WRK2_IMG="${WRK2_IMG:-flare-cmp-wrk2:latest}"

ONLY_TARGETS=""
ONLY_CONFIGS="throughput-1w"
for arg in "$@"; do
    case "$arg" in
        --only=*)    ONLY_TARGETS="${arg#--only=}" ;;
        --configs=*) ONLY_CONFIGS="${arg#--configs=}" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

matches() {
    local cand="$1" list="$2"
    [[ -z "$list" ]] && return 0
    IFS=',' read -ra arr <<< "$list"
    for e in "${arr[@]}"; do [[ "$e" == "$cand" ]] && return 0; done
    return 1
}

# ── Environment snapshot ──────────────────────────────────────────────────────
echo "→ Collecting environment..."
BENCH_TS="$TS" BENCH_REPO_ROOT="$ROOT" \
    BENCH_HOST_LABEL="$HOST_LABEL" \
    BENCH_SERVER_CPU="$SERVER_CPU" BENCH_CLIENT_CPU="$CLIENT_CPU" \
    bash "$SCRIPTS_DIR/_collect_env.sh" > "$RESULTS_DIR/env.json"

# ── Discover targets ──────────────────────────────────────────────────────────
declare -a ALL_TARGETS
for d in "$BASELINES_DIR"/*/; do
    name="$(basename "$d")"
    [[ "$name" == "_common" || "$name" == "wrk2" ]] && continue
    [[ -f "$d/run.sh" ]] || continue
    ALL_TARGETS+=("$name")
done
declare -a TARGETS
for t in "${ALL_TARGETS[@]}"; do
    matches "$t" "$ONLY_TARGETS" && TARGETS+=("$t")
done
[[ ${#TARGETS[@]} -eq 0 ]] && { echo "no targets matched --only=$ONLY_TARGETS" >&2; exit 2; }
echo "→ Targets: ${TARGETS[*]}"

# ── Integrity gate ────────────────────────────────────────────────────────────
echo "→ Running integrity check..."
BENCH_PORT="$PORT" bash "$SCRIPTS_DIR/_integrity_check.sh" "${TARGETS[@]}" \
    | tee "$RESULTS_DIR/integrity.md"
INTEGRITY_RC=${PIPESTATUS[0]}
[[ $INTEGRITY_RC -ne 0 ]] && { echo "→ Integrity check FAILED; aborting." >&2; exit 3; }

# ── wrk2 wrapper ──────────────────────────────────────────────────────────────
# Runs wrk2 in a pinned container against host loopback. Pins to
# $CLIENT_CPU so it doesn't share a core with the server.
run_wrk2() {
    local out="$1"; shift
    docker run --rm --network host --cpuset-cpus="$CLIENT_CPU" \
        "$WRK2_IMG" "$@" > "$out" 2>&1 || true
}

# Parse percentile block out of one wrk2 stdout. Prints
# "p50_ms p99_ms p99_9_ms p99_99_ms".
parse_pct() {
    python3 - "$1" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p, errors="replace").read()
re_pct = re.compile(r"^\s*([0-9]+\.[0-9]+)%\s+([0-9.]+)(us|ms|s|m)\s*$", re.M)
want = {"50.000": "p50", "99.000": "p99", "99.900": "p99_9", "99.990": "p99_99"}
got = {}
in_dist = False
for line in text.splitlines():
    if "Latency Distribution" in line:
        in_dist = True; continue
    if not in_dist: continue
    s = line.strip()
    if not s or s.startswith("Detailed"): in_dist = False; continue
    m = re_pct.match("  " + s)
    if not m: continue
    pct, v, u = m.group(1), float(m.group(2)), m.group(3)
    if pct not in want: continue
    ms = v/1000 if u == "us" else v if u == "ms" else v*1000 if u == "s" else v*60000
    got[want[pct]] = ms
print(f"{got.get('p50', 0):.3f} {got.get('p99', 99999):.3f} {got.get('p99_9', 99999):.3f} {got.get('p99_99', 99999):.3f}")
PY
}

# ── Main sweep ────────────────────────────────────────────────────────────────
declare -a SUMMARY_ROWS

for target in "${TARGETS[@]}"; do
    target_dir="$BASELINES_DIR/$target"
    run_sh="$target_dir/run.sh"
    check_sh="$ROOT/baselines/_common/check.sh"
    [[ -f "$run_sh" ]] || { echo "$target: no run.sh, skipping" >&2; continue; }

    for config_file in "$CONFIGS_DIR"/*.yaml; do
        config="$(basename "$config_file" .yaml)"
        matches "$config" "$ONLY_CONFIGS" || continue

        WRK_THREADS=$(awk '/^wrk_threads:/         {print $2}' "$config_file")
        WRK_CONNS=$(awk   '/^wrk_connections:/     {print $2}' "$config_file")
        WRK_DURATION=$(awk '/^wrk_duration_seconds:/ {print $2}' "$config_file")
        WARMUP=$(awk      '/^warmup_seconds:/      {print $2}' "$config_file")
        RUNS=$(awk        '/^runs:/                {print $2}' "$config_file")
        QUIET=$(awk       '/^quiet_seconds:/       {print $2}' "$config_file")
        SETTLE_RPS=$(awk  '/^settle_rps:/          {print $2}' "$config_file")
        P99_BUDGET_MS=$(awk '/^sustain_p99_budget_ms:/ {print $2}' "$config_file")
        SUSTAIN_PCT=$(awk '/^sustain_rps_pct:/     {print $2}' "$config_file")
        PROBE_DURATION_SEC="${BENCH_PROBE_SEC:-20}"

        URL="http://127.0.0.1:${PORT}/plaintext"
        echo ""
        echo "─── $target / $config ───"

        # Bring up server.
        bash "$SCRIPTS_DIR/_kill_baseline.sh" "$target" >/dev/null 2>&1 || true
        BENCH_PORT="$PORT" BENCH_SERVER_CPU="$SERVER_CPU" \
            BENCH_CONTAINER_NAME="flare-cmp-${target}" \
            bash "$run_sh" \
                >"$RESULTS_DIR/RAW/$target-$config.server.stdout" \
                2>"$RESULTS_DIR/RAW/$target-$config.server.stderr" &
        RUNNER_PID=$!
        if ! BENCH_PORT="$PORT" bash "$check_sh" >/dev/null 2>&1; then
            echo "[$target] check.sh FAILED — skipping"
            bash "$SCRIPTS_DIR/_kill_baseline.sh" "$target" >/dev/null 2>&1 || true
            kill -9 "$RUNNER_PID" 2>/dev/null || true
            SUMMARY_ROWS+=("$target|$config|DOWN|-|-|-|-|-|-|-|-|-|false")
            continue
        fi

        # 1) Settle.
        echo "  settle 5s @ -R${SETTLE_RPS} …"
        run_wrk2 "$RESULTS_DIR/RAW/$target-$config-settle.txt" \
            -t"$WRK_THREADS" -c"$WRK_CONNS" -d5s -R"$SETTLE_RPS" --latency "$URL"

        # 2) Overdrive ceiling.
        echo "  overdrive probe ${WARMUP}s …"
        peak_raw="$RESULTS_DIR/RAW/$target-$config-peakfind.txt"
        run_wrk2 "$peak_raw" \
            -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WARMUP}s" -R10000000 --latency "$URL"
        OVERDRIVE_RPS=$(awk '/^Requests\/sec:/ {print $2}' "$peak_raw")
        if [[ -z "$OVERDRIVE_RPS" || "$(printf '%.0f' "$OVERDRIVE_RPS")" -le 0 ]]; then
            echo "  peak-find FAILED — server unresponsive"
            bash "$SCRIPTS_DIR/_kill_baseline.sh" "$target" >/dev/null 2>&1 || true
            kill -9 "$RUNNER_PID" 2>/dev/null || true
            SUMMARY_ROWS+=("$target|$config|DOWN|-|-|-|-|-|-|-|-|-|false")
            continue
        fi
        echo "  overdrive=$(printf '%.0f' "$OVERDRIVE_RPS") req/s"

        # 3) Binary-search the latency-bounded peak.
        LO=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 0.30))")
        HI=$(python3 -c "print(int(float('$OVERDRIVE_RPS') * 1.00))")
        SUSTAINABLE_RPS=$LO
        P99_FLOOR=999.0

        run_probe() {
            local rate="$1" raw="$2"
            run_wrk2 "$raw" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                -d"${PROBE_DURATION_SEC}s" -R"$rate" --latency "$URL"
            read -r P50_MS P99_MS P99_9_MS P99_99_MS <<< "$(parse_pct "$raw")"
            local ach
            ach=$(awk '/^Requests\/sec:/ {print $2}' "$raw")
            ACHIEVED_INT=$(python3 -c "print(int(float('$ach' or '0')))")
        }
        evaluate_probe() {
            local mid="$1"
            MIN_ACHIEVED=$(python3 -c "print(int($mid * 0.90))")
            verdict="OK"
            P99_OK=$(python3 -c "print(1 if float('$P99_MS') <= $P99_BUDGET_MS else 0)")
            ACH_OK=$(python3 -c "print(1 if $ACHIEVED_INT >= $MIN_ACHIEVED else 0)")
            CLIFF_OK=$(python3 -c "
p99=float('$P99_MS'); p99_9=float('$P99_9_MS'); p99_99=float('$P99_99_MS')
print(1 if (p99_9 <= max(p99*3.0, p99+2.0) and p99_99 <= max(p99*10.0, p99+5.0)) else 0)
")
            P99_GROWTH_OK=$(python3 -c "
floor=float('$P99_FLOOR'); p99=float('$P99_MS')
print(1 if p99 <= max(floor*2.0, floor+2.0) else 0)
")
            if [ "$P99_OK" = "1" ] && [ "$ACH_OK" = "1" ] && [ "$CLIFF_OK" = "1" ] && [ "$P99_GROWTH_OK" = "1" ]; then
                verdict=OK
            elif [ "$P99_GROWTH_OK" = "0" ]; then verdict=P99_GREW
            elif [ "$CLIFF_OK"      = "0" ]; then verdict=CLIFF
            elif [ "$P99_OK"        = "0" ]; then verdict=P99_HIGH
            else                                   verdict=UNDER_RATE
            fi
        }

        for step in 1 2 3 4 5; do
            MID=$(python3 -c "print(int(($LO + $HI) / 2))")
            cal_raw="$RESULTS_DIR/RAW/$target-$config-cal-${MID}.txt"
            run_probe "$MID" "$cal_raw"
            P99_FLOOR=$(python3 -c "print(min(float('$P99_FLOOR'), float('$P99_MS')))")
            evaluate_probe "$MID"
            if [[ "$verdict" == "CLIFF" || "$verdict" == "P99_GREW" ]]; then
                retry_raw="$RESULTS_DIR/RAW/$target-$config-cal-${MID}-retry.txt"
                echo "    retry @ R=${MID}: rejected on ${verdict}, re-probing once"
                run_probe "$MID" "$retry_raw"
                P99_FLOOR=$(python3 -c "print(min(float('$P99_FLOOR'), float('$P99_MS')))")
                evaluate_probe "$MID"
            fi
            if [ "$verdict" = "OK" ]; then
                SUSTAINABLE_RPS=$MID
                LO=$MID
            else
                HI=$MID
            fi
            echo "    probe @ R=${MID}: ach=${ACHIEVED_INT} p99=${P99_MS}ms p99.9=${P99_9_MS}ms p99.99=${P99_99_MS}ms (floor=${P99_FLOOR}ms) → ${verdict}"
        done
        PEAK_RPS=$SUSTAINABLE_RPS
        SUSTAIN_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * $SUSTAIN_PCT / 100))")

        # 4) Post-search validation, one back-off.
        for attempt in 1 2; do
            val_raw="$RESULTS_DIR/RAW/$target-$config-val-${SUSTAIN_RPS}.txt"
            echo "  validate @ R=${SUSTAIN_RPS} (${PROBE_DURATION_SEC}s) …"
            run_wrk2 "$val_raw" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                -d"${PROBE_DURATION_SEC}s" -R"$SUSTAIN_RPS" --latency "$URL"
            read -r VP50 VP99 VP99_9 VP99_99 <<< "$(parse_pct "$val_raw")"
            V_OK=$(python3 -c "
p99=float('$VP99'); p99_9=float('$VP99_9'); p99_99=float('$VP99_99')
ok = (p99 <= float('$P99_BUDGET_MS')
      and p99_9  <= max(p99*3.0,  p99+2.0)
      and p99_99 <= max(p99*10.0, p99+5.0))
print(1 if ok else 0)
")
            if [ "$V_OK" = "1" ]; then
                echo "    validation OK: p99=${VP99}ms p99.9=${VP99_9}ms p99.99=${VP99_99}ms"
                break
            fi
            echo "    validation FAILED: p99=${VP99}ms p99.9=${VP99_9}ms p99.99=${VP99_99}ms"
            if [ "$attempt" = "1" ]; then
                PEAK_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * 0.92))")
                SUSTAIN_RPS=$(python3 -c "print(int(float('$PEAK_RPS') * $SUSTAIN_PCT / 100))")
                echo "    backing off to peak=${PEAK_RPS} sustain=${SUSTAIN_RPS}"
            fi
        done
        echo "  sustainable peak=$(printf '%.0f' "$PEAK_RPS") req/s; sustaining ${SUSTAIN_PCT}% = ${SUSTAIN_RPS}"

        # 5) Measurement rounds.
        for run in $(seq 1 "$RUNS"); do
            sleep "$QUIET"
            raw="$RESULTS_DIR/RAW/$target-$config-run${run}.txt"
            echo "  run $run/${RUNS} ${WRK_DURATION}s @ -R${SUSTAIN_RPS} …"
            run_wrk2 "$raw" -t"$WRK_THREADS" -c"$WRK_CONNS" \
                -d"${WRK_DURATION}s" -R"$SUSTAIN_RPS" --latency "$URL"
        done

        # 6) Aggregate.
        RUN_FILES=()
        for run in $(seq 1 "$RUNS"); do
            RUN_FILES+=("$RESULTS_DIR/RAW/$target-$config-run${run}.txt")
        done
        stats_json="$RESULTS_DIR/$target-$config.json"
        python3 "$SCRIPTS_DIR/_stat.py" --peak-rps "$PEAK_RPS" \
            "$stats_json" "${RUN_FILES[@]}"

        med=$(python3   -c "import json; d=json.load(open('$stats_json')); print(int(d['summary']['median_req_per_sec']))")
        stv=$(python3   -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['stdev_pct']:.2f}\")")
        p50=$(python3   -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p50_ms']:.2f}\")")
        p99=$(python3   -c "import json; d=json.load(open('$stats_json')); print(f\"{d['summary']['median_p99_ms']:.2f}\")")
        p99_9=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_9_ms', 0.0); print(f\"{v:.2f}\")")
        p99_99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('median_p99_99_ms', 0.0); print(f\"{v:.2f}\")")
        sp50=$(python3   -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p50_ms', 0.0); print(f\"{v:.2f}\")")
        sp99=$(python3   -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_ms', 0.0); print(f\"{v:.2f}\")")
        sp99_9=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_9_ms', 0.0); print(f\"{v:.2f}\")")
        sp99_99=$(python3 -c "import json; d=json.load(open('$stats_json')); v=d['summary'].get('stdev_p99_99_ms', 0.0); print(f\"{v:.2f}\")")
        stable=$(python3 -c "import json; d=json.load(open('$stats_json')); print(str(d['summary']['stable']).lower())")
        SUMMARY_ROWS+=("$target|$config|$med|$stv|$p50|$sp50|$p99|$sp99|$p99_9|$sp99_9|$p99_99|$sp99_99|$stable")

        bash "$SCRIPTS_DIR/_kill_baseline.sh" "$target" >/dev/null 2>&1 || true
        kill -9 "$RUNNER_PID" 2>/dev/null || true
    done
done

# ── Emit summary.md ───────────────────────────────────────────────────────────
# Inlines a minimal run-conditions block at the top of every summary so
# the headline is interpretable without env.json — overall shape only,
# no host identity or co-resident processes.
{
    echo "# Flare-methodology benchmark — navette vs competitors"
    echo ""
    echo "- Run: ${TS}-${HOST_LABEL}-${COMMIT}"
    echo "- Methodology: wrk2 calibrated-peak (Flare docs/benchmark.md)."
    echo "- Endpoint: GET /plaintext → 13B \"Hello, World!\", HTTP/1.1 keep-alive."
    echo "- Percentile cells: median ± σ over 5 measurement rounds (ms)."
    echo ""
    echo "## Run conditions"
    echo ""
    python3 - "$RESULTS_DIR/env.json" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
pin = env.get("pinning", {})
digests = env.get("baseline_image_digests", {})

print(f"- CPU class: {env.get('cpu_model','?')} ({env.get('logical_cores',0)} logical)")
print(f"- Memory: {env.get('memory_gb',0)} GB")
print(f"- Loadavg at bench-start (1-min): {env.get('loadavg_1min','?')}")
print(f"- Pinning: server → CPU `{pin.get('server_cpu','?')}`, wrk2 → CPU `{pin.get('client_cpu','?')}`")
print(f"- Commit: `{env.get('commit','?')}` · Docker `{env.get('docker_version','?')}`")
print("")
print("Image digests (short) for the binaries that produced these numbers:")
print("")
print("```")
for t, d in digests.items():
    short = d.split(":")[-1][:12] if ":" in d else d[:12]
    print(f"  {t:<12} {short}")
print("```")
PY
    echo ""
    echo "## Results"
    echo ""
    echo "| Target | Config | Req/s (median) | σ% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |"
    echo "|---|---|---:|---:|---:|---:|---:|---:|---|"
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS='|' read -r t c m s p50 sp50 p99 sp99 p999 sp999 p9999 sp9999 stab <<< "$row"
        printf "| %s | %s | %s | %s | %s ± %s | %s ± %s | %s ± %s | %s ± %s | %s |\n" \
            "$t" "$c" "$m" "$s" \
            "$p50" "$sp50" "$p99" "$sp99" "$p999" "$sp999" "$p9999" "$sp9999" "$stab"
    done
} > "$RESULTS_DIR/summary.md"

echo ""
echo "══ Benchmark complete ══"
echo "Results: $RESULTS_DIR"
echo ""
cat "$RESULTS_DIR/summary.md"
