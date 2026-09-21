#!/usr/bin/env bash
# perf-diag.sh — end-to-end profiling + analysis for navette.
#
# Builds the server, starts it, records perf data (CPU + i-cache),
# generates folded stacks, and runs perf-analyze.py.
#
# Usage:
#   perf-diag.sh [options]
#
# Options:
#   --body-size N     Response body size in bytes (default: 5120)
#   --duration N      Measurement duration in seconds (default: 15)
#   --warmup N        Warmup duration in seconds (default: 3)
#   --freq N          Perf sampling frequency in Hz (default: 999)
#   --scenario S      long-conn (default) or short-conn
#   --skip-build      Skip building the server binary
#   --skip-icache     Skip i-cache miss recording (faster)
#   --hot-roots F,G   Pass through to perf-analyze.py
#   --out DIR         Output directory (default: auto-generated in /tmp)
#   --analyze-only D  Skip profiling, just run analysis on existing dir
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$HERE/scripts"
SERVER_DIR="$REPO_ROOT/examples/static_h3_server"
BINARY="$SERVER_DIR/static_h3_server"
FLAMEGRAPH="$REPO_ROOT/bench/.tools/FlameGraph"
ANALYZE="$SCRIPTS/perf-analyze.py"

BODY_SIZE=5120
DURATION=15
WARMUP=3
FREQ=999
SCENARIO=long-conn
SKIP_BUILD=false
SKIP_ICACHE=false
HOT_ROOTS=""
OUT=""
ANALYZE_ONLY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --body-size)   BODY_SIZE="$2"; shift 2 ;;
        --duration)    DURATION="$2"; shift 2 ;;
        --warmup)      WARMUP="$2"; shift 2 ;;
        --freq)        FREQ="$2"; shift 2 ;;
        --scenario)    SCENARIO="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --skip-icache) SKIP_ICACHE=true; shift ;;
        --hot-roots)   HOT_ROOTS="$2"; shift 2 ;;
        --out)         OUT="$2"; shift 2 ;;
        --analyze-only) ANALYZE_ONLY="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$SCENARIO" in
    long-conn)
        MAX_REQUESTS_PER_CONN=0
        MAX_CONCURRENT_REQUESTS=10
        ;;
    short-conn)
        MAX_REQUESTS_PER_CONN=1
        MAX_CONCURRENT_REQUESTS=1
        ;;
    *) echo "unknown scenario: $SCENARIO (use long-conn or short-conn)" >&2; exit 2 ;;
esac

# ---- Analyze-only mode ----
if [[ -n "$ANALYZE_ONLY" ]]; then
    ANALYZE_ARGS=("$ANALYZE_ONLY/perf-cpu-folded.txt")
    if [[ -f "$ANALYZE_ONLY/perf-icache-folded.txt" ]]; then
        ANALYZE_ARGS+=(--icache "$ANALYZE_ONLY/perf-icache-folded.txt")
    fi
    if [[ -f "$BINARY" ]]; then
        ANALYZE_ARGS+=(--binary "$BINARY")
    fi
    if [[ -n "$HOT_ROOTS" ]]; then
        ANALYZE_ARGS+=(--hot-roots "$HOT_ROOTS")
    fi
    python3 "$ANALYZE" "${ANALYZE_ARGS[@]}"
    exit 0
fi

# ---- Preflight ----
if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf not installed" >&2; exit 1
fi
if ! docker images tquic-bench:latest --format '{{.Repository}}' | grep -q tquic-bench; then
    echo "error: tquic-bench:latest docker image not found" >&2; exit 1
fi
if [[ ! -x "$FLAMEGRAPH/stackcollapse-perf.pl" ]]; then
    echo "error: FlameGraph not vendored at $FLAMEGRAPH" >&2; exit 1
fi

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
OUT="${OUT:-/tmp/navette-diag-$(date +%Y%m%d-%H%M%S)-${GIT_SHA}}"
mkdir -p "$OUT"

echo "=== NAVETTE PERF DIAGNOSIS ==="
echo "Output:    $OUT"
echo "Binary:    $BINARY"
echo "Scenario:  $SCENARIO"
echo "Body size: $BODY_SIZE bytes"
echo "Duration:  ${DURATION}s (warmup ${WARMUP}s)"
echo "SHA:       $GIT_SHA"
echo ""

# ---- Build ----
if [[ "$SKIP_BUILD" != "true" ]]; then
    echo "[build] Building server..."
    (cd "$SERVER_DIR" && uv run mojox build 2>&1 | tail -3)
    echo ""
fi

# ---- Helpers ----
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    pkill -f "$BINARY" 2>/dev/null || true
}
trap cleanup EXIT

start_server() {
    cleanup
    sleep 1
    cd "$SERVER_DIR"
    env STATIC_BODY_SIZE="$BODY_SIZE" LD_LIBRARY_PATH=lib taskset -c 0 "$BINARY" > "$OUT/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "error: server failed to start" >&2
        cat "$OUT/server.log" >&2
        exit 1
    fi
    echo "[server] PID=$SERVER_PID"
}

run_client() {
    local dur="${1:-$DURATION}"
    docker run --rm --network host --cpuset-cpus=2-5 \
        --entrypoint /usr/local/bin/tquic_client tquic-bench:latest \
        --threads 4 \
        --max-concurrent-conns 25 \
        --max-requests-per-conn "$MAX_REQUESTS_PER_CONN" \
        --max-concurrent-requests "$MAX_CONCURRENT_REQUESTS" \
        --total-requests-per-thread 0 \
        --send-udp-payload-size 1350 \
        --duration "$dur" \
        --connect-to 127.0.0.1:8443 \
        "https://localhost:8443/static/5k.bin" 2>&1 || true
}

# ---- Phase 1: perf stat baseline ----
echo "[phase 1] perf stat baseline (${DURATION}s)..."
start_server

run_client "$WARMUP" > /dev/null 2>&1

perf stat -e instructions,cycles,L1-icache-load-misses,L1-dcache-load-misses,branch-misses \
    -p "$SERVER_PID" -- sleep "$DURATION" > "$OUT/perf-stat.txt" 2>&1 &
PERF_PID=$!

run_client "$DURATION" > "$OUT/client-stat.log" 2>&1
wait "$PERF_PID" 2>/dev/null || true

RPS=$(grep -oP '[\d.]+(?= req/s)' "$OUT/client-stat.log" | head -1)
echo "[phase 1] ${RPS:-?} rps"
cat "$OUT/perf-stat.txt"
echo ""
cleanup; sleep 2

# ---- Phase 2: perf record CPU ----
echo "[phase 2] perf record CPU (${DURATION}s at ${FREQ}Hz)..."
start_server

run_client "$WARMUP" > /dev/null 2>&1

perf record -F "$FREQ" -g --call-graph=dwarf,16384 \
    -p "$SERVER_PID" -o "$OUT/perf-cpu.data" \
    -- sleep "$DURATION" > "$OUT/perf-record-cpu.log" 2>&1 &
PERF_PID=$!

run_client "$DURATION" > "$OUT/client-cpu.log" 2>&1
wait "$PERF_PID" 2>/dev/null || true

perf script -i "$OUT/perf-cpu.data" > "$OUT/perf-cpu-script.txt" 2>/dev/null || true
"$FLAMEGRAPH/stackcollapse-perf.pl" "$OUT/perf-cpu-script.txt" > "$OUT/perf-cpu-folded.txt" 2>/dev/null
"$FLAMEGRAPH/flamegraph.pl" \
    --title "navette CPU ($GIT_SHA, $SCENARIO, ${BODY_SIZE}B body)" \
    "$OUT/perf-cpu-folded.txt" > "$OUT/cpu-flamegraph.svg" 2>/dev/null

echo "[phase 2] CPU flamegraph: $OUT/cpu-flamegraph.svg"
cleanup; sleep 2

# ---- Phase 3: perf record call counts ----
echo "[phase 3] perf record call counts (${DURATION}s, br_inst_retired.near_call)..."
start_server

run_client "$WARMUP" > /dev/null 2>&1

perf record -e br_inst_retired.near_call -c 1000 -g --call-graph=dwarf,16384 \
    -p "$SERVER_PID" -o "$OUT/perf-calls.data" \
    -- sleep "$DURATION" > "$OUT/perf-record-calls.log" 2>&1 &
PERF_PID=$!

run_client "$DURATION" > "$OUT/client-calls.log" 2>&1
wait "$PERF_PID" 2>/dev/null || true

perf script -i "$OUT/perf-calls.data" > "$OUT/perf-calls-script.txt" 2>/dev/null || true
"$FLAMEGRAPH/stackcollapse-perf.pl" "$OUT/perf-calls-script.txt" > "$OUT/perf-calls-folded.txt" 2>/dev/null

echo "[phase 3] call-count data: $OUT/perf-calls-folded.txt"
cleanup; sleep 2

# ---- Phase 4: perf record i-cache (optional) ----
if [[ "$SKIP_ICACHE" != "true" ]]; then
    echo "[phase 3] perf record i-cache misses (${DURATION}s)..."
    start_server

    run_client "$WARMUP" > /dev/null 2>&1

    perf record -e L1-icache-load-misses -c 10000 -g --call-graph=dwarf,16384 \
        -p "$SERVER_PID" -o "$OUT/perf-icache.data" \
        -- sleep "$DURATION" > "$OUT/perf-record-icache.log" 2>&1 &
    PERF_PID=$!

    run_client "$DURATION" > "$OUT/client-icache.log" 2>&1
    wait "$PERF_PID" 2>/dev/null || true

    perf script -i "$OUT/perf-icache.data" > "$OUT/perf-icache-script.txt" 2>/dev/null || true
    "$FLAMEGRAPH/stackcollapse-perf.pl" "$OUT/perf-icache-script.txt" > "$OUT/perf-icache-folded.txt" 2>/dev/null
    "$FLAMEGRAPH/flamegraph.pl" \
        --title "navette L1-icache-misses ($GIT_SHA)" \
        --colors=red \
        "$OUT/perf-icache-folded.txt" > "$OUT/icache-flamegraph.svg" 2>/dev/null

    echo "[phase 4] i-cache flamegraph: $OUT/icache-flamegraph.svg"
    cleanup; sleep 2
fi

# ---- Phase 5: Analysis ----
echo ""
echo "[phase 5] Running perf-analyze.py..."
echo ""

# Extract request count from the CPU-phase client log (requests: line, not conns:)
REQUESTS=$(grep '^requests:' "$OUT/client-cpu.log" 2>/dev/null | grep -oP 'finish \K\d+' | head -1)
if [[ -z "$REQUESTS" ]]; then
    REQUESTS=$(grep '^requests:' "$OUT/client-cpu.log" 2>/dev/null | grep -oP 'success \K\d+' | head -1)
fi

ANALYZE_ARGS=("$OUT/perf-cpu-folded.txt")
if [[ -f "$OUT/perf-icache-folded.txt" ]]; then
    ANALYZE_ARGS+=(--icache "$OUT/perf-icache-folded.txt")
fi
if [[ -f "$OUT/perf-calls-folded.txt" ]]; then
    ANALYZE_ARGS+=(--calls "$OUT/perf-calls-folded.txt")
fi
ANALYZE_ARGS+=(--binary "$BINARY")
if [[ -n "$REQUESTS" ]]; then
    ANALYZE_ARGS+=(--requests "$REQUESTS")
fi
if [[ -n "$HOT_ROOTS" ]]; then
    ANALYZE_ARGS+=(--hot-roots "$HOT_ROOTS")
fi

python3 "$ANALYZE" "${ANALYZE_ARGS[@]}"

# ---- Summary ----
echo "=== DIAGNOSIS COMPLETE ==="
echo "Output:           $OUT"
echo "CPU flamegraph:   $OUT/cpu-flamegraph.svg"
if [[ -f "$OUT/icache-flamegraph.svg" ]]; then
    echo "i-cache flamegraph: $OUT/icache-flamegraph.svg"
fi
echo "Folded stacks:    $OUT/perf-cpu-folded.txt"
echo "Re-analyze:       perf-diag.sh --analyze-only $OUT"
