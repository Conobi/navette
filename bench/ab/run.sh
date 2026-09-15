#!/usr/bin/env bash
# bench/ab/run.sh — Interleaved A/B regression benchmark
#
# Runs h2load against navette-bench:old and navette-bench:new in
# alternating order with pauses, then reports per-image statistics.
#
# Usage:
#   bash bench/ab/run.sh              # 10 iterations, default params
#   ITERS=5 bash bench/ab/run.sh      # fewer iterations for a smoke run
#
# Env:
#   ITERS        — iterations per image (default: 10)
#   PAUSE        — seconds between runs (default: 30)
#   N            — h2load total requests (default: 200000)
#   C            — h2load connections (default: 50)
#   M            — h2load max concurrent streams (default: 16)
#   WARMUP_REQS  — warmup requests before measurement (default: 5000)
#   ENDPOINT     — URL path (default: /baseline2?a=1&b=2)
#   PROTOCOL     — h2 or h1 (default: h2)
#   H1_DURATION  — wrk duration for h1 mode (default: 8s)
#   H1_THREADS   — wrk threads for h1 mode (default: 4)
#   H1_CONNS     — wrk connections for h1 mode (default: 200)
#   OUTDIR       — results directory (default: bench/ab/results/<timestamp>)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

ITERS="${ITERS:-10}"
PAUSE="${PAUSE:-30}"
N="${N:-200000}"
C="${C:-50}"
M="${M:-16}"
WARMUP_REQS="${WARMUP_REQS:-5000}"
ENDPOINT="${ENDPOINT:-/baseline2?a=1&b=2}"
PROTOCOL="${PROTOCOL:-h2}"
H1_DURATION="${H1_DURATION:-8s}"
H1_THREADS="${H1_THREADS:-4}"
H1_CONNS="${H1_CONNS:-200}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="${OUTDIR:-$SCRIPT_DIR/results/$TIMESTAMP}"
mkdir -p "$OUTDIR"

OLD_TAG="navette-bench:old"
NEW_TAG="navette-bench:new"

DOCKER_FLAGS=(
    -d --rm --network host
    --security-opt seccomp=unconfined
    --ulimit memlock=-1:-1
    --ulimit nofile=1048576:1048576
)

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

log() { echo "[$(date +%H:%M:%S)] $*"; }

check_host() {
    log "Host state:"
    echo "  loadavg: $(cat /proc/loadavg)"
    echo "  top CPU:"
    ps --sort=-pcpu -eo pid,pcpu,comm | head -6 | tail -5 | sed 's/^/    /'
    local mojo_procs
    mojo_procs=$(pgrep -c -f 'mojo' 2>/dev/null || echo 0)
    if [ "$mojo_procs" -gt 0 ]; then
        echo "  WARNING: $mojo_procs mojo process(es) running — results may be noisy"
    fi
}

wait_for_server() {
    local proto="$1" tries=30
    if [ "$proto" = "h2" ]; then
        while ! docker run --rm --network host h2load:latest -n 10 -c 1 -m 1 \
            "https://127.0.0.1:8443$ENDPOINT" 2>&1 | grep -q "10 succeeded"; do
            tries=$((tries - 1))
            [ $tries -le 0 ] && return 1
            sleep 1
        done
    else
        while ! curl -sf "http://127.0.0.1:8080$ENDPOINT" >/dev/null 2>&1; do
            tries=$((tries - 1))
            [ $tries -le 0 ] && return 1
            sleep 1
        done
    fi
    return 0
}

run_single() {
    local label="$1" image="$2" iter="$3" outfile="$4"
    local container="bench-ab-$label"

    docker rm -f "$container" >/dev/null 2>&1 || true
    docker run --name "$container" "${DOCKER_FLAGS[@]}" "$image" >/dev/null 2>&1

    if ! wait_for_server "$PROTOCOL"; then
        log "[$label] FAIL: server didn't accept requests within 30s"
        docker rm -f "$container" >/dev/null 2>&1 || true
        echo "FAIL" >> "$outfile"
        return 1
    fi

    if [ "$PROTOCOL" = "h2" ]; then
        # Warmup
        docker run --rm --network host h2load:latest \
            -n "$WARMUP_REQS" -c "$C" -m "$M" \
            "https://127.0.0.1:8443$ENDPOINT" >/dev/null 2>&1 || true

        # Measurement
        docker run --rm --network host h2load:latest \
            -n "$N" -c "$C" -m "$M" \
            "https://127.0.0.1:8443$ENDPOINT" 2>&1 | tee -a "$outfile"
    else
        # Warmup (2s wrk)
        docker run --rm --network host wrk:latest \
            -t "$H1_THREADS" -c "$H1_CONNS" -d 2s \
            "http://127.0.0.1:8080$ENDPOINT" >/dev/null 2>&1 || true

        # Measurement
        docker run --rm --network host wrk:latest \
            -t "$H1_THREADS" -c "$H1_CONNS" -d "$H1_DURATION" \
            "http://127.0.0.1:8080$ENDPOINT" 2>&1 | tee -a "$outfile"
    fi

    docker rm -f "$container" >/dev/null 2>&1 || true
    return 0
}

# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

log "A/B Regression Benchmark"
log "  OLD: $OLD_TAG"
log "  NEW: $NEW_TAG"
log "  Protocol: $PROTOCOL"
log "  Iterations: $ITERS"
log "  Pause: ${PAUSE}s"
log "  Output: $OUTDIR"
if [ "$PROTOCOL" = "h2" ]; then
    log "  h2load: -n $N -c $C -m $M  endpoint=$ENDPOINT"
else
    log "  wrk: -t $H1_THREADS -c $H1_CONNS -d $H1_DURATION  endpoint=$ENDPOINT"
fi
echo ""

# Verify images exist
for img in "$OLD_TAG" "$NEW_TAG"; do
    if ! docker image inspect "$img" >/dev/null 2>&1; then
        echo "error: image $img not found. Run bench/ab/build.sh first."
        exit 1
    fi
done

# Verify load generator exists
if [ "$PROTOCOL" = "h2" ]; then
    if ! docker image inspect h2load:latest >/dev/null 2>&1; then
        echo "error: h2load:latest not found. Run bench/compare/build-comparators.sh first."
        exit 1
    fi
fi

OLD_RAW="$OUTDIR/raw-old.txt"
NEW_RAW="$OUTDIR/raw-new.txt"
: > "$OLD_RAW"
: > "$NEW_RAW"

# Save run metadata
cat > "$OUTDIR/meta.json" <<EOF
{
  "timestamp": "$TIMESTAMP",
  "protocol": "$PROTOCOL",
  "iterations": $ITERS,
  "pause_seconds": $PAUSE,
  "h2_params": {"n": $N, "c": $C, "m": $M, "warmup": $WARMUP_REQS},
  "endpoint": "$ENDPOINT",
  "old_image": "$OLD_TAG",
  "new_image": "$NEW_TAG",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "cpu": "$(lscpu | grep 'Model name' | sed 's/.*: *//')"
}
EOF

check_host
echo ""

for i in $(seq 1 "$ITERS"); do
    log "=== Iteration $i/$ITERS ==="

    # Alternate start order each iteration to cancel ordering effects
    if [ $((i % 2)) -eq 1 ]; then
        first="old"; second="new"
    else
        first="new"; second="old"
    fi

    for variant in "$first" "$second"; do
        if [ "$variant" = "old" ]; then
            tag="$OLD_TAG"; raw="$OLD_RAW"; label="OLD"
        else
            tag="$NEW_TAG"; raw="$NEW_RAW"; label="NEW"
        fi

        check_host
        log "  Running $label..."
        echo "--- iter $i ---" >> "$raw"
        run_single "$variant" "$tag" "$i" "$raw"
        log "  $label done. Pausing ${PAUSE}s..."
        sleep "$PAUSE"
    done
done

log "All iterations complete. Raw output in $OUTDIR/"
log "Run: python3 bench/ab/report.py $OUTDIR"
