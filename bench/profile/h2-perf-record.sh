#!/usr/bin/env bash
# h2-perf-record.sh — Phase 0 perf-record + flamegraph tier.
#
# Runs the *host-built* mojo-net h2_server (single process, no
# launcher) under perf record while h2load drives a fixed-duration
# load. Emits perf.data + perf-folded.txt + perf.svg flamegraph to a
# timestamped run dir under bench/profile/runs/.
#
# Why host-build instead of Docker:
#  - mojo-net's host binary is unstripped ELF, so perf resolves
#    symbols (H2Connection.send_data, drain_ciphertext, ...) cleanly
#    without --symfs gymnastics.
#  - Single-worker by construction (we run h2_server directly, no
#    SO_REUSEPORT scaling). Multi-worker is for throughput, not
#    attribution.
#  - h2load still runs in Docker — it's just the load gen, doesn't
#    need symbols.
#
# Knobs (env):
#   DURATION    h2load -D seconds (default 30)
#   PERF_DUR    perf record sleep seconds; ends earlier than h2load
#               so we don't sample teardown (default DURATION-5)
#   C           h2load -c (default 50)
#   M           h2load -m (default 16)
#   ENDPOINT    target path (default /baseline2?a=1&b=2)
#   PERF_FREQ   perf -F sampling Hz (default 99)
#   OUT         run dir (default bench/profile/runs/<ts>-<sha>/)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARENA="$REPO_ROOT/bench/.httparena"
CERTS_DIR="$ARENA/certs"
DATA_DIR="$ARENA/data"
H2_BIN="$REPO_ROOT/bench/h2_server"
FLAMEGRAPH="$REPO_ROOT/bench/.tools/FlameGraph"

DURATION="${DURATION:-30}"
PERF_DUR="${PERF_DUR:-$((DURATION - 5))}"
C="${C:-50}"
M="${M:-16}"
ENDPOINT="${ENDPOINT:-/baseline2?a=1&b=2}"
PERF_FREQ="${PERF_FREQ:-99}"

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$REPO_ROOT/bench/profile/runs/$TS-$GIT_SHA}"

# Preflight.
if [ ! -x "$H2_BIN" ]; then
    echo "error: $H2_BIN not built. Run 'pixi run build-bench' (or your build cmd) first." >&2
    exit 1
fi
if [ ! -x "$FLAMEGRAPH/flamegraph.pl" ] || [ ! -x "$FLAMEGRAPH/stackcollapse-perf.pl" ]; then
    echo "error: FlameGraph not vendored. See bench/profile/README.md." >&2
    exit 1
fi
if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf not installed." >&2
    exit 1
fi
PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 99)"
if [ "$PARANOID" -gt 2 ] 2>/dev/null; then
    echo "warning: kernel.perf_event_paranoid=$PARANOID; user-space profiling may fail" >&2
fi
if pgrep -x h2_server >/dev/null 2>&1; then
    echo "error: another h2_server is already running. Stop it first." >&2
    exit 1
fi

mkdir -p "$OUT"
echo "[perf-record] out=$OUT"
echo "[perf-record] sha=$GIT_SHA endpoint=$ENDPOINT c=$C m=$M dur=${DURATION}s perf_dur=${PERF_DUR}s freq=${PERF_FREQ}Hz"

# Boot h2_server on host.
export CERTS_DIR
export STATIC_DIR="$DATA_DIR/static"
export DATA_DIR
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$REPO_ROOT/bench/.httparena/build/lib:/usr/local/lib"
"$H2_BIN" >"$OUT/h2_server.log" 2>&1 &
H2_PID=$!
trap '[ -n "${H2_PID:-}" ] && kill "$H2_PID" 2>/dev/null || true; wait "$H2_PID" 2>/dev/null || true' EXIT

# Wait until the listener is up.
echo "[perf-record] waiting for h2 :8443..."
tries=20
while ! docker run --rm --network host h2load:latest \
    -n 4 -c 1 -m 1 "https://127.0.0.1:8443${ENDPOINT}" 2>&1 | grep -q "4 succeeded"; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
        echo "error: h2_server didn't accept requests in 20s" >&2
        cat "$OUT/h2_server.log" >&2 || true
        exit 1
    fi
    sleep 1
done
echo "[perf-record] h2_server pid=$H2_PID listening"

# Drive load (background) and record (foreground for clean wait).
docker run --rm --network host h2load:latest \
    -D "$DURATION" -c "$C" -m "$M" \
    "https://127.0.0.1:8443${ENDPOINT}" \
    >"$OUT/h2load.log" 2>&1 &
LOAD_PID=$!

sleep 2  # let load ramp up before sampling
echo "[perf-record] sampling for ${PERF_DUR}s..."
perf record -F "$PERF_FREQ" -g --call-graph=dwarf \
    -p "$H2_PID" -o "$OUT/perf.data" \
    -- sleep "$PERF_DUR" 2>&1 | tail -5

wait "$LOAD_PID" 2>/dev/null || true

# Stop server cleanly so the trap doesn't have to.
kill "$H2_PID" 2>/dev/null || true
wait "$H2_PID" 2>/dev/null || true
H2_PID=""  # disarm trap

# Convert to folded stacks and flamegraph.
echo "[perf-record] generating flamegraph..."
perf script -i "$OUT/perf.data" >"$OUT/perf-script.txt" 2>"$OUT/perf-script.err"
"$FLAMEGRAPH/stackcollapse-perf.pl" "$OUT/perf-script.txt" >"$OUT/perf-folded.txt"
"$FLAMEGRAPH/flamegraph.pl" --title "mojo-net h2 ${ENDPOINT} (${GIT_SHA})" \
    "$OUT/perf-folded.txt" >"$OUT/perf.svg"

echo
echo "[perf-record] done."
echo "  perf.data       $(stat -c%s "$OUT/perf.data" 2>/dev/null || echo 0) bytes"
echo "  perf-folded.txt $(wc -l <"$OUT/perf-folded.txt" 2>/dev/null || echo 0) unique stacks"
echo "  perf.svg        open in a browser"
echo "  h2load.log      $(grep -E 'finished in|status codes:' "$OUT/h2load.log" 2>/dev/null || echo '(see file)')"
