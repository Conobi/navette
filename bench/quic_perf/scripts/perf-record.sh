#!/usr/bin/env bash
# perf-record.sh — capture a CPU flamegraph during a single short-conn iter.
#
# Mirrors bench/profile/h2-perf-record.sh:107-109 (the H2 host-build harness)
# but attaches perf to the *containerized* bench-h3 worker PID instead of a
# host binary. PID is resolved via resolve-server-pid.sh, which returns the
# host-visible PID of the container init — and since start-server.sh:42
# uses `--entrypoint /usr/local/bin/h3_server`, the init *is* the worker.
#
# Reuses the existing bench scripts (start-server.sh, run-tquic-client.sh,
# stop-server.sh) so the load shape matches `bench.sh` exactly minus the
# CPU-sampler / parser steps (which we don't need for a flamegraph).
#
# Knobs (env):
#   PAYLOAD     1k|5k|15k|2m       (default 1k)
#   SCENARIO    short-conn|long-conn (default short-conn)
#   PERF_FREQ   perf -F sampling Hz (default 99)
#   PERF_DUR    perf record sleep seconds; ends inside the 30s window so
#               we don't sample teardown (default 25)
#   WARMUP_S    warmup duration before sampling (default 5; matches bench.sh)
#   DURATION_S  total measurement duration (default 30; matches bench.sh)
#   OUT         override output dir (default
#               bench/quic_perf/results/profile/shortconn-<ts>-<sha>)
#
# Per spec §6, deliverables in $OUT:
#   perf.data         raw samples
#   perf-script.txt   `perf script` output (folded source)
#   perf-folded.txt   stackcollapse-perf.pl output
#   perf.svg          flamegraph (the deliverable)
#   client.log        tquic_client stdout/stderr
#   meta.txt          one-line provenance (sha, freq, dur, paranoid)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
FLAMEGRAPH="$REPO_ROOT/bench/.tools/FlameGraph"

PAYLOAD="${PAYLOAD:-1k}"
SCENARIO="${SCENARIO:-short-conn}"
PERF_FREQ="${PERF_FREQ:-99}"
DURATION_S="${DURATION_S:-30}"
WARMUP_S="${WARMUP_S:-5}"
PERF_DUR="${PERF_DUR:-25}"   # 30s measurement - 5s lead-in (mirrors h2 harness DURATION-5)

# Preflight.
if ! command -v perf >/dev/null 2>&1; then
    echo "error: perf not installed" >&2
    exit 1
fi
if [ ! -x "$FLAMEGRAPH/flamegraph.pl" ] || [ ! -x "$FLAMEGRAPH/stackcollapse-perf.pl" ]; then
    echo "error: FlameGraph not vendored at $FLAMEGRAPH" >&2
    exit 1
fi
PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 99)"
if [ "$PARANOID" -gt 2 ] 2>/dev/null; then
    echo "warning: kernel.perf_event_paranoid=$PARANOID; user-space profiling may fail" >&2
fi

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$HERE/results/profile/shortconn-${TS}-${GIT_SHA}}"
mkdir -p "$OUT"

echo "[perf-record] sha=$GIT_SHA payload=$PAYLOAD scenario=$SCENARIO out=$OUT"
echo "[perf-record] warmup=${WARMUP_S}s duration=${DURATION_S}s perf_dur=${PERF_DUR}s freq=${PERF_FREQ}Hz paranoid=$PARANOID"

# Ensure payloads exist (gen-payloads.sh is idempotent).
"$HERE/scripts/gen-payloads.sh" >/dev/null

# Boot bench-h3 with --user $(id -u):$(id -g) so the container process
# is owned by the host invoker. At kernel.perf_event_paranoid=2
# perf cannot attach to a process owned by another UID without CAP_PERFMON;
# UID-matching is the simplest fix that doesn't require sudo or container
# capability changes (alternative is --cap-add=SYS_ADMIN per spec §4).
# We bypass start-server.sh because it hardcodes root.
MOJO_NET_IMAGE="${MOJO_NET_IMAGE:-mojo-net-bench:latest}"
"$HERE/scripts/stop-server.sh" >/dev/null 2>&1 || true
docker run -d --name bench-h3 \
    --network host \
    --security-opt seccomp=unconfined \
    --ulimit nofile=65536:65536 \
    --cpuset-cpus=0 \
    --user "$(id -u):$(id -g)" \
    -v "$HERE/payloads:/data/static:ro" \
    -v "$REPO_ROOT/certs:/certs:ro" \
    -v "$REPO_ROOT/bench/quic_perf/results/profile:/app/bench/quic_perf/results/profile" \
    --entrypoint /usr/local/bin/h3_server \
    "$MOJO_NET_IMAGE" --workers 1 \
    >/tmp/perf-record-start.log

# Wait for readiness.
if ! "$HERE/scripts/wait-ready.sh"; then
    echo "error: bench-h3 failed to become ready" >&2
    docker logs bench-h3 2>&1 | tail -20
    "$HERE/scripts/stop-server.sh" >/dev/null 2>&1 || true
    exit 1
fi

PID="$("$HERE/scripts/resolve-server-pid.sh" bench-h3)"
if [ -z "$PID" ] || [ "$PID" = "0" ]; then
    echo "error: failed to resolve bench-h3 PID" >&2
    "$HERE/scripts/stop-server.sh" >/dev/null || true
    exit 1
fi
echo "[perf-record] bench-h3 host pid=$PID owner=$(stat -c %U /proc/$PID 2>/dev/null || echo unknown)"

# Trap cleanup so we don't leave bench-h3 running on failure.
trap '"$HERE/scripts/stop-server.sh" >/dev/null 2>&1 || true' EXIT

# Warmup (matches bench.sh:65) — discard output.
"$HERE/scripts/run-tquic-client.sh" "$PAYLOAD" "$SCENARIO" "$WARMUP_S" >/dev/null 2>&1 || true

# Drive the 30s measurement window in the background; perf samples for
# PERF_DUR seconds inside it (with a 2s ramp-in pause, matching h2 harness).
"$HERE/scripts/run-tquic-client.sh" "$PAYLOAD" "$SCENARIO" "$DURATION_S" \
    >"$OUT/client.log" 2>&1 &
LOAD_PID=$!

sleep 2  # let load stabilize before sampling
echo "[perf-record] sampling for ${PERF_DUR}s..."
# `-e cpu-clock` is a software event that works even with
# kernel.perf_event_paranoid=2 (CPU PMU events are gated at paranoid>=1).
# UID-matched container (--user) makes per-process attach legal at paranoid=2.
# `--call-graph=dwarf,16384` captures 16KB of stack per sample for DWARF
# unwinding; default 8KB is too small for deep rustls inlining + Mojo handler
# stacks (verified in dry run — 8KB gave only top-frame samples).
perf record -F "$PERF_FREQ" -g --call-graph=dwarf,16384 \
    -e cpu-clock \
    -p "$PID" -o "$OUT/perf.data" \
    -- sleep "$PERF_DUR" 2>&1 | tail -5

wait "$LOAD_PID" 2>/dev/null || true

# Build symfs from the container's filesystem BEFORE stopping it.
# perf reads /proc/$PID/maps and resolves symbols from --symfs <root>; we
# need to copy out the binaries while the container is still running. This
# replaces the per-spec docker-exec fallback (§4) with the simpler symfs
# approach.
SYMFS="$OUT/symfs"
mkdir -p "$SYMFS/usr/local/lib" "$SYMFS/usr/local/bin"
cp "/proc/$PID/root/usr/local/bin/h3_server" "$SYMFS/usr/local/bin/" 2>/dev/null || true
cp /proc/"$PID"/root/usr/local/lib/*.so "$SYMFS/usr/local/lib/" 2>/dev/null || true

# Stop the server cleanly.
"$HERE/scripts/stop-server.sh" >/dev/null 2>&1 || true
trap - EXIT

# Post-process with --symfs so perf script resolves in-container paths
# from the snapshot we just took.
echo "[perf-record] generating flamegraph..."
perf script --symfs "$SYMFS" -i "$OUT/perf.data" \
    >"$OUT/perf-script.txt" 2>"$OUT/perf-script.err" || true
"$FLAMEGRAPH/stackcollapse-perf.pl" "$OUT/perf-script.txt" >"$OUT/perf-folded.txt"
"$FLAMEGRAPH/flamegraph.pl" \
    --title "mojo-net h3 ${SCENARIO} ${PAYLOAD} (${GIT_SHA})" \
    --subtitle "perf -F ${PERF_FREQ} -g --call-graph=dwarf, ${PERF_DUR}s window" \
    "$OUT/perf-folded.txt" >"$OUT/perf.svg"

# Provenance one-liner.
{
    echo "ts=$TS sha=$GIT_SHA payload=$PAYLOAD scenario=$SCENARIO"
    echo "perf_freq=$PERF_FREQ perf_dur=$PERF_DUR warmup=$WARMUP_S duration=$DURATION_S"
    echo "paranoid=$PARANOID host_pid=$PID"
    echo "image=$(docker image inspect mojo-net-bench:latest --format '{{.Id}}' 2>/dev/null || echo unknown)"
} >"$OUT/meta.txt"

echo
echo "[perf-record] done."
echo "  perf.data       $(stat -c%s "$OUT/perf.data" 2>/dev/null || echo 0) bytes"
echo "  perf-folded.txt $(wc -l <"$OUT/perf-folded.txt" 2>/dev/null || echo 0) unique stacks"
echo "  perf.svg        $OUT/perf.svg"
echo "  client.log      $(grep -E 'connections|finished|requests' "$OUT/client.log" 2>/dev/null | head -3 || echo '(see file)')"
