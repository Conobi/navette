#!/usr/bin/env bash
# scripts/bench_fin_leak_drift.sh
#
# AC7 — 3 independent server-start -> load-driver -> server-stop cycles
# with sleep 30 between iters. Reports rps per iter + median + IQR + stdev.
# Pacing per memory feedback_bench_iter_pacing.md.
#
# Usage:   bash scripts/bench_fin_leak_drift.sh [h1|h2]

set -u
PROTO="${1:?usage: $0 h1|h2}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
case "$PROTO" in
  h1)
    DIR="$REPO/examples/hello_h1_server"; PORT="${HELLO_H1_PORT:-8080}"
    URL="http://[::1]:${PORT}/"
    if command -v wrk >/dev/null 2>&1; then DRIVER=wrk
    elif command -v ab >/dev/null 2>&1; then DRIVER=ab
    else echo "FATAL: neither wrk nor ab found in PATH"; exit 2
    fi
    ;;
  h2)
    DIR="$REPO/examples/hello_h2_server"; PORT="${HELLO_H2_PORT:-8443}"
    URL="https://[::1]:${PORT}/"
    if command -v h2load >/dev/null 2>&1; then DRIVER=h2load
    else echo "FATAL: h2load not found in PATH (HTTP/2 requires h2load)"; exit 2
    fi
    ;;
  *)  echo "bad proto: $PROTO"; exit 2 ;;
esac
echo "driver: $DRIVER"

AUDIT_THRESHOLD="${AUDIT_THRESHOLD:-50}"
audit_host() {
  echo "--- host audit pre-iter (threshold ${AUDIT_THRESHOLD}%) ---"
  cat /proc/loadavg
  ps -eo pid,pcpu,comm --sort=-pcpu | head -5
  local foreign
  foreign=$(ps -eo pcpu,comm --sort=-pcpu | awk -v T="$AUDIT_THRESHOLD" 'NR>1 && $2=="mojo" && $1>T {print $0}')
  if [ -n "$foreign" ]; then
    echo "ABORT: foreign mojo process at >${AUDIT_THRESHOLD}% CPU detected:"
    echo "$foreign"
    return 1
  fi
}

kill_tree() {
  local pgid=$1
  [ -z "$pgid" ] && return
  kill -TERM -- "-$pgid" 2>/dev/null
  for i in $(seq 1 30); do
    if ! kill -0 -- "-$pgid" 2>/dev/null; then return; fi
    sleep 0.1
  done
  kill -KILL -- "-$pgid" 2>/dev/null
}

run_iter() {
  local n=$1
  local rps_file=$2
  audit_host || return 1
  echo "--- $PROTO iter $n ---"
  : > "$rps_file"
  setsid bash -c "cd '$DIR' && exec env LD_LIBRARY_PATH='$REPO/lib' uv run --project . mojox run main.mojo" \
    >"/tmp/${PROTO}_iter${n}.log" 2>&1 &
  local server_pid=$!
  # 600 * 0.1s = 60s readiness window; covers first-time mojox rebuild after a library swap.
  for i in $(seq 1 600); do
    grep -q "listening" "/tmp/${PROTO}_iter${n}.log" 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q "listening" "/tmp/${PROTO}_iter${n}.log"; then
    echo "ABORT: $PROTO iter $n server did not become ready (see /tmp/${PROTO}_iter${n}.log)"
    kill_tree "$server_pid"
    wait "$server_pid" 2>/dev/null
    return 1
  fi
  local rps
  case "$DRIVER" in
    wrk)
      rps=$(wrk -t8 -c256 -d30s "$URL" 2>&1 \
            | awk '/Requests\/sec:/ {print $2}')
      ;;
    ab)
      # ab is single-threaded; -c256 is the concurrency level.
      # -t30 caps duration to 30s; -n100000 caps total requests if duration finishes first.
      rps=$(ab -t 30 -n 100000 -c 256 "$URL" 2>&1 \
            | awk '/Requests per second:/ {print $4}')
      ;;
    h2load)
      rps=$(h2load -t8 -c256 -D30 "$URL" 2>&1 \
            | awk '/finished in/ {for(i=1;i<=NF;i++) if($i ~ /req\/s/) print $(i-1)}')
      ;;
  esac
  kill_tree "$server_pid"
  wait "$server_pid" 2>/dev/null
  sleep 1
  echo "iter${n}_rps=${rps}"
  printf '%s\n' "$rps" > "$rps_file"
}

declare -a RPS
for n in 1 2 3; do
  rps_file="/tmp/${PROTO}_iter${n}.rps"
  run_iter "$n" "$rps_file" || { echo "iter $n aborted; exiting"; exit 3; }
  rps_val=$(cat "$rps_file" 2>/dev/null | tr -d '[:space:]')
  if ! [[ "$rps_val" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "ABORT: iter $n produced non-numeric rps: '$rps_val'"
    exit 4
  fi
  RPS+=("$rps_val")
  if [ "$n" -lt 3 ]; then
    echo "--- sleep 30 ---"
    sleep 30
  fi
done

echo "--- verdict ---"
python3 - "${RPS[@]}" <<'PY'
import sys, statistics
rps=[float(x) for x in sys.argv[1:]]
if len(rps) < 3:
    print("FAIL: fewer than 3 iters captured")
    raise SystemExit(2)
med = statistics.median(rps)
iqr = statistics.quantiles(rps, n=4)[2] - statistics.quantiles(rps, n=4)[0]
sd  = statistics.stdev(rps)
drift = abs(rps[2] - rps[0]) / rps[0]
print(f"rps_iter1={rps[0]:.0f} rps_iter2={rps[1]:.0f} rps_iter3={rps[2]:.0f}")
print(f"median={med:.0f} IQR={iqr:.0f} ({iqr/med*100:.2f}%) stdev={sd:.0f}")
print(f"|iter3-iter1|/iter1 = {drift*100:.2f}%")
PY
