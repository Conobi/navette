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
  h1) DIR="$REPO/examples/hello_h1_server"; PORT="${HELLO_H1_PORT:-8080}"; URL="http://[::1]:${PORT}/"; DRIVER=wrk ;;
  h2) DIR="$REPO/examples/hello_h2_server"; PORT="${HELLO_H2_PORT:-8443}"; URL="https://[::1]:${PORT}/"; DRIVER=h2load ;;
  *)  echo "bad proto: $PROTO"; exit 2 ;;
esac

audit_host() {
  echo "--- host audit pre-iter ---"
  cat /proc/loadavg
  ps -eo pid,pcpu,comm --sort=-pcpu | head -5
  local foreign
  foreign=$(ps -eo pcpu,comm --sort=-pcpu | awk 'NR>1 && $2=="mojo" && $1>50 {print $0}')
  if [ -n "$foreign" ]; then
    echo "ABORT: foreign mojo process at >50% CPU detected:"
    echo "$foreign"
    return 1
  fi
}

run_iter() {
  local n=$1
  audit_host || return 1
  echo "--- $PROTO iter $n ---"
  (cd "$DIR" && LD_LIBRARY_PATH="$REPO/lib" uv run --project . mojox run main.mojo \
      >/tmp/${PROTO}_iter${n}.log 2>&1) &
  local server_pid=$!
  for i in $(seq 1 50); do
    grep -q "listening" /tmp/${PROTO}_iter${n}.log 2>/dev/null && break
    sleep 0.1
  done
  local rps
  if [ "$DRIVER" = "wrk" ]; then
    rps=$(wrk -t8 -c256 -d30s "$URL" 2>&1 \
          | awk '/Requests\/sec:/ {print $2}')
  else
    rps=$(h2load -t8 -c256 -D30 "$URL" 2>&1 \
          | awk '/finished in/ {for(i=1;i<=NF;i++) if($i ~ /req\/s/) print $(i-1)}')
  fi
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  sleep 1
  echo "iter${n}_rps=${rps}"
  echo "$rps"
}

declare -a RPS
for n in 1 2 3; do
  out=$(run_iter "$n")
  echo "$out"
  RPS+=("$(echo "$out" | tail -1)")
  if [ "$n" -lt 3 ]; then
    echo "--- sleep 30 ---"
    sleep 30
  fi
done

echo "--- verdict ---"
python3 - <<PY
import statistics
rps=[float(x) for x in "${RPS[@]}".split() if x]
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
