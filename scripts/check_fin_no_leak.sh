#!/usr/bin/env bash
# scripts/check_fin_no_leak.sh
#
# AC6 — Drive 1000 sequential Connection: close connections against
# examples/hello_h1_server and examples/hello_h2_server, then probe the
# residual ESTABLISHED-state socket count. Post-fix expected count: 0.
#
# Usage: bash scripts/check_fin_no_leak.sh
# Exit:  0 if H1 residual == 0 AND H2 residual == 0; non-zero otherwise.

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
H1_PORT="${HELLO_H1_PORT:-8080}"
H2_PORT="${HELLO_H2_PORT:-8443}"
H1_DIR="$REPO/examples/hello_h1_server"
H2_DIR="$REPO/examples/hello_h2_server"
N="${N:-1000}"

run_one() {
  local proto=$1 dir=$2 port=$3 scheme=$4 curl_extra=$5
  echo "--- $proto: $N sequential Connection: close ($scheme) ---"
  (cd "$dir" && LD_LIBRARY_PATH="$REPO/lib" uv run --project . mojox run main.mojo \
      >/tmp/${proto}_server.log 2>&1) &
  local server_pid=$!
  for i in $(seq 1 50); do
    grep -q "listening" /tmp/${proto}_server.log 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q "listening" /tmp/${proto}_server.log; then
    echo "FAIL: $proto server did not start (see /tmp/${proto}_server.log)"
    kill "$server_pid" 2>/dev/null
    return 1
  fi
  local errs=0
  for i in $(seq 1 "$N"); do
    curl -sS -o /dev/null $curl_extra -H 'Connection: close' \
      "${scheme}://[::1]:${port}/" 2>/dev/null || errs=$((errs+1))
  done
  if [ "$errs" -gt 0 ]; then
    echo "WARN: $errs/$N curl errors against ${scheme}://[::1]:${port}/"
  fi
  sleep 5
  local count
  count=$(ss -Htn state established "( sport = :${port} )" | wc -l)
  echo "$proto residual ESTABLISHED count = $count (expected 0)"
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null
  [ "$count" -eq 0 ]
}

H1_OK=0; H2_OK=0
run_one h1 "$H1_DIR" "$H1_PORT" http "" && H1_OK=1
run_one h2 "$H2_DIR" "$H2_PORT" https "-k --http2" && H2_OK=1

echo "--- Verdict ---"
echo "H1 residual=0: $([ $H1_OK -eq 1 ] && echo PASS || echo FAIL)"
echo "H2 residual=0: $([ $H2_OK -eq 1 ] && echo PASS || echo FAIL)"
[ $H1_OK -eq 1 ] && [ $H2_OK -eq 1 ]
