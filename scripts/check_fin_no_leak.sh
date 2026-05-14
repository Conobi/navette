#!/usr/bin/env bash
# scripts/check_fin_no_leak.sh
#
# AC6 — Drive N sequential Connection: close connections against
# examples/hello_h1_server and examples/hello_h2_server, then probe the
# residual server-side TCP state. The FIN-leak fingerprint on the server
# (client closes first) is CLOSE-WAIT, not ESTABLISHED. Clean
# post-condition: 0 sockets in any state other than LISTEN or TIME-WAIT.
#
# Usage: bash scripts/check_fin_no_leak.sh
# Exit:  0 if H1 residual == 0 AND H2 residual == 0; non-zero otherwise.
#
# Probe uses `ss -Htan` (NOT -tn): without -a, ss hides everything except
# ESTABLISHED, which would mask the CLOSE-WAIT leak fingerprint.
#
# Server lifecycle: `setsid` puts the server in its own process group so
# `kill -TERM -- -$pgid` reaps the full subtree (uv -> mojox -> mojo). A
# bare `kill $server_pid` only kills the subshell wrapper, leaving the
# real mojo binary holding the port across runs.

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
H1_PORT="${HELLO_H1_PORT:-8080}"
H2_PORT="${HELLO_H2_PORT:-8443}"
H1_DIR="$REPO/examples/hello_h1_server"
H2_DIR="$REPO/examples/hello_h2_server"
N="${N:-1000}"
CONCURRENCY="${CONCURRENCY:-1}"  # 1 = sequential; >1 = parallel curls via xargs -P

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

run_one() {
  local proto=$1 dir=$2 port=$3 scheme=$4 curl_extra=$5
  local mode="sequential"
  [ "$CONCURRENCY" -gt 1 ] && mode="concurrent x${CONCURRENCY}"
  echo "--- $proto: $N $mode Connection: close ($scheme) ---"
  setsid bash -c "cd '$dir' && exec env LD_LIBRARY_PATH='$REPO/lib' uv run --project . mojox run main.mojo" \
    >"/tmp/${proto}_server.log" 2>&1 &
  local server_pid=$!
  for i in $(seq 1 100); do
    grep -q "listening" "/tmp/${proto}_server.log" 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q "listening" "/tmp/${proto}_server.log"; then
    echo "FAIL: $proto server did not start (see /tmp/${proto}_server.log)"
    kill_tree "$server_pid"
    wait "$server_pid" 2>/dev/null
    return 1
  fi
  local errs=0
  if [ "$CONCURRENCY" -le 1 ]; then
    echo "($N sequential, no parallelism)"
    for i in $(seq 1 "$N"); do
      curl -sS -o /dev/null $curl_extra -H 'Connection: close' \
        "${scheme}://[::1]:${port}/" 2>/dev/null || errs=$((errs+1))
    done
  else
    echo "($N total, $CONCURRENCY in parallel)"
    local err_file
    err_file=$(mktemp)
    : > "$err_file"
    seq 1 "$N" | xargs -P "$CONCURRENCY" -I {} bash -c \
      "curl -sS -o /dev/null $curl_extra -H 'Connection: close' '${scheme}://[::1]:${port}/' 2>/dev/null || echo x >> '$err_file'"
    errs=$(wc -c < "$err_file" 2>/dev/null || echo 0)
    rm -f "$err_file"
  fi
  if [ "$errs" -gt 0 ]; then
    echo "WARN: $errs/$N curl errors against ${scheme}://[::1]:${port}/"
  fi
  sleep 5
  echo "$proto state breakdown (-Htan, server-side, excluding LISTEN/TIME-WAIT):"
  ss -Htan "( sport = :${port} )" 2>/dev/null \
    | awk '$1 != "LISTEN" && $1 != "TIME-WAIT" {print "  "$1}' \
    | sort | uniq -c
  local count
  count=$(ss -Htan "( sport = :${port} )" 2>/dev/null \
          | awk '$1 != "LISTEN" && $1 != "TIME-WAIT"' | wc -l)
  echo "$proto residual count (excl LISTEN, TIME-WAIT) = $count (expected 0 post-fix)"
  kill_tree "$server_pid"
  wait "$server_pid" 2>/dev/null
  sleep 1
  [ "$count" -eq 0 ]
}

H1_OK=0; H2_OK=0
run_one h1 "$H1_DIR" "$H1_PORT" http "" && H1_OK=1
run_one h2 "$H2_DIR" "$H2_PORT" https "-k --http2" && H2_OK=1

echo "--- Verdict ---"
echo "H1 residual=0: $([ $H1_OK -eq 1 ] && echo PASS || echo FAIL)"
echo "H2 residual=0: $([ $H2_OK -eq 1 ] && echo PASS || echo FAIL)"
[ $H1_OK -eq 1 ] && [ $H2_OK -eq 1 ]
