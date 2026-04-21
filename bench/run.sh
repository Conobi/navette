#!/usr/bin/env bash
set -euo pipefail

# Find binaries: Docker puts them in /usr/local/bin, local dev uses bench/
H1_BIN="$(command -v h1_server 2>/dev/null || echo "${BASH_SOURCE[0]%/*}/h1_server")"
H2_BIN="$(command -v h2_server 2>/dev/null || echo "${BASH_SOURCE[0]%/*}/h2_server")"
H3_BIN="$(command -v h3_server 2>/dev/null || echo "${BASH_SOURCE[0]%/*}/h3_server")"

export CERTS_DIR="${CERTS_DIR:-/certs}"
export STATIC_DIR="${STATIC_DIR:-/data/static}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib}"

echo "[bench] Starting H1 server on :8080..."
"$H1_BIN" &
H1_PID=$!

echo "[bench] Starting H2 server on :8443 (TCP)..."
"$H2_BIN" &
H2_PID=$!

echo "[bench] Starting H3 server on :8443 (UDP)..."
"$H3_BIN" &
H3_PID=$!

cleanup() {
    kill "$H1_PID" "$H2_PID" "$H3_PID" 2>/dev/null || true
    wait "$H1_PID" "$H2_PID" "$H3_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[bench] All servers started. PIDs: H1=$H1_PID H2=$H2_PID H3=$H3_PID"
wait
