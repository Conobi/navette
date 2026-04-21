#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CERTS_DIR="${CERTS_DIR:-/certs}"
STATIC_DIR="${STATIC_DIR:-/data/static}"

export CERTS_DIR STATIC_DIR LD_LIBRARY_PATH="${REPO_ROOT}/lib"

echo "[bench] Starting H1 server on :8080..."
"${SCRIPT_DIR}/h1_server" &
H1_PID=$!

echo "[bench] Starting H2 server on :8443 (TCP)..."
"${SCRIPT_DIR}/h2_server" &
H2_PID=$!

echo "[bench] Starting H3 server on :8443 (UDP)..."
"${SCRIPT_DIR}/h3_server" &
H3_PID=$!

cleanup() {
    kill "$H1_PID" "$H2_PID" "$H3_PID" 2>/dev/null || true
    wait "$H1_PID" "$H2_PID" "$H3_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "[bench] All servers started. PIDs: H1=$H1_PID H2=$H2_PID H3=$H3_PID"
echo "[bench] Press Ctrl+C to stop."
wait
