#!/usr/bin/env bash
# Runs the h3i-scenarios crate against examples/hello_h3_server and gates on
# pass_count >= conformance/h3i_min_pass.txt.
#
# Exit codes:
#   0 — passes >= threshold
#   1 — passes < threshold (regression)
#   2 — environment / setup failure
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"
SCENARIOS_DIR="$CONFORMANCE_DIR/h3i-scenarios"
THRESHOLD_FILE="$CONFORMANCE_DIR/h3i_min_pass.txt"
SERVER_DIR="$REPO_ROOT/examples/hello_h3_server"
SERVER_BIN="$SERVER_DIR/hello_h3_server"

# Preflight — exit 2 on misconfig.
[[ -d "$SCENARIOS_DIR" ]] || { echo "[run_h3i] missing $SCENARIOS_DIR" >&2; exit 2; }
[[ -f "$THRESHOLD_FILE" ]] || { echo "[run_h3i] missing $THRESHOLD_FILE" >&2; exit 2; }
[[ -x "$SERVER_BIN" ]] || { echo "[run_h3i] missing $SERVER_BIN — build hello_h3_server first" >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "[run_h3i] cargo not in PATH" >&2; exit 2; }

THRESHOLD="$(tr -d '[:space:]' < "$THRESHOLD_FILE")"
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || { echo "[run_h3i] threshold is not an integer: '$THRESHOLD'" >&2; exit 2; }

# Build scenario binaries once (release profile keeps things fast at run time).
echo "[run_h3i] building scenarios (release)..."
(cd "$SCENARIOS_DIR" && cargo build --release --locked --bins) >&2 || {
    echo "[run_h3i] cargo build failed" >&2
    exit 2
}

LOGDIR="${RUN_H3I_LOGDIR:-/tmp/run_h3i.$$}"
mkdir -p "$LOGDIR"
SERVER_OUT="$LOGDIR/server.stdout.log"
SERVER_ERR="$LOGDIR/server.stderr.log"

# Terminate the backgrounded server on script exit so no listener lingers.
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Server must run from its own directory so its CWD-relative lib/ and certs/
# symlinks resolve.
(cd "$SERVER_DIR" && exec ./hello_h3_server) > "$SERVER_OUT" 2> "$SERVER_ERR" &
SERVER_PID=$!

# Wait up to 5s for the listener to bind.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ss -uln 2>/dev/null | grep -q ':4433 '; then break; fi
    sleep 0.5
done
if ! ss -uln 2>/dev/null | grep -q ':4433 '; then
    echo "[run_h3i] server failed to bind 4433 within 5s" >&2
    cat "$SERVER_ERR" >&2
    exit 2
fi

# Enumerate scenario binaries from the cargo target dir. Each binary exits 0
# on PASS and non-zero on FAIL; we count exit codes.
TARGET_DIR="$SCENARIOS_DIR/target/release"
PASSED=0
FAILED=0
TOTAL=0
for bin in "$TARGET_DIR"/*; do
    [[ -x "$bin" && -f "$bin" ]] || continue
    # Skip dep build artifacts (everything in `target/release/deps/`, `build/`, etc.
    # is excluded by the glob above since those live in subdirs).
    name="$(basename "$bin")"
    TOTAL=$((TOTAL + 1))
    if "$bin" > "$LOGDIR/scenario.$name.log" 2>&1; then
        PASSED=$((PASSED + 1))
        echo "[run_h3i] PASS $name"
    else
        FAILED=$((FAILED + 1))
        echo "[run_h3i] FAIL $name (see $LOGDIR/scenario.$name.log)"
    fi
done

echo "[run_h3i] passed=$PASSED failed=$FAILED total=$TOTAL threshold=$THRESHOLD"
echo "[run_h3i] logs: $LOGDIR"

if (( PASSED < THRESHOLD )); then
    echo "[run_h3i] REGRESSION: pass count $PASSED < threshold $THRESHOLD" >&2
    exit 1
fi

exit 0
