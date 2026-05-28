#!/usr/bin/env bash
# Runs the pinned h3spec against examples/hello_h3_server and gates on pass_count >= conformance/h3spec_min_pass.txt.
# Exit codes:
#   0 — passes >= threshold
#   1 — passes < threshold (regression)
#   2 — environment / setup failure
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"
VENDOR="$CONFORMANCE_DIR/vendor/h3spec"
H3SPEC="$VENDOR/h3spec"
# Upstream ships the binary gzipped; SHA256SUMS pins the DECOMPRESSED ELF.
RELEASE_URL="https://github.com/kazu-yamamoto/h3spec/releases/download/v0.1.0/h3spec-linux-x86_64.gz"
THRESHOLD_FILE="$CONFORMANCE_DIR/h3spec_min_pass.txt"
SERVER_BIN="$REPO_ROOT/examples/hello_h3_server/hello_h3_server"

# Ensure the cached binary exists; download + gunzip on first use.
ensure_binary() {
    if [[ -x "$H3SPEC" ]] && (cd "$VENDOR" && sha256sum -c SHA256SUMS >/dev/null 2>&1); then
        return 0
    fi
    echo "[run_h3spec] downloading h3spec from $RELEASE_URL" >&2
    local tmp_gz tmp
    tmp_gz="$(mktemp --suffix=.gz)"
    tmp="${tmp_gz%.gz}"
    if ! curl -L --http1.1 -fSso "$tmp_gz" "$RELEASE_URL"; then
        echo "[run_h3spec] download failed" >&2
        rm -f "$tmp_gz"
        return 2
    fi
    if ! gunzip -f "$tmp_gz"; then
        echo "[run_h3spec] gunzip failed" >&2
        rm -f "$tmp_gz" "$tmp"
        return 2
    fi
    chmod +x "$tmp"
    mv "$tmp" "$H3SPEC"
    if ! (cd "$VENDOR" && sha256sum -c SHA256SUMS >/dev/null); then
        echo "[run_h3spec] checksum mismatch after download; SHA256SUMS may be stale" >&2
        return 2
    fi
}

[[ -f "$VENDOR/SHA256SUMS" ]] || { echo "[run_h3spec] missing $VENDOR/SHA256SUMS — see $VENDOR/README.md for the pin refresh procedure" >&2; exit 2; }
[[ -f "$THRESHOLD_FILE" ]] || { echo "[run_h3spec] missing $THRESHOLD_FILE" >&2; exit 2; }
[[ -x "$SERVER_BIN" ]] || { echo "[run_h3spec] missing $SERVER_BIN — build hello_h3_server first" >&2; exit 2; }
ensure_binary || exit 2

THRESHOLD="$(tr -d '[:space:]' < "$THRESHOLD_FILE")"
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || { echo "[run_h3spec] threshold is not an integer: '$THRESHOLD'" >&2; exit 2; }

LOGDIR="${RUN_H3SPEC_LOGDIR:-/tmp/run_h3spec.$$}"
mkdir -p "$LOGDIR"
SERVER_OUT="$LOGDIR/server.stdout.log"
SERVER_ERR="$LOGDIR/server.stderr.log"
H3SPEC_OUT="$LOGDIR/h3spec.out"
H3SPEC_JSON="$LOGDIR/h3spec.json"

# Terminate the backgrounded server on script exit so no listener lingers.
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Server lifecycle — exec from the example dir so the relative `lib/` and
# `certs/` symlinks resolve.
(cd "$REPO_ROOT/examples/hello_h3_server" && exec ./hello_h3_server) \
    > "$SERVER_OUT" 2> "$SERVER_ERR" &
SERVER_PID=$!

# Wait up to 5s for the listener to come up. ss -uln (UDP) since QUIC.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ss -uln 2>/dev/null | grep -q ':4433 '; then break; fi
    sleep 0.5
done
if ! ss -uln 2>/dev/null | grep -q ':4433 '; then
    echo "[run_h3spec] server failed to bind 4433 within 5s" >&2
    cat "$SERVER_ERR" >&2
    exit 2
fi

# Run h3spec (it does not signal failure via exit code; it always finishes).
# h3spec v0.1.0 takes positional <host> <port> arguments.
"$H3SPEC" 127.0.0.1 4433 > "$H3SPEC_OUT" 2>&1 || true

# Parse pass count.
python3 "$SCRIPT_DIR/h3spec_parse.py" "$H3SPEC_OUT" > "$H3SPEC_JSON"
PASSED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["passed"])' "$H3SPEC_JSON")"
TOTAL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total"])' "$H3SPEC_JSON")"

echo "[run_h3spec] passed=$PASSED total=$TOTAL threshold=$THRESHOLD"
echo "[run_h3spec] logs: $LOGDIR"

if (( PASSED < THRESHOLD )); then
    echo "[run_h3spec] REGRESSION: pass count $PASSED < threshold $THRESHOLD" >&2
    echo "[run_h3spec] per-test failures:" >&2
    python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
for row in data["per_test"]:
    if row["status"] != "pass":
        print("  - [{}] {}".format(row["status"], row["name"]))
' "$H3SPEC_JSON" >&2
    exit 1
fi

exit 0
