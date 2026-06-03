#!/usr/bin/env bash
# Runs the quiche-raw-frame-scenarios crate against examples/hello_h3_server
# and gates on pass_count >= conformance/quiche_raw_frame_min_pass.txt.
#
# Each scenario injects a single adversarial QUIC frame (or a packet with
# reserved-bit-flipped header) into a live navette connection via the
# vendored `quiche::test_utils::encode_pkt` path and asserts that navette
# emits CONNECTION_CLOSE with the expected error code and a `[QUIC-...]`
# GUARD_TAG substring in the reason phrase.
#
# Exit codes:
#   0 — passes >= threshold
#   1 — passes < threshold (regression)
#   2 — environment / setup failure
set -euo pipefail

# Prepend ~/.local/bin so `uv` (installed via the standalone installer) is
# discoverable when this script runs under `env -i PATH=/usr/bin:/bin bash …`
# from the reproducibility checklist. The rebuild path inside
# ensure_server_fresh() shells out to `uv sync` / `uv build`, which live there
# on the maintainer host. Append a colon only if PATH is non-empty so we don't
# emit a stray leading separator.
if [[ -d "$HOME/.local/bin" ]]; then
    case ":${PATH:-}:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="$HOME/.local/bin${PATH:+:$PATH}" ;;
    esac
    export PATH
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"
SCENARIOS_DIR="$CONFORMANCE_DIR/quiche-raw-frame-scenarios"
THRESHOLD_FILE="$CONFORMANCE_DIR/quiche_raw_frame_min_pass.txt"
SERVER_DIR="$REPO_ROOT/examples/hello_h3_server"
SERVER_BIN="$SERVER_DIR/hello_h3_server"

# Port configurability: child scenario binaries read QRF_SERVER_PORT to
# locate the server (see quiche_raw_frame_scenarios::navette_connect).
PORT="${QRF_SERVER_PORT:-4433}"
export QRF_SERVER_PORT="$PORT"

# Preflight — exit 2 on misconfig.
[[ -d "$SCENARIOS_DIR" ]] || { echo "[run_qrf] missing $SCENARIOS_DIR" >&2; exit 2; }
[[ -f "$THRESHOLD_FILE" ]] || { echo "[run_qrf] missing $THRESHOLD_FILE" >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "[run_qrf] cargo not in PATH" >&2; exit 2; }

# Vendor-patch integrity check (AC-0). Bails out before any expensive work
# if the vendored quiche tree has drifted from its required patches.
if ! bash "$SCRIPT_DIR/check_quiche_patch.sh"; then
    echo "[run_qrf] vendor patch integrity check failed" >&2
    exit 2
fi

# Port-conflict guard: refuse to spawn a second listener on the same port.
# Running two gates back-to-back without cleanup would cause the server to
# silently fail to bind; this gives an explicit, actionable error instead.
if ss -ulnp 2>/dev/null | grep -q ":$PORT "; then
    echo "[run_qrf] port $PORT already bound — refusing to spawn server" >&2
    exit 2
fi

# Freshness check: if any navette/*.mojo is newer than $SERVER_BIN, rebuild
# the example. The editable-install of navette in the example's .venv does
# NOT auto-bust navette.mojopkg, so source edits to navette/ leave a stale
# binary on disk that would otherwise pass the gate with pre-edit behaviour.
ensure_server_fresh() {
    if [[ ! -x "$SERVER_BIN" ]]; then
        echo "[run_qrf] $SERVER_BIN not built; rebuilding" >&2
    else
        local newest_src
        # Watch both the navette package AND the example's own main.mojo;
        # without the example check, edits to hello_h3_server's entry
        # point silently won't take effect across QRF re-runs.
        newest_src="$(find "$REPO_ROOT/navette" "$REPO_ROOT/examples/hello_h3_server" \
            -name '*.mojo' -newer "$SERVER_BIN" -print -quit 2>/dev/null)"
        if [[ -z "$newest_src" ]]; then
            return 0
        fi
        echo "[run_qrf] source newer than $SERVER_BIN ($newest_src); rebuilding" >&2
    fi

    local example_dir="$REPO_ROOT/examples/hello_h3_server"
    (
        cd "$example_dir" || exit 2
        uv sync --reinstall-package navette >&2 || exit 2
        rm -f hello_h3_server
        uv build --wheel >&2 || exit 2
        local whl
        whl="$(ls -t dist/navette_example_hello_h3_server-*.whl 2>/dev/null | head -1)"
        [[ -n "$whl" ]] || { echo "[run_qrf] could not locate built wheel" >&2; exit 2; }
        unzip -p "$whl" '*/hello_h3_server' > hello_h3_server || exit 2
        chmod +x hello_h3_server
    )
}

if [[ "${RUN_QRF_SKIP_REBUILD:-0}" == "1" ]]; then
    [[ -x "$SERVER_BIN" ]] || { echo "[run_qrf] $SERVER_BIN missing and RUN_QRF_SKIP_REBUILD=1" >&2; exit 2; }
else
    ensure_server_fresh || { echo "[run_qrf] failed to rebuild $SERVER_BIN" >&2; exit 2; }
fi

THRESHOLD="$(tr -d '[:space:]' < "$THRESHOLD_FILE")"
[[ "$THRESHOLD" =~ ^[0-9]+$ ]] || { echo "[run_qrf] threshold is not an integer: '$THRESHOLD'" >&2; exit 2; }

# Create the log directory up front so we can capture build diagnostics too.
LOGDIR="${RUN_QRF_LOGDIR:-/tmp/run_quiche_raw_frame.$$}"
mkdir -p "$LOGDIR"
SERVER_OUT="$LOGDIR/server.stdout.log"
SERVER_ERR="$LOGDIR/server.stderr.log"

# Build scenario binaries once (release profile keeps things fast at run time).
# Tee stderr to a log so a failed build leaves a postmortem-able artifact.
echo "[run_qrf] building scenarios (release)..."
(cd "$SCENARIOS_DIR" && cargo build --release --locked --bins) > "$LOGDIR/cargo.log" 2>&1 || {
    echo "[run_qrf] cargo build failed — see $LOGDIR/cargo.log" >&2
    tail -20 "$LOGDIR/cargo.log" >&2
    exit 2
}

# Terminate the backgrounded server on script exit so no listener lingers.
# If SIGTERM doesn't take (D-state, signal mask, deadlock) we escalate to
# SIGKILL after 5s so the script never hangs waiting on a wedged child.
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        # Give the server 5s to exit gracefully, then SIGKILL.
        ( sleep 5; kill -KILL "$SERVER_PID" 2>/dev/null || true ) &
        local killer_pid=$!
        wait "$SERVER_PID" 2>/dev/null || true
        # Reap the killer if it hasn't fired yet.
        kill "$killer_pid" 2>/dev/null || true
        wait "$killer_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Server must run from its own directory so its CWD-relative lib/ and certs/
# symlinks resolve.
#
# Mojo-built binaries link against the Modular runtime (libKGENCompilerRTShared
# et al.), which lives in the example's uv-managed .venv under
# `modular/lib/`. Neither the binary's RPATH nor `uv run` propagates this
# directory into LD_LIBRARY_PATH, so a fresh shell that hasn't sourced the
# Modular SDK env hits "libKGENCompilerRTShared.so: cannot open shared object
# file" the moment the loader resolves the binary. Detecting the dir by glob
# (Python minor version floats with the SDK) keeps the gate self-contained.
MODULAR_LIB="$(ls -d "$SERVER_DIR"/.venv/lib/python*/site-packages/modular/lib 2>/dev/null | head -1 || true)"
if [[ -z "$MODULAR_LIB" ]]; then
    echo "[run_qrf] could not locate modular/lib under $SERVER_DIR/.venv — run 'uv sync' in $SERVER_DIR" >&2
    exit 2
fi

(
    cd "$SERVER_DIR"
    export LD_LIBRARY_PATH="$MODULAR_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    # Enable 0-RTT acceptance on the test server. The F30 / R01 / R02 /
    # R03 / R04 scenarios require this; without it the server runs in
    # rejection mode (policy=Off, max_early_data = 0) and silently drops
    # 0-RTT, so the corresponding guards cannot fire. All non-0-RTT
    # scenarios are unaffected (they never present a resumed PSK so
    # the early-data permit is never invoked).
    export HELLO_H3_ENABLE_EARLY_DATA=1
    exec ./hello_h3_server
) > "$SERVER_OUT" 2> "$SERVER_ERR" &
SERVER_PID=$!

# Pin bind-detection to OUR backgrounded server's PID. Plain `ss -uln` would
# also accept a zombie listener from a prior crashed run, falsely greenlighting
# the gate. `ss -ulnp` shows pid=NNNN entries; we match only our PID. For the
# user's own process this works without CAP_NET_ADMIN. As a defensive fallback,
# if `ss -p` ever omits the PID (locked-down kernel), we accept "listener on
# :$PORT exists AND our SERVER_PID is still alive" — best we can do without -p.
is_server_bound() {
    local listeners
    listeners="$(ss -ulnp 2>/dev/null | grep ":$PORT " || true)"
    [[ -n "$listeners" ]] || return 1
    if grep -q "pid=$SERVER_PID," <<< "$listeners"; then
        return 0
    fi
    # Fallback: PIDs are hidden but a listener exists and our server is alive.
    if ! grep -q 'pid=' <<< "$listeners" && kill -0 "$SERVER_PID" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Wait up to BIND_TIMEOUT_S seconds (default 15) for the listener to bind.
# Cold-cache VMs and CI runners regularly miss the old 5s budget.
BIND_TIMEOUT_S="${RUN_QRF_BIND_TIMEOUT_S:-15}"
BIND_ITERS=$(( BIND_TIMEOUT_S * 2 ))
for _ in $(seq 1 "$BIND_ITERS"); do
    if is_server_bound; then break; fi
    sleep 0.5
done
if ! is_server_bound; then
    echo "[run_qrf] server (pid $SERVER_PID) failed to bind $PORT within ${BIND_TIMEOUT_S}s" >&2
    cat "$SERVER_ERR" >&2
    exit 2
fi

# Enumerate scenarios from Cargo.toml [[bin]] entries, not the filesystem,
# so stale binaries from renamed scenarios or stray `cargo install` artifacts
# don't pollute the count. Each binary exits 0 on PASS and non-zero on FAIL;
# we count exit codes. Exit code 2 is a setup failure (distinct from the
# guard-assertion exit 1) and is reported separately for triage.
TARGET_DIR="$SCENARIOS_DIR/target/release"
PASSED=0
FAILED=0
SETUP_FAIL=0
TOTAL=0

SCENARIO_NAMES=$(cargo metadata --manifest-path "$SCENARIOS_DIR/Cargo.toml" --no-deps --format-version 1 \
    | python3 -c 'import json,sys; m=json.load(sys.stdin); pkg=next(p for p in m["packages"] if p["name"]=="quiche-raw-frame-scenarios"); print("\n".join(t["name"] for t in pkg["targets"] if "bin" in t["kind"]))')

while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    bin="$TARGET_DIR/$name"
    if [[ ! -x "$bin" ]]; then
        echo "[run_qrf] missing built binary for scenario '$name' at $bin" >&2
        exit 2
    fi
    TOTAL=$((TOTAL + 1))
    if "$bin" > "$LOGDIR/scenario.$name.log" 2>&1; then
        PASSED=$((PASSED + 1))
        echo "[run_qrf] PASS $name"
    else
        ec=$?
        if [[ "$ec" == "2" ]]; then
            SETUP_FAIL=$((SETUP_FAIL + 1))
            FAILED=$((FAILED + 1))
            echo "[run_qrf] FAIL $name (setup, exit 2; see $LOGDIR/scenario.$name.log)"
        else
            FAILED=$((FAILED + 1))
            echo "[run_qrf] FAIL $name (see $LOGDIR/scenario.$name.log)"
        fi
    fi
done <<< "$SCENARIO_NAMES"

echo "[run_qrf] passed=$PASSED failed=$FAILED total=$TOTAL threshold=$THRESHOLD"
if (( SETUP_FAIL > 0 )); then
    echo "[run_qrf] setup_failures=$SETUP_FAIL (exit 2; treated as fail for threshold accounting)"
fi
echo "[run_qrf] logs: $LOGDIR"

if (( PASSED < THRESHOLD )); then
    echo "[run_qrf] REGRESSION: pass count $PASSED < threshold $THRESHOLD" >&2
    exit 1
fi

exit 0
