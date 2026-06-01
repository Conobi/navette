#!/usr/bin/env bash
#
# Run all production tests in tests/.
# Mirrors conformance/scripts/run_tests.sh but for the src/ tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$REPO_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

cd "$REPO_ROOT"

# Examples smoke gate — catches example bit-rot under refactors (per Plan 4).
echo "=== examples-smoke gate ==="
"$SCRIPT_DIR/check_examples_build.sh"

# R1' grep gate — boucle.stackful is allowed only in *_streaming_server.mojo
# files inside navette/, plus navette/tls/lib.mojo (FFI bridge slot, currently
# unused). Tests at repo-root tests/ are not scoped here. See
# specs/2026-04-27-sprint-2-h1h2h3-sync-streaming.md and
# plans/2026-04-27-sprint-2-retrospective.md.

R1_VIOLATIONS=$(grep -rEn 'from boucle\.stackful|import boucle\.stackful' navette/ \
  | grep -vE '^navette/(h2/h2_streaming_server|h3/h3_streaming_server)\.mojo:' \
  | grep -vE '^navette/tls/lib\.mojo:' \
  || true)
if [ -n "$R1_VIOLATIONS" ]; then
    echo "R1' violation: boucle.stackful imported outside allowed files:"
    echo "$R1_VIOLATIONS"
    exit 1
fi
echo "R1' grep gate: PASS"

rm -f src.mojopkg tests.mojopkg

# Auto-enumerate every test_*.mojo under tests/ so a new file is never
# silently orphaned. Walks the top-level tests/ entries (test_*.mojo) and
# every immediate sub-tree (h1/, h2/, h3/, http/, interop/, io/, net/,
# quic/, quic/cc/, tls/, fuzz/). Sorted for deterministic ordering across
# hosts; each test is self-contained so order is irrelevant.
#
# Fuzz harnesses (tests/fuzz/) AND the original opt-in skipped them via
# conformance/scripts/run_fuzz.sh — keep that gating here by default so
# the inner-loop dev run stays fast. Set FUZZ_IN_SRC=1 to fold them in.
mapfile -t TESTS < <(
    cd "$REPO_ROOT/tests" && \
    {
        # Top-level test_*.mojo
        find . -maxdepth 1 -name 'test_*.mojo' -type f 2>/dev/null \
            | sed 's|^\./||; s|\.mojo$||'
        # Per-subdirectory test_*.mojo, two levels deep (handles quic/cc/)
        find . -mindepth 2 -name 'test_*.mojo' -type f 2>/dev/null \
            | sed 's|^\./||; s|\.mojo$||' \
            | { if [ "${FUZZ_IN_SRC:-0}" != "1" ]; then grep -v '^fuzz/' || true; else cat; fi; }
    } | LC_ALL=C sort
)
if [ "${#TESTS[@]}" -eq 0 ]; then
    echo "run_tests: no test_*.mojo files found under tests/" >&2
    exit 2
fi

FILTER="${TESTS_FILTER:-}"
PASSED=0
TOTAL=0

for t in "${TESTS[@]}"; do
    if [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]]; then
        continue
    fi
    TOTAL=$((TOTAL + 1))
    echo "--- $t ---"
    # Conformance/oracle-using tests need `conformance/` on the include path.
    # test_proxy_token additionally imports from examples/reverse_proxy.
    EXTRA_I=()
    case "$t" in
        h2/*|h3/*|quic/*) EXTRA_I=(-I conformance) ;;
        io/test_ecn) EXTRA_I=(-I conformance) ;;
        # interop tests share helpers via tests/_test_util and conformance/lib
        interop/*) EXTRA_I=(-I conformance) ;;
        http/test_cross_validation|http/test_http_client|http/test_coro_client)
            EXTRA_I=(-I conformance) ;;
        http/test_proxy_token) EXTRA_I=(-I examples/reverse_proxy) ;;
    esac
    if uv run mojox run "${EXTRA_I[@]}" -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL src tests passed."

# TLS-conformance gate — opt-in via TLS=1 to keep the inner-loop dev run fast.
# CI sets TLS=1; the local run defaults to off.
# Mirrors the H3I=1 block above (lines 104-118 of this file).
#
# Runs the Rust scenario harness against examples/hello_h3_server, then
# validates COVERAGE.md invariants.  COVERAGE_CHECK_MODE defaults to strict.
# --always-on-count 0: tls_sanity_handshake is enumerated as SY01 in Table B
# and already counted in gated(B); no implicit +1 should be added by Inv-4.
if [[ "${TLS:-0}" == "1" ]]; then
    echo "Running TLS conformance gate..."
    "$SCRIPT_DIR/../conformance/scripts/run_tls_conformance.sh"

    # Derive the per-harness F-row scope from COVERAGE.md (Table A rows).
    # Eliminates drift between the gate scope and the coverage index — a row
    # added to Table A is automatically in scope; Inv-6 catches typos.
    # Fallback (verify against Table A if grep ever stops matching):
    # F02,F03,F04,F05,F06,F07,F08,F09,F25,F26,F27,F28,F29
    TLS_TAG_SCOPE=$(grep -oE '^\| F[0-9]{2}\b' \
        "$REPO_ROOT/conformance/tls-conformance/COVERAGE.md" \
        | tr -d '| ' | paste -sd,)
    if [[ -z "$TLS_TAG_SCOPE" ]]; then
        echo "ERROR: TLS_TAG_SCOPE derivation returned empty — COVERAGE.md schema drift?" >&2
        exit 1
    fi

    echo "Running coverage_check.py for TLS conformance (${COVERAGE_CHECK_MODE:-strict} mode)..."
    python3 "$SCRIPT_DIR/../conformance/scripts/coverage_check.py" \
        --mode "${COVERAGE_CHECK_MODE:-strict}" \
        --triage "$REPO_ROOT/research/h3spec-failure-triage.md" \
        --tag-scope "$TLS_TAG_SCOPE" \
        --coverage "$REPO_ROOT/conformance/tls-conformance/COVERAGE.md" \
        --threshold-file "$REPO_ROOT/conformance/tls_conformance_min_pass.txt" \
        --scenarios-dir "$REPO_ROOT/conformance/tls-conformance" \
        --tags "$REPO_ROOT/navette/quic/guard_tags.mojo" \
               "$REPO_ROOT/navette/tls/guard_tags.mojo" \
        --always-on-count 0
fi

# Quiche-raw-frame conformance gate — opt-in via QUICHE_RAW=1 to keep the
# inner-loop dev run fast. CI sets QUICHE_RAW=1; the local loop defaults
# to off. Mirrors the TLS=1 block above.
#
# Runs the Rust scenario harness against examples/hello_h3_server, then
# validates the cycle-local COVERAGE.md against Inv-1..4. Inv-5 (tag
# uniqueness) is intentionally NOT wired here at Phase α: no new tags
# exist yet, and the existing navette/quic/guard_tags.mojo entries are
# scoped to the TLS C1 + h3i F15/F16 cycles. Inv-5 wires in at Phase γ
# once cycle-scoped tag references land alongside the new guards.
# The new COVERAGE.md enumerates sanity_get as SY01 in Table B, so
# --always-on-count 0 keeps the baseline counted exactly once.
# COVERAGE_CHECK_MODE defaults to lenient at Phase α (red rows expected);
# tightened to strict at Phase γ once the gate is fully green.
if [[ "${QUICHE_RAW:-0}" == "1" ]]; then
    echo "Running quiche-raw-frame conformance gate..."
    "$SCRIPT_DIR/../conformance/scripts/run_quiche_raw_frame.sh"

    # Derive the per-harness F-row scope from COVERAGE.md (Table A rows).
    # Fallback (verify against Table A if grep ever stops matching):
    # F01,F10,F11,F12,F13,F14,F15,F16,F17,F18,F19,F20,F21,F22,F23,F24,F30
    QUICHE_TAG_SCOPE=$(grep -oE '^\| F[0-9]{2}\b' \
        "$REPO_ROOT/conformance/quiche-raw-frame-scenarios/COVERAGE.md" \
        | tr -d '| ' | paste -sd,)
    if [[ -z "$QUICHE_TAG_SCOPE" ]]; then
        echo "ERROR: QUICHE_TAG_SCOPE derivation returned empty — COVERAGE.md schema drift?" >&2
        exit 1
    fi

    echo "Running coverage_check.py for quiche-raw-frame (${COVERAGE_CHECK_MODE:-lenient} mode)..."
    python3 "$SCRIPT_DIR/../conformance/scripts/coverage_check.py" \
        --mode "${COVERAGE_CHECK_MODE:-lenient}" \
        --triage "$REPO_ROOT/research/h3spec-failure-triage.md" \
        --tag-scope "$QUICHE_TAG_SCOPE" \
        --coverage "$REPO_ROOT/conformance/quiche-raw-frame-scenarios/COVERAGE.md" \
        --threshold-file "$REPO_ROOT/conformance/quiche_raw_frame_min_pass.txt" \
        --scenarios-dir "$REPO_ROOT/conformance/quiche-raw-frame-scenarios" \
        --always-on-count 0
fi
