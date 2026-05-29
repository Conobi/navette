#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$REPO_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Auto-enumerate every test_*.mojo in conformance/tests/ so a new file is
# never silently orphaned. Glob-based discovery replaces a hand-curated array
# that was silently ~2.6% short for two months (test_http1_types_smoke was
# added 2026-04-05 but never registered, and went stale against the
# strictness refactor without anyone noticing). Sorted for deterministic
# ordering across hosts; each test is self-contained so order is irrelevant
# to correctness.
mapfile -t TESTS < <(
    cd "$CONFORMANCE_DIR/tests" && \
    ls test_*.mojo 2>/dev/null | sed 's/\.mojo$//' | LC_ALL=C sort
)
if [ "${#TESTS[@]}" -eq 0 ]; then
    echo "run_tests: no test_*.mojo files found under $CONFORMANCE_DIR/tests" >&2
    exit 2
fi

FILTER="${CONFORMANCE_FILTER:-}"
PASSED=0
TOTAL=0

for t in "${TESTS[@]}"; do
    if [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]]; then
        continue
    fi
    TOTAL=$((TOTAL + 1))
    echo "--- $t ---"
    cd "$CONFORMANCE_DIR"
    rm -f ./*.mojopkg 2>/dev/null || true
    if uv run --project "$REPO_ROOT" mojox run -I "$CONFORMANCE_DIR" -I "$REPO_ROOT" -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL conformance tests passed."

# h3i conformance gate — opt-in via H3I=1 to keep the inner-loop dev run fast.
# CI sets H3I=1; the local conformance loop defaults to off.
#
# The earlier h3spec gate (H3SPEC=1) is kept on disk but no longer wired here:
# h3spec's Haskell QUIC client cannot complete a handshake with navette's
# rustls-based server (curl/ngtcp2 + h3i both handshake fine, so it is not a
# navette bug). Invoke conformance/scripts/run_h3spec.sh directly if you want
# to probe whether a future h3spec build has fixed the interop.
if [[ "${H3I:-0}" == "1" ]]; then
    echo "Running AC-0 comptime probe..."
    PROBE_OUT="$(uv run --project "$REPO_ROOT" mojo \
        "$REPO_ROOT/plans/2026-05-29-h3i-phase-a-completion/comptime_probe.mojo" 2>&1)"
    echo "$PROBE_OUT" | grep -q "case1: \[H3-TEST\] some runtime detail" \
        || { echo "AC-0 probe regression: case1 missing" >&2; exit 1; }
    echo "$PROBE_OUT" | grep -q "case3-contains: True" \
        || { echo "AC-0 probe regression: case3 missing" >&2; exit 1; }
    echo "$PROBE_OUT" | grep -q "case4-comptime-in-string: True" \
        || { echo "AC-0 probe regression: case4 missing" >&2; exit 1; }
    echo "AC-0 probe OK"

    echo "Running coverage_check.py (strict by default; lenient via COVERAGE_CHECK_MODE=lenient)..."
    python3 "$SCRIPT_DIR/coverage_check.py" \
        --mode "${COVERAGE_CHECK_MODE:-strict}" \
        --spec  "$REPO_ROOT/specs/2026-05-29-h3i-phase-a-completion.md" \
        --triage "$REPO_ROOT/research/h3spec-failure-triage.md" \
        --coverage "$REPO_ROOT/conformance/h3i-scenarios/COVERAGE.md" \
        --tags "$REPO_ROOT/navette/quic/guard_tags.mojo" \
               "$REPO_ROOT/navette/h3/guard_tags.mojo" \
        --threshold-file "$REPO_ROOT/conformance/h3i_min_pass.txt" \
        --scenarios-dir "$REPO_ROOT/conformance/h3i-scenarios" \
        --connection-files "$REPO_ROOT/navette/h3/connection.mojo" \
                           "$REPO_ROOT/navette/quic/connection.mojo"

    echo "Running h3i conformance gate..."
    "$SCRIPT_DIR/run_h3i.sh"
fi
