#!/usr/bin/env bash
#
# Run all production tests in tests/.
# Mirrors conformance/scripts/run_tests.sh but for the src/ tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$REPO_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

cd "$REPO_ROOT"
rm -f src.mojopkg tests.mojopkg

TESTS=(
    test_method
    test_status
    test_headers
    test_body
    test_request_response
    test_phase_a_smoke
)

FILTER="${TESTS_FILTER:-}"
PASSED=0
TOTAL=0

for t in "${TESTS[@]}"; do
    if [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]]; then
        continue
    fi
    TOTAL=$((TOTAL + 1))
    echo "--- $t ---"
    if uv run mojo run -I . -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL src tests passed."
