#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"

TESTS=(
    test_varint
    test_packet_number
    test_initial_protection
)

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
    rm -f *.mojopkg
    if uv run --project "$REPO_ROOT" mojo run -I "$CONFORMANCE_DIR" -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL conformance tests passed."
