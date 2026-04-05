#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFORMANCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CONFORMANCE_DIR/.." && pwd)"

export LD_LIBRARY_PATH="$REPO_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

TESTS=(
    test_util_smoke
    test_cursor
    test_varint
    test_packet_number
    test_initial_protection
    test_cross_varint
    test_cross_packet_number
    test_cross_initial_crypto
    test_rustls_initial
    test_rustls_aead
    test_h1_chunked
    test_h1_parser
    test_h1_security
    test_h1_cross_parser
    test_h1_response
    test_h1_response_cross
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
    rm -f ./*.mojopkg 2>/dev/null || true
    if uv run --project "$REPO_ROOT" mojo run -I "$CONFORMANCE_DIR" -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL conformance tests passed."
