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
    test_serializer
    test_h1_connection
    test_server_connection
    test_client_connection
    test_cross_validation
    test_tls_connection
    test_proxy_token
    test_capabilities
    test_stream_error
    test_write_result
    test_body_frame_v2
    test_recv_body
    test_send_body
    test_handler_detach
    test_response_writer
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
    # The cross-validation test imports both src.h1 and the conformance
    # batch parser (lib.http1) so it needs an extra include path.
    EXTRA_I=()
    if [ "$t" = "test_cross_validation" ]; then
        EXTRA_I=(-I conformance)
    fi
    if [ "$t" = "test_proxy_token" ]; then
        EXTRA_I=(-I examples/reverse_proxy)
    fi
    if uv run mojo run -I . "${EXTRA_I[@]}" -D ASSERT=all "tests/$t.mojo"; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $t"
        exit 1
    fi
done

echo ""
echo "All $PASSED/$TOTAL src tests passed."
