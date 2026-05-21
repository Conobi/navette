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

TESTS=(
    test_phase_a_smoke
    test_memory_safety_hardening
    test_fuzz_infra
    http/test_method
    http/test_status
    http/test_headers
    http/test_body
    http/test_body_frame_v2
    http/test_request_response
    http/test_request_body
    http/test_request_clone
    http/test_recv_body
    http/test_send_body
    http/test_response_writer
    http/test_url
    http/test_decode
    http/test_alt_svc
    http/test_priority
    http/test_sse
    http/test_capabilities
    http/test_stream_error
    http/test_write_result
    http/test_handler_detach
    http/test_handler_try_detach
    http/test_handler_lifecycle
    http/test_session_handle
    http/test_mock_session
    http/test_http_client
    http/test_coro_client
    http/test_cross_validation
    http/test_client_connection
    http/test_server_connection
    http/test_reverse_proxy_refactor
    http/test_proxy_token
    h1/test_h1_connection
    h1/test_h1_server_handler
    h1/test_h1_client_session
    h1/test_serializer
    h2/test_h2_pseudo_headers
    h2/test_h2_handler
    h2/test_h2_session
    h2/test_h2_e2e
    h2/test_h2_tls_alpn
    h2/test_h2_sync_server
    h2/test_h2_streaming_server
    h3/test_h3_extension
    h3/test_h3_frame
    h3/test_h3_qpack
    h3/test_h3_connection
    h3/test_h3_e2e
    h3/test_h3_sync_server
    h3/test_h3_streaming_server
    h3/test_h3_udp_server
    quic/test_quic_cid
    quic/test_quic_codec
    quic/test_quic_frame
    quic/test_quic_packet
    quic/test_quic_transport_params
    quic/test_quic_crypto_stream
    quic/test_quic_pn_space
    quic/test_quic_recovery
    quic/test_quic_retry
    quic/test_quic_flow_control
    quic/test_quic_stream
    quic/test_quic_stream_map
    quic/test_quic_connection
    quic/test_quic_pacer_bypass
    quic/test_quic_resumption
    quic/test_quic_profile
    quic/test_quic_profile_wiring
    quic/cc/test_cc_cubic
    quic/cc/test_cc_pacing
    quic/cc/test_cc_controller
    quic/cc/test_cc_minmax
    tls/test_tls_connection
    tls/test_tls_quic
    io/test_io_loopback
    io/test_ecn
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
    # Conformance/oracle-using tests need `conformance/` on the include path.
    # test_proxy_token additionally imports from examples/reverse_proxy.
    EXTRA_I=()
    case "$t" in
        h2/*|h3/*|quic/*) EXTRA_I=(-I conformance) ;;
        io/test_ecn) EXTRA_I=(-I conformance) ;;
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
