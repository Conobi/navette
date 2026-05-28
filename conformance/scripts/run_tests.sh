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
    test_h1_connection
    test_h1_connection_cross
    test_h2_frame
    test_h2_payloads_smoke
    test_h2_frame_cross
    test_hpack_integer
    test_hpack_huffman
    test_hpack_decode
    test_hpack_roundtrip
    test_hpack_cross
    test_hpack_security
    test_h2_connection
    test_h2_connection_cross
    test_h2_stream
    test_h2_stream_cross
    test_h2_send_window_exhaustion
    test_cross_quic_hs_keys
    test_cross_quic_packet_header
    test_h3_frame_cross
    test_qpack_cross
    test_hpack_oracle_self
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
    echo "Running h3i conformance gate..."
    "$SCRIPT_DIR/run_h3i.sh"
fi
