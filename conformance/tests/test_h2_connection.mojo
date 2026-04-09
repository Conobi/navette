# conformance/tests/test_h2_connection.mojo
#
# HC-4a: HTTP/2 connection state machine tests.
from lib.test_util import assert_true, assert_equal, hex_decode, hex_encode
from lib.http2.frame import (
    H2_NO_ERROR,
    H2_PROTOCOL_ERROR,
    H2_INTERNAL_ERROR,
    H2_FLOW_CONTROL_ERROR,
    H2_SETTINGS_TIMEOUT,
    H2_STREAM_CLOSED,
    H2_FRAME_SIZE_ERROR,
    H2_REFUSED_STREAM,
    H2_CANCEL,
    H2_COMPRESSION_ERROR,
    H2_CONNECT_ERROR,
    H2_ENHANCE_YOUR_CALM,
    H2_INADEQUATE_SECURITY,
    H2_HTTP_1_1_REQUIRED,
)


def test_error_codes() raises:
    """All 14 RFC 9113 §7 error codes have correct values."""
    assert_equal(H2_NO_ERROR, 0, "NO_ERROR")
    assert_equal(H2_PROTOCOL_ERROR, 1, "PROTOCOL_ERROR")
    assert_equal(H2_INTERNAL_ERROR, 2, "INTERNAL_ERROR")
    assert_equal(H2_FLOW_CONTROL_ERROR, 3, "FLOW_CONTROL_ERROR")
    assert_equal(H2_SETTINGS_TIMEOUT, 4, "SETTINGS_TIMEOUT")
    assert_equal(H2_STREAM_CLOSED, 5, "STREAM_CLOSED")
    assert_equal(H2_FRAME_SIZE_ERROR, 6, "FRAME_SIZE_ERROR")
    assert_equal(H2_REFUSED_STREAM, 7, "REFUSED_STREAM")
    assert_equal(H2_CANCEL, 8, "CANCEL")
    assert_equal(H2_COMPRESSION_ERROR, 9, "COMPRESSION_ERROR")
    assert_equal(H2_CONNECT_ERROR, 10, "CONNECT_ERROR")
    assert_equal(H2_ENHANCE_YOUR_CALM, 11, "ENHANCE_YOUR_CALM")
    assert_equal(H2_INADEQUATE_SECURITY, 12, "INADEQUATE_SECURITY")
    assert_equal(H2_HTTP_1_1_REQUIRED, 13, "HTTP_1_1_REQUIRED")


def main() raises:
    test_error_codes()
    print("test_h2_connection: 1 test passed")
