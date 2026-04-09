# conformance/tests/test_h2_connection.mojo
#
# HC-4a: HTTP/2 connection state machine tests.
from lib.test_util import assert_true, assert_equal, hex_decode, hex_encode
from lib.http2.connection import H2Config, H2Settings
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


def test_h2config_defaults() raises:
    """H2Config defaults match spec."""
    var c = H2Config(client_side=True)
    assert_true(c.client_side, "client_side")
    assert_equal(Int(c.initial_window_size), 65535, "initial_window_size")
    assert_equal(Int(c.max_concurrent_streams), 200, "max_concurrent_streams")
    assert_equal(Int(c.max_frame_size), 16384, "max_frame_size")
    assert_equal(Int(c.max_header_list_size), 16384, "max_header_list_size")
    assert_equal(Int(c.header_table_size), 4096, "header_table_size")
    assert_true(not c.enable_connect_protocol, "enable_connect_protocol")


def test_h2settings_defaults() raises:
    """H2Settings.defaults() matches RFC 9113 §6.5.2."""
    var s = H2Settings.defaults()
    assert_equal(Int(s.header_table_size), 4096, "header_table_size")
    assert_true(s.enable_push, "enable_push default is True")
    assert_equal(Int(s.initial_window_size), 65535, "initial_window_size")
    assert_equal(Int(s.max_frame_size), 16384, "max_frame_size")
    assert_true(not s.enable_connect_protocol, "enable_connect_protocol")


def test_h2settings_from_config() raises:
    """H2Settings.from_config overrides defaults from H2Config."""
    var c = H2Config(client_side=True)
    var s = H2Settings.from_config(c)
    assert_true(not s.enable_push, "from_config sets enable_push=False")
    assert_equal(Int(s.max_concurrent_streams), 200, "from_config max_concurrent_streams")
    assert_equal(Int(s.max_header_list_size), 16384, "from_config max_header_list_size")


def main() raises:
    test_error_codes()
    test_h2config_defaults()
    test_h2settings_defaults()
    test_h2settings_from_config()
    print("test_h2_connection: 4 tests passed")
