# conformance/tests/test_h2_connection.mojo
#
# HC-4a: HTTP/2 connection state machine tests.
from lib.test_util import assert_true, assert_equal, hex_decode, hex_encode
from lib.http2.connection import (
    H2Config,
    H2Settings,
    H2Event,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_PING_ACKNOWLEDGED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_WINDOW_UPDATED,
    H2_EVT_CONNECTION_TERMINATED,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_STREAM_RESET,
    StreamState,
    STREAM_IDLE, STREAM_OPEN, STREAM_HALF_CLOSED_LOCAL,
    STREAM_HALF_CLOSED_REMOTE, STREAM_CLOSED,
    CONN_IDLE, CONN_OPEN, CONN_GOAWAY, CONN_CLOSED,
)
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


def test_h2event_factory_methods() raises:
    """H2Event factory methods set correct kind and fields."""
    var e1 = H2Event.settings_acknowledged()
    assert_equal(e1.kind, H2_EVT_SETTINGS_ACKNOWLEDGED, "settings_acknowledged kind")

    var e2 = H2Event.settings_changed()
    assert_equal(e2.kind, H2_EVT_SETTINGS_CHANGED, "settings_changed kind")

    var ping_data = List[UInt8]()
    ping_data.append(UInt8(1))
    ping_data.append(UInt8(2))
    ping_data.append(UInt8(3))
    ping_data.append(UInt8(4))
    ping_data.append(UInt8(5))
    ping_data.append(UInt8(6))
    ping_data.append(UInt8(7))
    ping_data.append(UInt8(8))
    var e3 = H2Event.ping_received(ping_data)
    assert_equal(e3.kind, H2_EVT_PING_RECEIVED, "ping_received kind")
    assert_equal(len(e3.data), 8, "ping_received data length")

    var e4 = H2Event.goaway_received(UInt32(3), UInt32(0), List[UInt8]())
    assert_equal(e4.kind, H2_EVT_GOAWAY_RECEIVED, "goaway_received kind")
    assert_equal(Int(e4.last_stream_id), 3, "goaway last_stream_id")

    var e5 = H2Event.window_updated(UInt32(0), UInt32(1024))
    assert_equal(e5.kind, H2_EVT_WINDOW_UPDATED, "window_updated kind")
    assert_equal(Int(e5.window_increment), 1024, "window_updated increment")

    var e6 = H2Event.connection_terminated(UInt32(0), UInt32(1), String("test"))
    assert_equal(e6.kind, H2_EVT_CONNECTION_TERMINATED, "connection_terminated kind")
    assert_equal(Int(e6.error_code), 1, "connection_terminated error_code")


def test_stream_state_and_constants() raises:
    """StreamState initializes correctly; lifecycle constants have expected values."""
    assert_equal(STREAM_IDLE, 0, "STREAM_IDLE")
    assert_equal(STREAM_OPEN, 1, "STREAM_OPEN")
    assert_equal(STREAM_HALF_CLOSED_LOCAL, 2, "STREAM_HALF_CLOSED_LOCAL")
    assert_equal(STREAM_HALF_CLOSED_REMOTE, 3, "STREAM_HALF_CLOSED_REMOTE")
    assert_equal(STREAM_CLOSED, 4, "STREAM_CLOSED")
    assert_equal(CONN_IDLE, 0, "CONN_IDLE")
    assert_equal(CONN_OPEN, 1, "CONN_OPEN")
    assert_equal(CONN_GOAWAY, 2, "CONN_GOAWAY")
    assert_equal(CONN_CLOSED, 3, "CONN_CLOSED")
    var s = StreamState()
    assert_equal(s.lifecycle, STREAM_IDLE, "default lifecycle")
    assert_equal(s.send_window, 65535, "default send_window")
    assert_equal(s.recv_window, 65535, "default recv_window")
    assert_true(not s.expects_continuation, "default expects_continuation")
    assert_equal(len(s.header_block_buffer), 0, "default header_block_buffer")


def main() raises:
    test_error_codes()
    test_h2config_defaults()
    test_h2settings_defaults()
    test_h2settings_from_config()
    test_h2event_factory_methods()
    test_stream_state_and_constants()
    print("test_h2_connection: 6 tests passed")
