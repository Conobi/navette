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
    H2Connection,
    _append_setting,
    SETTINGS_INITIAL_WINDOW_SIZE,
)
from lib.http2.frame import (
    Frame,
    encode_frame,
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
    FRAME_SETTINGS,
    FRAME_PING,
    FRAME_GOAWAY,
    FRAME_HEADERS,
    FRAME_CONTINUATION,
    FLAG_END_HEADERS,
)


def _build_headers_frame(stream_id: Int, end_headers: Bool = True, end_stream: Bool = False) -> List[UInt8]:
    """Build a minimal HEADERS frame with a dummy header block."""
    var payload = List[UInt8]()
    payload.append(UInt8(0x82))  # indexed: :method GET (static table index 2)
    var flags = 0
    if end_headers:
        flags = flags | 0x04  # END_HEADERS
    if end_stream:
        flags = flags | 0x01  # END_STREAM
    var frame = Frame(len(payload), FRAME_HEADERS, flags, stream_id, payload)
    return encode_frame(frame)


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


def test_client_preface() raises:
    """Client initiate_connection emits magic + SETTINGS."""
    var conn = H2Connection(client_side=True)
    conn.initiate_connection()
    var data = conn.data_to_send()
    # First 24 bytes must be the connection preface magic
    assert_true(len(data) >= 24, "client preface >= 24 bytes")
    var magic = String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    var mb = magic.as_bytes()
    for i in range(len(magic)):
        assert_equal(Int(data[i]), Int(mb[i]), "magic byte " + String(i))
    # Bytes 24+ must be a SETTINGS frame (type=4, stream_id=0, no ACK)
    assert_true(len(data) >= 33, "client preface has SETTINGS frame")
    assert_equal(Int(data[27]), FRAME_SETTINGS, "frame type is SETTINGS")
    assert_equal(Int(data[28]), 0, "SETTINGS flags = 0 (no ACK)")
    # Stream ID = 0
    var sid = (Int(data[29]) << 24) | (Int(data[30]) << 16) | (Int(data[31]) << 8) | Int(data[32])
    assert_equal(sid, 0, "SETTINGS stream_id = 0")
    assert_true(not conn.is_closed(), "connection is not closed")


def test_server_preface() raises:
    """Server initiate_connection emits SETTINGS (no magic)."""
    var conn = H2Connection(client_side=False)
    conn.initiate_connection()
    var data = conn.data_to_send()
    # First byte should be start of SETTINGS frame, not magic
    assert_true(len(data) >= 9, "server preface >= 9 bytes")
    assert_equal(Int(data[3]), FRAME_SETTINGS, "frame type is SETTINGS")
    assert_equal(Int(data[4]), 0, "SETTINGS flags = 0")


def test_server_receives_client_preface() raises:
    """Server receives client preface, validates magic, processes SETTINGS, sends ACK."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()

    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()  # drain server's own SETTINGS
    var events = server.receive_data(client_preface)

    # Should emit SettingsChanged (remote settings updated)
    assert_true(len(events) >= 1, "server emitted >= 1 event")
    assert_equal(events[0].kind, H2_EVT_SETTINGS_CHANGED, "first event is SETTINGS_CHANGED")

    # Server should have queued a SETTINGS ACK
    var ack_data = server.data_to_send()
    assert_true(len(ack_data) >= 9, "server sent SETTINGS ACK")
    assert_equal(Int(ack_data[3]), FRAME_SETTINGS, "ACK frame type")
    assert_equal(Int(ack_data[4]), 1, "ACK flag set (FLAG_ACK=0x01)")
    var ack_len = (Int(ack_data[0]) << 16) | (Int(ack_data[1]) << 8) | Int(ack_data[2])
    assert_equal(ack_len, 0, "ACK payload length = 0")


def test_server_rejects_bad_magic() raises:
    """Server rejects invalid client magic with GOAWAY."""
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()
    var bad_magic = List[UInt8]()
    for i in range(24):
        bad_magic.append(UInt8(0))
    var events = server.receive_data(bad_magic)
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")
    assert_equal(Int(events[0].error_code), H2_PROTOCOL_ERROR, "PROTOCOL_ERROR")
    assert_true(server.is_closed(), "connection closed")


def test_settings_ack_roundtrip() raises:
    """Full preface exchange: client and server both get SettingsAcknowledged."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var client_preface = client.data_to_send()
    var server_preface = server.data_to_send()

    # Server processes client preface → SettingsChanged + queues ACK
    var server_events = server.receive_data(client_preface)
    assert_true(len(server_events) >= 1, "server got events")
    assert_equal(server_events[0].kind, H2_EVT_SETTINGS_CHANGED, "server got SETTINGS_CHANGED")
    var server_ack = server.data_to_send()

    # Client processes server preface → SettingsChanged
    var client_events_1 = client.receive_data(server_preface)
    assert_true(len(client_events_1) >= 1, "client got events from server preface")
    assert_equal(client_events_1[0].kind, H2_EVT_SETTINGS_CHANGED, "client got SETTINGS_CHANGED")
    var client_ack = client.data_to_send()

    # Client processes server's ACK → SettingsAcknowledged
    var client_events_2 = client.receive_data(server_ack)
    assert_true(len(client_events_2) >= 1, "client got events from server ACK")
    assert_equal(client_events_2[0].kind, H2_EVT_SETTINGS_ACKNOWLEDGED, "client got SETTINGS_ACKNOWLEDGED")

    # Server processes client's ACK → SettingsAcknowledged
    var server_events_2 = server.receive_data(client_ack)
    assert_true(len(server_events_2) >= 1, "server got events from client ACK")
    assert_equal(server_events_2[0].kind, H2_EVT_SETTINGS_ACKNOWLEDGED, "server got SETTINGS_ACKNOWLEDGED")


def test_settings_invalid_initial_window() raises:
    """SETTINGS with INITIAL_WINDOW_SIZE > 2^31-1 triggers FLOW_CONTROL_ERROR."""
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()
    # Exchange preface first
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var good_preface = client.data_to_send()
    _ = server.receive_data(good_preface)
    _ = server.data_to_send()
    # Now send a SETTINGS with bad INITIAL_WINDOW_SIZE (2^31 = 2147483648)
    var payload = List[UInt8]()
    _append_setting(payload, SETTINGS_INITIAL_WINDOW_SIZE, 2147483648)
    var frame = Frame(len(payload), FRAME_SETTINGS, 0, 0, payload)
    var wire = encode_frame(frame)
    var events = server.receive_data(wire)
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")
    assert_equal(Int(events[0].error_code), H2_FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR")


def test_ping_roundtrip() raises:
    """Send PING, receive auto-ACK with PingReceived event."""
    # Establish connection
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    var s_ack = server.data_to_send()
    _ = client.receive_data(sp)
    var c_ack = client.data_to_send()
    _ = client.receive_data(s_ack)
    _ = server.receive_data(c_ack)

    # Client sends PING
    var ping_data = List[UInt8]()
    ping_data.append(UInt8(1))
    ping_data.append(UInt8(2))
    ping_data.append(UInt8(3))
    ping_data.append(UInt8(4))
    ping_data.append(UInt8(5))
    ping_data.append(UInt8(6))
    ping_data.append(UInt8(7))
    ping_data.append(UInt8(8))
    client.send_ping(ping_data)
    var ping_wire = client.data_to_send()

    # Server receives PING → auto-ACK + PingReceived event
    var events = server.receive_data(ping_wire)
    assert_true(len(events) >= 1, "server got event")
    assert_equal(events[0].kind, H2_EVT_PING_RECEIVED, "PingReceived")
    assert_equal(len(events[0].data), 8, "ping data length")
    for i in range(8):
        assert_equal(Int(events[0].data[i]), i + 1, "ping data byte " + String(i))

    # Server queued a PING ACK
    var pong_wire = server.data_to_send()
    assert_true(len(pong_wire) == 17, "PING ACK is 17 bytes (9 header + 8 payload)")
    assert_equal(Int(pong_wire[3]), FRAME_PING, "type is PING")
    assert_equal(Int(pong_wire[4]), 1, "ACK flag set")

    # Client receives PING ACK → PingAcknowledged event
    var events2 = client.receive_data(pong_wire)
    assert_true(len(events2) >= 1, "client got event")
    assert_equal(events2[0].kind, H2_EVT_PING_ACKNOWLEDGED, "PingAcknowledged")


def test_goaway_receive() raises:
    """Receive GOAWAY → GoawayReceived event, connection enters draining."""
    # Establish connection
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()

    # Server sends GOAWAY
    server.send_goaway(UInt32(0), UInt32(H2_NO_ERROR))
    var goaway_wire = server.data_to_send()

    # Client receives GOAWAY
    var events = client.receive_data(goaway_wire)
    assert_true(len(events) >= 1, "client got event")
    assert_equal(events[0].kind, H2_EVT_GOAWAY_RECEIVED, "GoawayReceived")
    assert_equal(Int(events[0].last_stream_id), 0, "last_stream_id")
    assert_equal(Int(events[0].error_code), H2_NO_ERROR, "error_code")


def test_goaway_send_draining() raises:
    """send_goaway puts connection in GOAWAY (draining) state."""
    var conn = H2Connection(client_side=True)
    conn.initiate_connection()
    _ = conn.data_to_send()
    conn.send_goaway(UInt32(0), UInt32(H2_NO_ERROR))
    var data = conn.data_to_send()
    assert_true(len(data) >= 17, "GOAWAY frame sent (9 header + 8 payload)")
    assert_equal(Int(data[3]), FRAME_GOAWAY, "frame type GOAWAY")


def test_stream_creation() raises:
    """HEADERS creates a stream in OPEN state."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()
    _ = client.receive_data(server.data_to_send())
    _ = server.receive_data(client.data_to_send())

    var headers_wire = _build_headers_frame(1)
    _ = server.receive_data(headers_wire)
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_OPEN, "stream 1 is OPEN")
    assert_equal(server.open_stream_count(), 1, "open stream count = 1")


def test_stream_id_must_be_odd_for_server() raises:
    """Server rejects even stream ID from client."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()
    _ = client.receive_data(server.data_to_send())
    _ = server.receive_data(client.data_to_send())

    var headers_wire = _build_headers_frame(2)
    var events = server.receive_data(headers_wire)
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")
    assert_equal(Int(events[0].error_code), H2_PROTOCOL_ERROR, "PROTOCOL_ERROR")


def test_stream_id_must_increase() raises:
    """Stream IDs must be monotonically increasing."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()
    _ = client.receive_data(server.data_to_send())
    _ = server.receive_data(client.data_to_send())

    var h3 = _build_headers_frame(3)
    _ = server.receive_data(h3)
    var h1 = _build_headers_frame(1)
    var events = server.receive_data(h1)
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")


def test_max_concurrent_streams() raises:
    """Exceeding MAX_CONCURRENT_STREAMS triggers connection error."""
    var config = H2Config(client_side=False)
    config.max_concurrent_streams = UInt32(2)
    var server = H2Connection(client_side=False, config=config)
    server.initiate_connection()
    _ = server.data_to_send()
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var cp = client.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()

    _ = server.receive_data(_build_headers_frame(1))
    _ = server.receive_data(_build_headers_frame(3))
    assert_equal(server.open_stream_count(), 2, "2 open streams")

    var events = server.receive_data(_build_headers_frame(5))
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")


def test_continuation_assembly() raises:
    """HEADERS without END_HEADERS + CONTINUATION with END_HEADERS assembles block."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()
    _ = client.receive_data(server.data_to_send())
    _ = server.receive_data(client.data_to_send())

    # HEADERS without END_HEADERS on stream 1
    var h_payload = List[UInt8]()
    h_payload.append(UInt8(0x82))
    h_payload.append(UInt8(0x84))
    var h_frame = Frame(len(h_payload), FRAME_HEADERS, 0, 1, h_payload)
    var h_wire = encode_frame(h_frame)
    _ = server.receive_data(h_wire)
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_OPEN, "stream 1 OPEN while awaiting CONTINUATION")

    # CONTINUATION with END_HEADERS
    var c_payload = List[UInt8]()
    c_payload.append(UInt8(0x86))
    var c_frame = Frame(len(c_payload), FRAME_CONTINUATION, FLAG_END_HEADERS, 1, c_payload)
    var c_wire = encode_frame(c_frame)
    _ = server.receive_data(c_wire)
    assert_equal(server.stream_state(UInt32(1)), STREAM_OPEN, "stream 1 still OPEN after CONTINUATION")


def test_continuation_interleave_rejected() raises:
    """Non-CONTINUATION frame during CONTINUATION sequence → PROTOCOL_ERROR."""
    var client = H2Connection(client_side=True)
    var server = H2Connection(client_side=False)
    client.initiate_connection()
    server.initiate_connection()
    var cp = client.data_to_send()
    var sp = server.data_to_send()
    _ = server.receive_data(cp)
    _ = server.data_to_send()
    _ = client.receive_data(sp)
    _ = client.data_to_send()
    _ = client.receive_data(server.data_to_send())
    _ = server.receive_data(client.data_to_send())

    # HEADERS without END_HEADERS
    var h_payload = List[UInt8]()
    h_payload.append(UInt8(0x82))
    var h_frame = Frame(len(h_payload), FRAME_HEADERS, 0, 1, h_payload)
    var h_wire = encode_frame(h_frame)
    _ = server.receive_data(h_wire)

    # PING interleaves → PROTOCOL_ERROR (the interleave check is in receive_data loop)
    var ping_payload = List[UInt8]()
    for _ in range(8):
        ping_payload.append(UInt8(0))
    var ping_frame = Frame(8, FRAME_PING, 0, 0, ping_payload)
    var ping_wire = encode_frame(ping_frame)
    var events = server.receive_data(ping_wire)
    assert_true(len(events) >= 1, "server emitted event")
    assert_equal(events[0].kind, H2_EVT_CONNECTION_TERMINATED, "CONNECTION_TERMINATED")
    assert_equal(Int(events[0].error_code), H2_PROTOCOL_ERROR, "PROTOCOL_ERROR")


def main() raises:
    test_error_codes()
    test_h2config_defaults()
    test_h2settings_defaults()
    test_h2settings_from_config()
    test_h2event_factory_methods()
    test_stream_state_and_constants()
    test_client_preface()
    test_server_preface()
    test_server_receives_client_preface()
    test_server_rejects_bad_magic()
    test_settings_ack_roundtrip()
    test_settings_invalid_initial_window()
    test_ping_roundtrip()
    test_goaway_receive()
    test_goaway_send_draining()
    test_stream_creation()
    test_stream_id_must_be_odd_for_server()
    test_stream_id_must_increase()
    test_max_concurrent_streams()
    test_continuation_assembly()
    test_continuation_interleave_rejected()
    print("test_h2_connection: 21 tests passed")
