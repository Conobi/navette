# conformance/tests/test_h2_stream.mojo
#
# HC-4b: HTTP/2 stream data path tests.
from lib.test_util import assert_true, assert_equal, hex_decode, hex_encode
from lib.http2.connection import (
    H2Config,
    H2Settings,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_SETTINGS_ACKNOWLEDGED,
    H2_EVT_SETTINGS_CHANGED,
    H2_EVT_PING_RECEIVED,
    H2_EVT_PING_ACKNOWLEDGED,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_WINDOW_UPDATED,
    H2_EVT_CONNECTION_TERMINATED,
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
    decode_frame,
    H2_NO_ERROR,
    H2_PROTOCOL_ERROR,
    H2_FLOW_CONTROL_ERROR,
    H2_COMPRESSION_ERROR,
    H2_STREAM_CLOSED,
    H2_CANCEL,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_CONTINUATION,
    FRAME_WINDOW_UPDATE,
    FLAG_END_STREAM,
    FLAG_ACK,
    FLAG_END_HEADERS,
)
from lib.http2.hpack import HpackEncoder, HpackDecoder, HpackConfig
from lib.http1.types import Header


def test_stream_state_new_fields() raises:
    """StreamState has headers_end_stream and data_received fields."""
    var s = StreamState()
    assert_true(not s.headers_end_stream, "default headers_end_stream")
    assert_true(not s.data_received, "default data_received")
    # Copy preserves new fields
    var s2 = StreamState(other=s)
    assert_true(not s2.headers_end_stream, "copy headers_end_stream")
    assert_true(not s2.data_received, "copy data_received")
    # Move preserves new fields
    var s3 = StreamState(take=s2^)
    assert_true(not s3.headers_end_stream, "move headers_end_stream")
    assert_true(not s3.data_received, "move data_received")


def _server_conn_after_preface() raises -> H2Connection:
    """Create a server conn that has received client preface."""
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var events = server.receive_data(client_preface)
    _ = server.data_to_send()
    return server^


def _build_hpack_headers_frame(stream_id: Int, headers: List[Header], end_headers: Bool = True, end_stream: Bool = False) -> List[UInt8]:
    """Build a HEADERS frame with HPACK-encoded header block."""
    var encoder = HpackEncoder(HpackConfig(use_huffman=False))
    var block = encoder.encode(headers)
    var flags = 0
    if end_headers:
        flags = flags | 0x04  # END_HEADERS
    if end_stream:
        flags = flags | 0x01  # END_STREAM
    var frame = Frame(len(block), FRAME_HEADERS, flags, stream_id, block)
    return encode_frame(frame)


def test_hpack_decode_request_received() raises:
    """Server decodes HPACK headers from HEADERS frame, emits RequestReceived."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var frame_bytes = _build_hpack_headers_frame(1, req_headers)
    var events = server.receive_data(frame_bytes)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_REQUEST_RECEIVED:
            found = True
            assert_equal(Int(events[i].stream_id), 1, "stream_id")
            assert_equal(len(events[i].headers), 4, "header count")
            assert_true(events[i].headers[0].name == ":method", "h0 name")
            assert_true(events[i].headers[0].value == "GET", "h0 value")
            assert_true(events[i].headers[1].name == ":path", "h1 name")
            assert_true(events[i].headers[1].value == "/", "h1 value")
            assert_true(not events[i].stream_ended, "stream_ended=False")
    assert_true(found, "RequestReceived event emitted")


def test_hpack_decode_end_stream_half_close() raises:
    """HEADERS with END_STREAM transitions stream to HALF_CLOSED_REMOTE."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var frame_bytes = _build_hpack_headers_frame(1, req_headers, end_stream=True)
    var events = server.receive_data(frame_bytes)
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_HALF_CLOSED_REMOTE, "half-closed remote after END_STREAM")
    for i in range(len(events)):
        if events[i].kind == H2_EVT_REQUEST_RECEIVED:
            assert_true(events[i].stream_ended, "stream_ended=True")


def test_hpack_decode_compression_error() raises:
    """Invalid HPACK block triggers COMPRESSION_ERROR."""
    var server = _server_conn_after_preface()
    # Invalid HPACK: overlong integer that never terminates
    var bad_block = List[UInt8]()
    bad_block.append(UInt8(0xFF))
    bad_block.append(UInt8(0xFF))
    bad_block.append(UInt8(0xFF))
    bad_block.append(UInt8(0xFF))
    bad_block.append(UInt8(0xFF))
    bad_block.append(UInt8(0x0F))
    var flags = 0x04  # END_HEADERS only
    var frame = Frame(len(bad_block), FRAME_HEADERS, flags, 1, bad_block)
    var frame_bytes = encode_frame(frame)
    var events = server.receive_data(frame_bytes)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_CONNECTION_TERMINATED:
            found = True
            assert_equal(Int(events[i].error_code), H2_COMPRESSION_ERROR, "COMPRESSION_ERROR")
    assert_true(found, "connection terminated on HPACK error")


def test_hpack_decode_continuation_assembly() raises:
    """HEADERS + CONTINUATION decoded after assembly, emits RequestReceived."""
    var server = _server_conn_after_preface()
    var encoder = HpackEncoder(HpackConfig(use_huffman=False))
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var block = encoder.encode(req_headers)
    # Split block: first 3 bytes in HEADERS, rest in CONTINUATION
    var split_point = 3
    var first_part = List[UInt8]()
    for i in range(split_point):
        first_part.append(block[i])
    var second_part = List[UInt8]()
    for i in range(split_point, len(block)):
        second_part.append(block[i])
    # HEADERS without END_HEADERS
    var hdr_frame = Frame(len(first_part), FRAME_HEADERS, 0, 1, first_part)
    var wire = encode_frame(hdr_frame)
    # CONTINUATION with END_HEADERS
    var cont_frame = Frame(len(second_part), FRAME_CONTINUATION, 0x04, 1, second_part)
    var cont_wire = encode_frame(cont_frame)
    for i in range(len(cont_wire)):
        wire.append(cont_wire[i])
    var events = server.receive_data(wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_REQUEST_RECEIVED:
            found = True
            assert_equal(Int(events[i].stream_id), 1, "stream_id")
            assert_equal(len(events[i].headers), 4, "header count after assembly")
            assert_true(events[i].headers[0].name == ":method", "h0 name")
            assert_true(events[i].headers[0].value == "GET", "h0 value")
    assert_true(found, "RequestReceived after CONTINUATION assembly")


def test_send_headers_client_request() raises:
    """Client send_headers encodes HPACK, queues HEADERS frame, creates stream."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _ = client.data_to_send()
    # Build server preface and feed to client
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()  # drain SETTINGS ACK
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), headers^, end_stream=True)
    var wire = client.data_to_send()
    # Decode the HEADERS frame
    assert_true(len(wire) > 9, "wire has frame header")
    var result = decode_frame(wire, 0)
    var frame = result[0].copy()
    assert_equal(frame.frame_type, FRAME_HEADERS, "frame type")
    assert_equal(frame.stream_id, 1, "stream_id")
    assert_true((frame.flags & FLAG_END_HEADERS) != 0, "END_HEADERS set")
    assert_true((frame.flags & FLAG_END_STREAM) != 0, "END_STREAM set")
    # Stream should exist and be half-closed local
    var state = client.stream_state(UInt32(1))
    assert_equal(state, STREAM_HALF_CLOSED_LOCAL, "half-closed local")
    assert_equal(client.open_stream_count(), 1, "1 active stream")


def test_send_headers_continuation_split() raises:
    """Large header block splits into HEADERS + CONTINUATION frames."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    _ = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()
    # Build headers large enough to exceed max_frame_size (16384)
    var headers = List[Header]()
    headers.append(Header(":method", "GET"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    for i in range(200):
        headers.append(Header("x-custom-" + String(i), "v" * 100))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    var wire = client.data_to_send()
    # First frame should be HEADERS without END_HEADERS
    var pos = 0
    var r1 = decode_frame(wire, pos)
    var f1 = r1[0].copy()
    assert_equal(f1.frame_type, FRAME_HEADERS, "first frame is HEADERS")
    assert_true((f1.flags & FLAG_END_HEADERS) == 0, "first frame lacks END_HEADERS")
    pos += r1[1]
    # There should be at least one CONTINUATION
    var last_is_end = False
    var cont_count = 0
    while pos < len(wire):
        var r = decode_frame(wire, pos)
        var f = r[0].copy()
        assert_equal(f.frame_type, FRAME_CONTINUATION, "subsequent frames are CONTINUATION")
        assert_equal(f.stream_id, 1, "CONTINUATION stream_id")
        cont_count += 1
        if (f.flags & FLAG_END_HEADERS) != 0:
            last_is_end = True
        pos += r[1]
    assert_true(cont_count >= 1, "at least 1 CONTINUATION")
    assert_true(last_is_end, "last CONTINUATION has END_HEADERS")


def test_client_receives_response_headers() raises:
    """Client receives ResponseReceived when server sends HEADERS on existing stream."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()
    # Client sends request
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), req_headers^, end_stream=True)
    var request_wire = client.data_to_send()
    # Server receives request
    _ = server.receive_data(request_wire)
    _ = server.data_to_send()
    # Server sends response
    var resp_headers = List[Header]()
    resp_headers.append(Header(":status", "200"))
    resp_headers.append(Header("content-type", "text/plain"))
    server.send_headers(UInt32(1), resp_headers^, end_stream=True)
    var response_wire = server.data_to_send()
    # Client receives response
    var cli_events = client.receive_data(response_wire)
    var found = False
    for i in range(len(cli_events)):
        if cli_events[i].kind == H2_EVT_RESPONSE_RECEIVED:
            found = True
            assert_equal(Int(cli_events[i].stream_id), 1, "stream_id")
            assert_true(cli_events[i].headers[0].name == ":status", "status header name")
            assert_true(cli_events[i].headers[0].value == "200", "status header value")
            assert_true(cli_events[i].stream_ended, "stream_ended=True")
    assert_true(found, "ResponseReceived event emitted")
    # Stream should be closed (both sides sent END_STREAM)
    var state = client.stream_state(UInt32(1))
    assert_equal(state, STREAM_CLOSED, "stream closed after both END_STREAM")


def test_inbound_data_received() raises:
    """Server receives DATA after HEADERS, emits DataReceived."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "POST"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    # Send DATA with body "hello"
    var body = List[UInt8]()
    body.append(UInt8(0x68))  # h
    body.append(UInt8(0x65))  # e
    body.append(UInt8(0x6C))  # l
    body.append(UInt8(0x6C))  # l
    body.append(UInt8(0x6F))  # o
    var data_frame = Frame(len(body), FRAME_DATA, 0, 1, body)
    var data_wire = encode_frame(data_frame)
    var events = server.receive_data(data_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_DATA_RECEIVED:
            found = True
            assert_equal(Int(events[i].stream_id), 1, "stream_id")
            assert_equal(len(events[i].data), 5, "data length")
            assert_equal(events[i].flow_controlled_length, 5, "flow_controlled_length")
            assert_true(not events[i].stream_ended, "stream_ended=False")
    assert_true(found, "DataReceived event emitted")


def test_inbound_data_end_stream() raises:
    """DATA with END_STREAM transitions to HALF_CLOSED_REMOTE."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "POST"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    var body = List[UInt8]()
    body.append(UInt8(0x68))
    var data_frame = Frame(len(body), FRAME_DATA, FLAG_END_STREAM, 1, body)
    var data_wire = encode_frame(data_frame)
    var events = server.receive_data(data_wire)
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_HALF_CLOSED_REMOTE, "half-closed remote")
    for i in range(len(events)):
        if events[i].kind == H2_EVT_DATA_RECEIVED:
            assert_true(events[i].stream_ended, "stream_ended=True")


def test_send_data() raises:
    """Client sends DATA after HEADERS, wire contains DATA frame."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    _ = client.data_to_send()
    var body = List[UInt8]()
    for i in range(5):
        body.append(UInt8(0x41 + i))  # ABCDE
    client.send_data(UInt32(1), body^, end_stream=True)
    var wire = client.data_to_send()
    var r = decode_frame(wire, 0)
    var f = r[0].copy()
    assert_equal(f.frame_type, FRAME_DATA, "frame type")
    assert_equal(f.stream_id, 1, "stream_id")
    assert_true((f.flags & FLAG_END_STREAM) != 0, "END_STREAM set")
    assert_equal(len(f.payload), 5, "payload length")
    var state = client.stream_state(UInt32(1))
    assert_equal(state, STREAM_HALF_CLOSED_LOCAL, "half-closed local")


def test_send_data_window_exhaustion() raises:
    """Send_data raises when send window is exhausted."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    _ = client.data_to_send()
    # Fill connection window (65535 bytes default)
    var body = List[UInt8]()
    for _ in range(65535):
        body.append(UInt8(0x42))
    client.send_data(UInt32(1), body^, end_stream=False)
    _ = client.data_to_send()
    # Next send should fail
    var small_body = List[UInt8]()
    small_body.append(UInt8(0x43))
    var raised = False
    try:
        client.send_data(UInt32(1), small_body^, end_stream=False)
    except:
        raised = True
    assert_true(raised, "send_data raises on window exhaustion")


def test_inbound_data_on_unknown_stream() raises:
    """DATA on unknown stream triggers connection error."""
    var server = _server_conn_after_preface()
    var body = List[UInt8]()
    body.append(UInt8(0x00))
    var data_frame = Frame(len(body), FRAME_DATA, 0, 1, body)
    var data_wire = encode_frame(data_frame)
    var events = server.receive_data(data_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_CONNECTION_TERMINATED:
            found = True
    assert_true(found, "connection error on DATA to unknown stream")


def test_stream_flow_control_window_update() raises:
    """Acknowledge_received_data emits stream-level WINDOW_UPDATE."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "POST"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    # Send multiple DATA frames totalling 40000 bytes (each <= 16384 max frame size)
    var total_sent = 0
    var chunk_size = 16384
    while total_sent < 40000:
        var this_chunk = chunk_size
        if total_sent + this_chunk > 40000:
            this_chunk = 40000 - total_sent
        var body = List[UInt8]()
        for _ in range(this_chunk):
            body.append(UInt8(0x41))
        var data_frame = Frame(len(body), FRAME_DATA, 0, 1, body)
        var data_wire = encode_frame(data_frame)
        _ = server.receive_data(data_wire)
        _ = server.data_to_send()
        total_sent += this_chunk
    # Acknowledge the data
    server.acknowledge_received_data(40000, UInt32(1))
    var wire = server.data_to_send()
    # Should contain WINDOW_UPDATE frames (connection + stream)
    var conn_wu = False
    var stream_wu = False
    var pos = 0
    while pos < len(wire):
        var r = decode_frame(wire, pos)
        var f = r[0].copy()
        if r[1] == 0:
            break
        if f.frame_type == FRAME_WINDOW_UPDATE:
            if f.stream_id == 0:
                conn_wu = True
            elif f.stream_id == 1:
                stream_wu = True
        pos += r[1]
    assert_true(conn_wu, "connection-level WINDOW_UPDATE emitted")
    assert_true(stream_wu, "stream-level WINDOW_UPDATE emitted")


def test_inbound_trailers() raises:
    """Server receives trailer HEADERS after DATA, emits TrailersReceived."""
    var server = _server_conn_after_preface()
    # HEADERS (no END_STREAM)
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "POST"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    # DATA
    var body = List[UInt8]()
    body.append(UInt8(0x68))
    var data_frame = Frame(len(body), FRAME_DATA, 0, 1, body)
    var data_wire = encode_frame(data_frame)
    _ = server.receive_data(data_wire)
    _ = server.data_to_send()
    # Trailer HEADERS (END_STREAM + END_HEADERS)
    var trailer_headers = List[Header]()
    trailer_headers.append(Header("x-checksum", "abc123"))
    var trailer_wire = _build_hpack_headers_frame(1, trailer_headers, end_stream=True)
    var events = server.receive_data(trailer_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_TRAILERS_RECEIVED:
            found = True
            assert_equal(Int(events[i].stream_id), 1, "stream_id")
            assert_equal(len(events[i].headers), 1, "trailer count")
            assert_true(events[i].headers[0].name == "x-checksum", "trailer name")
            assert_true(events[i].headers[0].value == "abc123", "trailer value")
            assert_true(events[i].stream_ended, "stream_ended=True on trailers")
    assert_true(found, "TrailersReceived event emitted")
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_HALF_CLOSED_REMOTE, "half-closed remote after trailers")


def test_inbound_rst_stream() raises:
    """Server receives RST_STREAM, emits StreamReset, closes stream."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    assert_equal(server.open_stream_count(), 1, "1 active before RST")
    # Send RST_STREAM for stream 1 with CANCEL (error code 8)
    var payload = List[UInt8]()
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x08))  # H2_CANCEL = 8
    var rst_frame = Frame(4, FRAME_RST_STREAM, 0, 1, payload)
    var rst_wire = encode_frame(rst_frame)
    var events = server.receive_data(rst_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_STREAM_RESET:
            found = True
            assert_equal(Int(events[i].stream_id), 1, "stream_id")
            assert_equal(Int(events[i].error_code), 8, "error_code=CANCEL")
    assert_true(found, "StreamReset event emitted")
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_CLOSED, "stream closed")
    assert_equal(server.open_stream_count(), 0, "0 active after RST")


def test_rst_stream_on_idle() raises:
    """RST_STREAM on idle stream triggers connection error."""
    var server = _server_conn_after_preface()
    var payload = List[UInt8]()
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x00))
    payload.append(UInt8(0x00))
    var rst_frame = Frame(4, FRAME_RST_STREAM, 0, 1, payload)
    var rst_wire = encode_frame(rst_frame)
    var events = server.receive_data(rst_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_CONNECTION_TERMINATED:
            found = True
            assert_equal(Int(events[i].error_code), H2_PROTOCOL_ERROR, "PROTOCOL_ERROR")
    assert_true(found, "connection error on RST_STREAM to idle stream")


def test_send_rst_stream_closes_stream() raises:
    """Send_rst_stream closes the stream and decrements active count."""
    var server = _server_conn_after_preface()
    var req_headers = List[Header]()
    req_headers.append(Header(":method", "GET"))
    req_headers.append(Header(":path", "/"))
    req_headers.append(Header(":scheme", "https"))
    req_headers.append(Header(":authority", "example.com"))
    var headers_wire = _build_hpack_headers_frame(1, req_headers)
    _ = server.receive_data(headers_wire)
    _ = server.data_to_send()
    assert_equal(server.open_stream_count(), 1, "1 active before RST")
    server.send_rst_stream(UInt32(1), UInt32(8))  # CANCEL
    var wire = server.data_to_send()
    assert_true(len(wire) > 0, "RST_STREAM frame queued")
    var state = server.stream_state(UInt32(1))
    assert_equal(state, STREAM_CLOSED, "stream closed")
    assert_equal(server.open_stream_count(), 0, "0 active after RST")


def test_settings_initial_window_size_adjusts_streams() raises:
    """SETTINGS INITIAL_WINDOW_SIZE change adjusts open stream send windows."""
    var client = H2Connection(client_side=True)
    client.initiate_connection()
    var client_preface = client.data_to_send()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    var server_preface = server.data_to_send()
    _ = client.receive_data(server_preface)
    _ = client.data_to_send()
    _ = server.receive_data(client_preface)
    _ = server.data_to_send()
    # Client creates stream 1 (no END_STREAM, stays OPEN)
    var headers = List[Header]()
    headers.append(Header(":method", "POST"))
    headers.append(Header(":path", "/"))
    headers.append(Header(":scheme", "https"))
    headers.append(Header(":authority", "example.com"))
    client.send_headers(UInt32(1), headers^, end_stream=False)
    _ = client.data_to_send()
    # Feed SETTINGS from server with smaller INITIAL_WINDOW_SIZE (100)
    var settings_payload = List[UInt8]()
    _append_setting(settings_payload, SETTINGS_INITIAL_WINDOW_SIZE, 100)
    var settings_frame = Frame(len(settings_payload), FRAME_SETTINGS, 0, 0, settings_payload)
    var settings_wire = encode_frame(settings_frame)
    _ = client.receive_data(settings_wire)
    _ = client.data_to_send()
    # Stream 1 send_window was 65535, delta = 100 - 65535 = -65435
    # New send_window = 65535 + (-65435) = 100
    # Try sending 101 bytes — should fail (stream window)
    var body_101 = List[UInt8]()
    for _ in range(101):
        body_101.append(UInt8(0x41))
    var raised = False
    try:
        client.send_data(UInt32(1), body_101, end_stream=False)
    except:
        raised = True
    assert_true(raised, "send_data fails when stream window < data size after SETTINGS adjustment")
    # But 100 bytes should succeed
    var body_100 = List[UInt8]()
    for _ in range(100):
        body_100.append(UInt8(0x41))
    client.send_data(UInt32(1), body_100, end_stream=False)
    # No exception = pass


def test_settings_max_frame_size_invalid() raises:
    """SETTINGS MAX_FRAME_SIZE outside valid range triggers PROTOCOL_ERROR."""
    var server = _server_conn_after_preface()
    # Send MAX_FRAME_SIZE = 100 (below 16384 minimum)
    var settings_payload = List[UInt8]()
    _append_setting(settings_payload, 5, 100)  # SETTINGS_MAX_FRAME_SIZE = id 5
    var settings_frame = Frame(len(settings_payload), FRAME_SETTINGS, 0, 0, settings_payload)
    var settings_wire = encode_frame(settings_frame)
    var events = server.receive_data(settings_wire)
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_CONNECTION_TERMINATED:
            found = True
            assert_equal(Int(events[i].error_code), H2_PROTOCOL_ERROR, "PROTOCOL_ERROR for invalid MAX_FRAME_SIZE")
    assert_true(found, "connection error on invalid MAX_FRAME_SIZE")


def main() raises:
    test_stream_state_new_fields()
    test_hpack_decode_request_received()
    test_hpack_decode_end_stream_half_close()
    test_hpack_decode_compression_error()
    test_hpack_decode_continuation_assembly()
    test_send_headers_client_request()
    test_send_headers_continuation_split()
    test_client_receives_response_headers()
    test_inbound_data_received()
    test_inbound_data_end_stream()
    test_inbound_data_on_unknown_stream()
    test_send_data()
    test_send_data_window_exhaustion()
    test_stream_flow_control_window_update()
    test_inbound_trailers()
    test_inbound_rst_stream()
    test_rst_stream_on_idle()
    test_send_rst_stream_closes_stream()
    test_settings_initial_window_size_adjusts_streams()
    test_settings_max_frame_size_invalid()
    print("All tests passed.")
