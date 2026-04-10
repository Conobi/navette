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


def main() raises:
    test_stream_state_new_fields()
    test_hpack_decode_request_received()
    test_hpack_decode_end_stream_half_close()
    test_hpack_decode_compression_error()
    test_hpack_decode_continuation_assembly()
    test_send_headers_client_request()
    test_send_headers_continuation_split()
    print("All tests passed.")
