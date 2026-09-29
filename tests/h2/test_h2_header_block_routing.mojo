"""H2Connection: what a HEADERS block on an existing stream means.

Server side, a second block on an open stream is trailers, never a new
request; client side, the block after the final (non-1xx) response is
trailers, and a block on a stream it reset or that already ended is
dropped or reset, never delivered. Every dropped block is still
HPACK-decoded, checked with a follow-up block that references the
dynamic table.
"""

from navette.h2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_RESET,
    STREAM_HALF_CLOSED_REMOTE,
)
from navette.h2.frame import (
    Frame,
    decode_frame,
    encode_frame_into,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_GOAWAY,
    FRAME_CONTINUATION,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    H2_PROTOCOL_ERROR,
    H2_CANCEL,
    H2_STREAM_CLOSED,
)
from navette.h2.hpack import HpackEncoder
from navette.h2.header import Header
from tests._test_util import assert_true, assert_equal_int


# ── Wire helpers ─────────────────────────────────────────────────────────


def _frame(ft: Int, flags: Int, sid: Int, payload: List[Byte]) -> List[Byte]:
    var out = List[Byte]()
    encode_frame_into(Frame(len(payload), ft, flags, sid, payload), out)
    return out^


def _split(sid: Int, block: List[Byte], end_stream: Bool) -> List[Byte]:
    """HEADERS without END_HEADERS carrying half of `block`, then CONTINUATION(END_HEADERS) with the rest."""
    var half = len(block) // 2
    var wire = _frame(FRAME_HEADERS, FLAG_END_STREAM if end_stream else 0, sid, List[Byte](block[:half]))
    wire.extend(Span(_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, sid, List[Byte](block[half:]))))
    return wire^


def _req(method: String, path: String) -> List[Header]:
    var h = List[Header]()
    h.append(Header(":method", method))
    h.append(Header(":scheme", "https"))
    h.append(Header(":path", path))
    h.append(Header(":authority", "example.test"))
    return h^


def _status(code: String) -> List[Header]:
    var h = List[Header]()
    h.append(Header(":status", code))
    return h^


def _one(name: String, value: String) -> List[Header]:
    var h = List[Header]()
    h.append(Header(name, value))
    return h^


def _server() raises -> H2Connection:
    """A server connection past the preface, its own SETTINGS already drained."""
    var srv = H2Connection(client_side=False, config=H2Config(client_side=False))
    srv.initiate_connection()
    var pre = List[Byte]()
    pre.extend(String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").as_bytes())
    pre.extend(Span(_frame(FRAME_SETTINGS, 0, 0, List[Byte]())))
    _ = srv.receive_data(pre)
    _ = srv.data_to_send()
    return srv^


def _client() raises -> H2Connection:
    var cli = H2Connection(client_side=True)
    cli.initiate_connection()
    _ = cli.receive_data(_frame(FRAME_SETTINGS, 0, 0, List[Byte]()))
    _ = cli.data_to_send()
    return cli^


def _frames(wire: List[Byte]) -> List[Frame]:
    var out = List[Frame]()
    var pos = 0
    while pos < len(wire):
        var r = decode_frame(wire, pos)
        if r[1] == 0:
            break
        out.append(r[0].copy())
        pos += r[1]
    return out^


def _code(f: Frame) -> Int:
    """Error code of a RST_STREAM (bytes 0..4) or GOAWAY (bytes 4..8)."""
    var o = 4 if f.frame_type == FRAME_GOAWAY else 0
    return (Int(f.payload[o]) << 24) | (Int(f.payload[o + 1]) << 16) | (Int(f.payload[o + 2]) << 8) | Int(f.payload[o + 3])


def _rst_count(frames: List[Frame], sid: Int) -> Int:
    var n = 0
    for ref f in frames:
        if f.frame_type == FRAME_RST_STREAM and f.stream_id == sid:
            n += 1
    return n


def _rst_code(frames: List[Frame], sid: Int) -> Int:
    for ref f in frames:
        if f.frame_type == FRAME_RST_STREAM and f.stream_id == sid:
            return _code(f)
    return -1


def _kind(events: List[H2Event], kind: Int) -> Int:
    var n = 0
    for ref e in events:
        if e.kind == kind:
            n += 1
    return n


def _has_header(events: List[H2Event], kind: Int, name: String, value: String) -> Bool:
    for ref e in events:
        if e.kind == kind:
            for ref h in e.headers:
                if h.name == name and h.value == value:
                    return True
    return False


# ── Server: a second block on an open stream is trailers ─────────────────


def test_repeated_header_blocks_are_not_new_requests() raises:
    """HEADERS(END_HEADERS) then 50 x [HEADERS + CONTINUATION] on one stream: one request, one PROTOCOL_ERROR reset, HPACK in sync."""
    var srv = _server()
    var enc = HpackEncoder()
    var ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    assert_equal_int(_kind(ev, H2_EVT_REQUEST_RECEIVED), 1, "the request is delivered once")
    var all = List[H2Event]()
    for i in range(50):
        var block = enc.encode(_one("x-probe", String(i)))  # a new dynamic-table entry each time
        all.extend(srv.receive_data(_split(1, block, end_stream=False)))
    assert_equal_int(_kind(all, H2_EVT_REQUEST_RECEIVED), 0, "no further request events")
    assert_equal_int(_kind(all, H2_EVT_RESPONSE_RECEIVED), 0, "no response events on a server")
    assert_equal_int(_kind(all, H2_EVT_STREAM_RESET), 1, "the stream is reset once")
    assert_true(not srv.is_closed(), "a stream error, not a connection error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_rst_count(out, 1), 1, "one RST_STREAM")
    assert_equal_int(_rst_code(out, 1), H2_PROTOCOL_ERROR, "trailers without END_STREAM are malformed (RFC 9113 Section 8.1)")
    assert_equal_int(srv.open_stream_count(), 0, "the slot is released")
    var next_req = _req("GET", "/next")
    next_req.append(Header("x-probe", "49"))
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(next_req)))
    assert_equal_int(_kind(ev, H2_EVT_REQUEST_RECEIVED), 1, "next stream accepted")
    assert_true(_has_header(ev, H2_EVT_REQUEST_RECEIVED, "x-probe", "49"), "HPACK in sync through every dropped block")
    print("PASS: test_repeated_header_blocks_are_not_new_requests")


def test_trailers_without_end_stream_is_stream_error() raises:
    """Trailers after DATA lacking END_STREAM, in one frame: stream PROTOCOL_ERROR, block still decoded."""
    var srv = _server()
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.receive_data(_frame(FRAME_DATA, 0, 1, List[Byte](length=10, fill=Byte(0x61))))
    _ = srv.data_to_send()
    var ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_one("x-t", "one"))))
    assert_equal_int(_kind(ev, H2_EVT_TRAILERS_RECEIVED), 0, "not delivered as trailers")
    assert_equal_int(_kind(ev, H2_EVT_STREAM_RESET), 1, "stream reset")
    assert_true(not srv.is_closed(), "a stream error, not a connection error")
    assert_equal_int(_rst_code(_frames(srv.data_to_send()), 1), H2_PROTOCOL_ERROR, "RST_STREAM(PROTOCOL_ERROR)")
    var next_req = _req("GET", "/next")
    next_req.append(Header("x-t", "one"))
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(next_req)))
    assert_true(_has_header(ev, H2_EVT_REQUEST_RECEIVED, "x-t", "one"), "HPACK in sync")
    print("PASS: test_trailers_without_end_stream_is_stream_error")


def _bodyless_trailers(split: Bool) raises:
    var srv = _server()
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/rpc"))))
    var block = enc.encode(_one("grpc-status", "0"))
    var wire = _split(1, block, end_stream=True) if split else _frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block)
    var ev = srv.receive_data(wire)
    assert_equal_int(len(ev), 1, "one event")
    assert_equal_int(_kind(ev, H2_EVT_TRAILERS_RECEIVED), 1, "trailers, not a response or a request")
    assert_true(_has_header(ev, H2_EVT_TRAILERS_RECEIVED, "grpc-status", "0"), "trailer fields delivered")
    assert_equal_int(srv.stream_state(1), STREAM_HALF_CLOSED_REMOTE, "the request is ended")
    assert_true(not srv.is_closed(), "connection open")
    assert_equal_int(_rst_count(_frames(srv.data_to_send()), 1), 0, "no reset")


def test_bodyless_request_trailers_are_trailers() raises:
    """gRPC shape: HEADERS, then HEADERS(END_STREAM) with no DATA between is trailers, whole or split."""
    _bodyless_trailers(split=False)
    _bodyless_trailers(split=True)
    print("PASS: test_bodyless_request_trailers_are_trailers")


def test_trailers_after_data_across_continuation() raises:
    var srv = _server()
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.receive_data(_frame(FRAME_DATA, 0, 1, List[Byte](length=10, fill=Byte(0x61))))
    var ev = srv.receive_data(_split(1, enc.encode(_one("x-t", "split")), end_stream=True))
    assert_equal_int(_kind(ev, H2_EVT_TRAILERS_RECEIVED), 1, "trailers delivered")
    assert_true(_has_header(ev, H2_EVT_TRAILERS_RECEIVED, "x-t", "split"), "fields intact")
    assert_equal_int(srv.stream_state(1), STREAM_HALF_CLOSED_REMOTE, "the request is ended")
    print("PASS: test_trailers_after_data_across_continuation")


def test_request_split_across_continuation_still_delivered() raises:
    var srv = _server()
    var enc = HpackEncoder()
    var ev = srv.receive_data(_split(1, enc.encode(_req("GET", "/split")), end_stream=True))
    assert_equal_int(_kind(ev, H2_EVT_REQUEST_RECEIVED), 1, "the request is delivered")
    assert_equal_int(srv.open_stream_count(), 1, "one stream")
    print("PASS: test_request_split_across_continuation_still_delivered")


# ── Client: late blocks on finished or reset streams ─────────────────────


def test_client_headers_after_end_stream_reset_once() raises:
    """20 x HEADERS(:status 500) after the server's END_STREAM: none delivered, one RST_STREAM(STREAM_CLOSED), HPACK in sync."""
    var cli = _client()
    var server_enc = HpackEncoder()
    cli.send_headers(1, _req("GET", "/"), end_stream=True)
    var ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, server_enc.encode(_status("200"))))
    assert_equal_int(_kind(ev, H2_EVT_RESPONSE_RECEIVED), 1, "the response is delivered")
    _ = cli.data_to_send()
    var all = List[H2Event]()
    for i in range(20):
        var h = _status("500")
        h.append(Header("x-late", String(i)))
        var block = server_enc.encode(h)
        if i % 2 == 0:
            all.extend(cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, block)))
        else:
            all.extend(cli.receive_data(_split(1, block, end_stream=False)))
    assert_equal_int(_kind(all, H2_EVT_RESPONSE_RECEIVED), 0, "late blocks are not delivered")
    assert_true(not cli.is_closed(), "a stream error, not a connection error")
    var out = _frames(cli.data_to_send())
    assert_equal_int(_rst_count(out, 1), 1, "one RST_STREAM, not one per block")
    assert_equal_int(_rst_code(out, 1), H2_STREAM_CLOSED, "STREAM_CLOSED")
    cli.send_headers(3, _req("GET", "/next"), end_stream=True)
    var h = _status("200")
    h.append(Header("x-late", "19"))
    ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, server_enc.encode(h)))
    assert_true(_has_header(ev, H2_EVT_RESPONSE_RECEIVED, "x-late", "19"), "HPACK in sync")
    print("PASS: test_client_headers_after_end_stream_reset_once")


def test_client_headers_after_own_reset_dropped() raises:
    """HEADERS arriving after the client reset the stream: decoded and dropped, not delivered or answered."""
    var cli = _client()
    var server_enc = HpackEncoder()
    cli.send_headers(1, _req("GET", "/"), end_stream=True)
    cli.send_headers(3, _req("GET", "/slow"), end_stream=True)
    cli.send_rst_stream(3, UInt32(H2_CANCEL))
    _ = cli.data_to_send()
    var ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, server_enc.encode(_one(":status", "204"))))
    ev.extend(cli.receive_data(_split(3, server_enc.encode(_one("x-late", "split")), end_stream=True)))
    assert_equal_int(len(ev), 0, "nothing delivered for the reset stream")
    assert_true(not cli.is_closed(), "connection open")
    assert_equal_int(len(_frames(cli.data_to_send())), 0, "no answer")
    var h = _status("200")
    h.append(Header("x-late", "split"))
    ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, server_enc.encode(h)))
    assert_true(_has_header(ev, H2_EVT_RESPONSE_RECEIVED, "x-late", "split"), "HPACK in sync")
    print("PASS: test_client_headers_after_own_reset_dropped")


def test_client_interim_then_final_response() raises:
    """1xx then the final response are both delivered, whole or split."""
    var cli = _client()
    var server_enc = HpackEncoder()
    cli.send_headers(1, _req("POST", "/"), end_stream=True)
    var ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, server_enc.encode(_status("100"))))
    ev.extend(cli.receive_data(_split(1, server_enc.encode(_status("103")), end_stream=False)))
    ev.extend(cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, server_enc.encode(_status("200")))))
    assert_equal_int(_kind(ev, H2_EVT_RESPONSE_RECEIVED), 3, "100, 103 and 200 delivered")
    assert_true(_has_header(ev, H2_EVT_RESPONSE_RECEIVED, ":status", "200"), "final response delivered")
    assert_equal_int(cli.open_stream_count(), 0, "stream closed")
    assert_true(not cli.is_closed(), "connection open")
    print("PASS: test_client_interim_then_final_response")


def test_client_response_trailers() raises:
    """Response trailers after DATA are delivered as trailers, whole or split."""
    for split in range(2):
        var cli = _client()
        var server_enc = HpackEncoder()
        cli.send_headers(1, _req("GET", "/"), end_stream=True)
        _ = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, server_enc.encode(_status("200"))))
        _ = cli.receive_data(_frame(FRAME_DATA, 0, 1, List[Byte](length=5, fill=Byte(0x62))))
        var block = server_enc.encode(_one("x-t", "end"))
        var wire = _split(1, block, end_stream=True) if split == 1 else _frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block)
        var ev = cli.receive_data(wire)
        assert_equal_int(_kind(ev, H2_EVT_TRAILERS_RECEIVED), 1, "trailers delivered")
        assert_equal_int(_kind(ev, H2_EVT_RESPONSE_RECEIVED), 0, "not a response")
        assert_equal_int(cli.open_stream_count(), 0, "stream closed")
    print("PASS: test_client_response_trailers")


def _wire(sid: Int, block: List[Byte], end_stream: Bool, split: Bool) -> List[Byte]:
    if split:
        return _split(sid, block, end_stream)
    return _frame(FRAME_HEADERS, FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0), sid, block)


def test_client_bodyless_response_trailers() raises:
    """HEADERS(:status 200) then HEADERS(END_STREAM) with no DATA: one response, then trailers, each whole or split."""
    for combo in range(4):
        var cli = _client()
        var server_enc = HpackEncoder()
        cli.send_headers(1, _req("POST", "/rpc"), end_stream=True)
        _ = cli.data_to_send()
        var ev = cli.receive_data(_wire(1, server_enc.encode(_status("200")), end_stream=False, split=combo & 1 != 0))
        ev.extend(cli.receive_data(_wire(1, server_enc.encode(_one("grpc-status", "0")), end_stream=True, split=combo & 2 != 0)))
        assert_equal_int(len(ev), 2, "two events")
        assert_true(ev[0].kind == H2_EVT_RESPONSE_RECEIVED, "the response first")
        assert_true(ev[1].kind == H2_EVT_TRAILERS_RECEIVED, "then trailers, not a second response")
        assert_true(_has_header(ev, H2_EVT_TRAILERS_RECEIVED, "grpc-status", "0"), "trailer fields delivered")
        assert_equal_int(cli.open_stream_count(), 0, "stream closed")
        assert_true(not cli.is_closed(), "connection open")
        assert_equal_int(_rst_count(_frames(cli.data_to_send()), 1), 0, "no reset")
    print("PASS: test_client_bodyless_response_trailers")


def test_client_interim_final_then_trailers() raises:
    """100 and 103 may repeat before the final response; the block after it is trailers."""
    var cli = _client()
    var server_enc = HpackEncoder()
    cli.send_headers(1, _req("POST", "/"), end_stream=True)
    var ev = cli.receive_data(_wire(1, server_enc.encode(_status("100")), end_stream=False, split=False))
    ev.extend(cli.receive_data(_wire(1, server_enc.encode(_status("103")), end_stream=False, split=True)))
    ev.extend(cli.receive_data(_wire(1, server_enc.encode(_status("103")), end_stream=False, split=False)))
    ev.extend(cli.receive_data(_wire(1, server_enc.encode(_status("200")), end_stream=False, split=True)))
    ev.extend(cli.receive_data(_wire(1, server_enc.encode(_one("x-t", "end")), end_stream=True, split=False)))
    assert_equal_int(_kind(ev, H2_EVT_RESPONSE_RECEIVED), 4, "100, 103, 103 and 200 delivered as responses")
    assert_equal_int(_kind(ev, H2_EVT_TRAILERS_RECEIVED), 1, "then trailers")
    assert_true(ev[len(ev) - 1].kind == H2_EVT_TRAILERS_RECEIVED, "trailers last")
    assert_equal_int(cli.open_stream_count(), 0, "stream closed")
    print("PASS: test_client_interim_final_then_trailers")


def test_client_second_final_headers_without_end_stream() raises:
    """Blocks without END_STREAM after the final response: one RST_STREAM(PROTOCOL_ERROR), none delivered, HPACK in sync."""
    var cli = _client()
    var server_enc = HpackEncoder()
    cli.send_headers(1, _req("GET", "/"), end_stream=True)
    var ev = cli.receive_data(_wire(1, server_enc.encode(_status("200")), end_stream=False, split=False))
    assert_equal_int(_kind(ev, H2_EVT_RESPONSE_RECEIVED), 1, "the response is delivered")
    _ = cli.data_to_send()
    var all = List[H2Event]()
    for i in range(10):
        var h = _status("500")
        h.append(Header("x-late", String(i)))
        all.extend(cli.receive_data(_wire(1, server_enc.encode(h), end_stream=False, split=i % 2 == 1)))
    assert_equal_int(_kind(all, H2_EVT_RESPONSE_RECEIVED), 0, "no second response")
    assert_equal_int(_kind(all, H2_EVT_TRAILERS_RECEIVED), 0, "not trailers either")
    assert_equal_int(_kind(all, H2_EVT_STREAM_RESET), 1, "the stream is reset once")
    assert_true(not cli.is_closed(), "a stream error, not a connection error")
    var out = _frames(cli.data_to_send())
    assert_equal_int(_rst_count(out, 1), 1, "one RST_STREAM")
    assert_equal_int(_rst_code(out, 1), H2_PROTOCOL_ERROR, "malformed trailers (RFC 9113 Section 8.1)")
    cli.send_headers(3, _req("GET", "/next"), end_stream=True)
    var h = _status("200")
    h.append(Header("x-late", "9"))
    ev = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, server_enc.encode(h)))
    assert_true(_has_header(ev, H2_EVT_RESPONSE_RECEIVED, "x-late", "9"), "HPACK in sync")
    print("PASS: test_client_second_final_headers_without_end_stream")


def main() raises:
    test_repeated_header_blocks_are_not_new_requests()
    test_trailers_without_end_stream_is_stream_error()
    test_bodyless_request_trailers_are_trailers()
    test_trailers_after_data_across_continuation()
    test_request_split_across_continuation_still_delivered()
    test_client_headers_after_end_stream_reset_once()
    test_client_headers_after_own_reset_dropped()
    test_client_interim_then_final_response()
    test_client_response_trailers()
    test_client_bodyless_response_trailers()
    test_client_interim_final_then_trailers()
    test_client_second_final_headers_without_end_stream()
