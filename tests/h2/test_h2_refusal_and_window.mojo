"""H2Connection (server side): REFUSED_STREAM on stream-limit excess, locally-closed streams, connection-window accounting.

Drives a real `H2Connection(client_side=False)` with hand-built frames and
a client-side `HpackEncoder`, then decodes what the server wrote.
"""

from navette.h2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_CONNECTION_TERMINATED,
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
    FRAME_WINDOW_UPDATE,
    FRAME_CONTINUATION,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    H2_NO_ERROR,
    H2_PROTOCOL_ERROR,
    H2_CANCEL,
    H2_REFUSED_STREAM,
    H2_STREAM_CLOSED,
    H2_FLOW_CONTROL_ERROR,
    H2_COMPRESSION_ERROR,
)
from navette.h2.hpack import HpackEncoder
from navette.h2.header import Header
from tests._test_util import assert_true, assert_equal_int


# ── Wire helpers ─────────────────────────────────────────────────────────


def _frame(ft: Int, flags: Int, sid: Int, payload: List[Byte]) -> List[Byte]:
    var out = List[Byte]()
    encode_frame_into(Frame(len(payload), ft, flags, sid, payload), out)
    return out^


def _u32(v: Int) -> List[Byte]:
    var p = List[Byte](capacity=4)
    p.append(UInt8((v >> 24) & 0xFF))
    p.append(UInt8((v >> 16) & 0xFF))
    p.append(UInt8((v >> 8) & 0xFF))
    p.append(UInt8(v & 0xFF))
    return p^


def _data(sid: Int, n: Int, end_stream: Bool = False) -> List[Byte]:
    return _frame(FRAME_DATA, FLAG_END_STREAM if end_stream else 0, sid, List[Byte](length=n, fill=Byte(0x61)))


def _req(method: String, path: String) -> List[Header]:
    var h = List[Header]()
    h.append(Header(":method", method))
    h.append(Header(":scheme", "https"))
    h.append(Header(":path", path))
    h.append(Header(":authority", "example.test"))
    return h^


def _server(max_streams: Int, initial_window: Int = 65535) raises -> H2Connection:
    """A server connection past the preface, its own SETTINGS already drained."""
    var cfg = H2Config(client_side=False)
    cfg.max_concurrent_streams = UInt32(max_streams)
    cfg.initial_window_size = UInt32(initial_window)
    var srv = H2Connection(client_side=False, config=cfg)
    srv.initiate_connection()
    var pre = List[Byte]()
    pre.extend(String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").as_bytes())
    pre.extend(Span(_frame(FRAME_SETTINGS, 0, 0, List[Byte]())))
    _ = srv.receive_data(pre)
    _ = srv.data_to_send()
    return srv^


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


def _count(frames: List[Frame], ft: Int, sid: Int, code: Int) -> Int:
    var n = 0
    for ref f in frames:
        if f.frame_type == ft and f.stream_id == sid and _code(f) == code:
            n += 1
    return n


def _conn_window_credit(frames: List[Frame]) -> Int:
    var total = 0
    for ref f in frames:
        if f.frame_type == FRAME_WINDOW_UPDATE and f.stream_id == 0:
            total += _code(f) & 0x7FFFFFFF
    return total


def _requests(events: List[H2Event]) -> Int:
    var n = 0
    for ref e in events:
        if e.kind == H2_EVT_REQUEST_RECEIVED:
            n += 1
    return n


# ── Tests ────────────────────────────────────────────────────────────────


def test_stream_flow_control_error_credits_connection() raises:
    var srv = _server(10, initial_window=1000)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_data(1, 1500))
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_FLOW_CONTROL_ERROR), 1, "stream-level FLOW_CONTROL_ERROR")
    assert_true(srv.window_credited_back_bytes == 1500, "the connection window gets the 1,500 bytes back")
    print("PASS: test_stream_flow_control_error_credits_connection")

def test_never_opened_lower_ids_are_closed() raises:
    """DATA on a skipped lower id → STREAM_CLOSED with credit; RST_STREAM on one → ignored."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, enc.encode(_req("GET", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_data(3, 500))
    assert_true(not srv.is_closed(), "DATA on a skipped id is a stream error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 3, H2_STREAM_CLOSED), 1, "STREAM_CLOSED on 3")
    assert_true(srv.window_credited_back_bytes == 500, "credited")
    var ev = srv.receive_data(_frame(FRAME_RST_STREAM, 0, 1, _u32(H2_CANCEL)))
    assert_equal_int(len(ev), 0, "RST_STREAM on a skipped id is ignored")
    assert_true(not srv.is_closed(), "not a connection error")
    print("PASS: test_never_opened_lower_ids_are_closed")

def test_idle_and_reused_ids_stay_connection_errors() raises:
    """Pins (pass before and after): reused lower id on HEADERS and frames above the last id are PROTOCOL_ERROR."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, enc.encode(_req("GET", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(_req("GET", "/x"))))
    assert_true(srv.is_closed(), "reused lower id closes the connection")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    var srv2 = _server(10)
    _ = srv2.receive_data(_data(7, 10))
    assert_true(srv2.is_closed(), "DATA on an idle stream is a connection error")
    var srv3 = _server(10)
    _ = srv3.receive_data(_frame(FRAME_RST_STREAM, 0, 9, _u32(H2_CANCEL)))
    assert_true(srv3.is_closed(), "RST_STREAM on an idle stream is a connection error")
    var srv4 = _server(10)
    var enc4 = HpackEncoder()
    _ = srv4.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, enc4.encode(_req("GET", "/"))))
    assert_true(not srv4.is_closed(), "stream 5 opens")
    _ = srv4.receive_data(_data(2, 10))
    assert_true(srv4.is_closed(), "DATA on a lower even id (ours, never pushed) is idle, a connection error")
    print("PASS: test_idle_and_reused_ids_stay_connection_errors")


def test_data_after_our_408_and_reset_is_ignored() raises:
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/slow"))))
    var status = List[Header]()
    status.append(Header(":status", "408"))
    srv.send_headers(1, status^, end_stream=True)
    srv.send_rst_stream(1, UInt32(H2_NO_ERROR))
    _ = srv.data_to_send()
    var ev = srv.receive_data(_data(1, 1000))
    assert_equal_int(len(ev), 0, "no event")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 0, "no RST_STREAM answer")
    assert_true(srv.ignored_frames_locally_closed == 1, "counted as ignored")
    assert_true(srv.window_credited_back_bytes == 1000, "its bytes credited back")
    print("PASS: test_data_after_our_408_and_reset_is_ignored")

def test_data_on_closed_unmarked_stream_no_window_loss() raises:
    """1,000 DATA frames on a normally closed stream: one STREAM_CLOSED, and every byte credited back."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/"))))
    var status = List[Header]()
    status.append(Header(":status", "200"))
    srv.send_headers(1, status^, end_stream=True)
    _ = srv.data_to_send()
    var wire = List[Byte]()
    for _ in range(1000):
        wire.extend(Span(_data(1, 100)))
    _ = srv.receive_data(wire)
    assert_true(not srv.is_closed(), "connection survives 100,000 bytes on a closed stream")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 1, "one STREAM_CLOSED, then the stream is locally closed")
    assert_equal_int(_conn_window_credit(out) + srv._recv_window_consumed, 100_000, "no connection-window loss")
    print("PASS: test_data_on_closed_unmarked_stream_no_window_loss")


def test_refused_stream_keeps_connection_and_hpack() raises:
    """Refused POST (HEADERS+CONTINUATION) + DATA + trailers + RST_STREAM: connection survives, window restored, next request decodes."""
    var srv = _server(1)
    var enc = HpackEncoder()
    var ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/a"))))
    assert_equal_int(_requests(ev), 1, "stream 1 accepted")

    var block = enc.encode(_req("POST", "/b"))
    var half = len(block) // 2
    var first = List[Byte](block[:half])
    var rest = List[Byte](block[half:])
    var wire = _frame(FRAME_HEADERS, 0, 3, first)
    wire.extend(Span(_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 3, rest)))
    ev = srv.receive_data(wire)
    assert_equal_int(len(ev), 0, "refused stream raises no event")
    assert_true(not srv.is_closed(), "stream-limit excess is not a connection error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 3, H2_REFUSED_STREAM), 1, "RST_STREAM(REFUSED_STREAM) on 3")
    assert_true(srv.refused_streams == 1, "refusal counted")

    var body = _data(3, 16000)
    body.extend(Span(_data(3, 16000)))
    body.extend(Span(_data(3, 16000)))
    ev = srv.receive_data(body)
    assert_equal_int(len(ev), 0, "DATA on the refused stream is ignored")
    out = _frames(srv.data_to_send())
    assert_equal_int(_conn_window_credit(out), 48000, "its bytes are credited back to the connection window")
    assert_equal_int(_count(out, FRAME_RST_STREAM, 3, H2_STREAM_CLOSED), 0, "and not answered")

    var trailers = List[Header]()
    trailers.append(Header("x-trailer", "t1"))  # new dynamic-table entry in the client encoder
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(trailers)))
    ev.extend(srv.receive_data(_frame(FRAME_RST_STREAM, 0, 3, _u32(H2_CANCEL))))
    assert_equal_int(len(ev), 0, "trailers and RST_STREAM on the refused stream are ignored")
    assert_true(srv.ignored_frames_locally_closed == 5, "3 DATA + trailers + RST_STREAM ignored")

    _ = srv.receive_data(_data(1, 0, end_stream=True))
    var status = List[Header]()
    status.append(Header(":status", "200"))
    srv.send_headers(1, status^, end_stream=True)
    _ = srv.data_to_send()
    var next_req = _req("GET", "/c")
    next_req.append(Header("x-trailer", "t1"))  # the encoder now emits an indexed reference
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 5, enc.encode(next_req)))
    assert_equal_int(_requests(ev), 1, "stream 5 accepted")
    var found = False
    for ref h in ev[0].headers:
        if h.name == "x-trailer" and h.value == "t1":
            found = True
    assert_true(found, "HPACK stayed in sync through the discarded blocks")
    print("PASS: test_refused_stream_keeps_connection_and_hpack")

def test_refused_block_with_bad_hpack_is_compression_error() raises:
    var srv = _server(0)
    var garbage = List[Byte](length=4, fill=Byte(0xFF))  # indexed field with an out-of-range index
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, garbage))
    assert_true(srv.is_closed(), "undecodable block closes the connection")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_COMPRESSION_ERROR), 1, "COMPRESSION_ERROR, even when refused")
    print("PASS: test_refused_block_with_bad_hpack_is_compression_error")


def main() raises:
    test_stream_flow_control_error_credits_connection()
    test_never_opened_lower_ids_are_closed()
    test_idle_and_reused_ids_stay_connection_errors()
    test_data_after_our_408_and_reset_is_ignored()
    test_data_on_closed_unmarked_stream_no_window_loss()
    test_refused_stream_keeps_connection_and_hpack()
    test_refused_block_with_bad_hpack_is_compression_error()
