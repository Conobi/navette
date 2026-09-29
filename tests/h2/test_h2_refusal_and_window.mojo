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


def main() raises:
    test_stream_flow_control_error_credits_connection()
    test_never_opened_lower_ids_are_closed()
    test_idle_and_reused_ids_stay_connection_errors()
