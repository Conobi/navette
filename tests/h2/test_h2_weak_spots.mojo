"""H2Connection (server side) resource bounds: closed-stream pruning and reset floods.

Drives a real `H2Connection(client_side=False)` with hand-built frames and
a client-side `HpackEncoder`. Iteration counts stay just past each limit,
so the file runs in seconds.
"""

from navette.h2.connection import H2Connection, H2Config
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
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    H2_PROTOCOL_ERROR,
    H2_CANCEL,
    H2_STREAM_CLOSED,
    H2_ENHANCE_YOUR_CALM,
)
from navette.h2.hpack import HpackEncoder
from navette.h2.header import Header
from navette.http.config import DEFAULT_MAX_LOCAL_RESET_STREAMS
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


def _req() -> List[Header]:
    var h = List[Header]()
    h.append(Header(":method", "GET"))
    h.append(Header(":scheme", "https"))
    h.append(Header(":path", "/"))
    h.append(Header(":authority", "example.test"))
    return h^


def _status() -> List[Header]:
    var h = List[Header]()
    h.append(Header(":status", "200"))
    return h^


def _server(max_streams: Int = 100) raises -> H2Connection:
    """A server connection past the preface, its own SETTINGS already drained."""
    var cfg = H2Config(client_side=False)
    cfg.max_concurrent_streams = UInt32(max_streams)
    var srv = H2Connection(client_side=False, config=cfg)
    srv.initiate_connection()
    var pre = List[Byte]()
    pre.extend(String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").as_bytes())
    pre.extend(Span(_frame(FRAME_SETTINGS, 0, 0, List[Byte]())))
    _ = srv.receive_data(pre)
    _ = srv.data_to_send()
    return srv^


def _goaway_code(wire: List[Byte]) -> Int:
    """Error code of the first GOAWAY in `wire`, or -1."""
    var pos = 0
    while pos < len(wire):
        var r = decode_frame(wire, pos)
        if r[1] == 0:
            break
        if r[0].frame_type == FRAME_GOAWAY:
            ref p = r[0].payload
            return (Int(p[4]) << 24) | (Int(p[5]) << 16) | (Int(p[6]) << 8) | Int(p[7])
        pos += r[1]
    return -1


def _count_rst(wire: List[Byte], sid: Int, code: Int) -> Int:
    var n = 0
    var pos = 0
    while pos < len(wire):
        var r = decode_frame(wire, pos)
        if r[1] == 0:
            break
        ref f = r[0]
        if f.frame_type == FRAME_RST_STREAM and f.stream_id == sid and Int(f.payload[3]) == code:
            n += 1
        pos += r[1]
    return n


# ── A. Closed streams are forgotten; resets are capped ───────────────────


def test_closed_streams_are_forgotten() raises:
    """Completed and peer-reset streams leave `_streams`; only live ones stay."""
    var srv = _server()
    var enc = HpackEncoder()
    var sid = 1
    for _ in range(50):
        _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid, enc.encode(_req())))
        srv.send_headers(UInt32(sid), _status(), end_stream=True)
        sid += 2
    for _ in range(50):
        var w = _frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, enc.encode(_req()))
        w.extend(Span(_frame(FRAME_RST_STREAM, 0, sid, _u32(H2_CANCEL))))
        _ = srv.receive_data(w)
        sid += 2
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, enc.encode(_req())))
    assert_equal_int(len(srv._streams), 1, "only the open stream is retained")
    assert_true(not srv.is_closed(), "connection stays up")
    print("PASS: test_closed_streams_are_forgotten")


def test_late_frames_on_forgotten_stream_are_closed_not_idle() raises:
    """The highest stream, completed and forgotten: WINDOW_UPDATE/RST ignored, DATA one STREAM_CLOSED, HEADERS reuse PROTOCOL_ERROR."""
    var srv = _server()
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req())))
    srv.send_headers(1, _status(), end_stream=True)
    _ = srv.data_to_send()
    var ev = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(100)))
    assert_true(not srv.is_closed() and len(ev) == 0, "WINDOW_UPDATE on a closed stream is ignored")
    ev = srv.receive_data(_frame(FRAME_RST_STREAM, 0, 1, _u32(H2_CANCEL)))
    assert_true(not srv.is_closed() and len(ev) == 0, "RST_STREAM on a closed stream is ignored")
    var w = _frame(FRAME_DATA, 0, 1, List[Byte](length=10, fill=Byte(0x61)))
    w.extend(Span(_frame(FRAME_DATA, 0, 1, List[Byte](length=10, fill=Byte(0x61)))))
    _ = srv.receive_data(w)
    assert_true(not srv.is_closed(), "DATA on a closed stream is a stream error")
    assert_equal_int(_count_rst(srv.data_to_send(), 1, H2_STREAM_CLOSED), 1, "one RST_STREAM(STREAM_CLOSED)")

    var srv3 = _server()
    var enc3 = HpackEncoder()
    _ = srv3.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc3.encode(_req())))
    srv3.send_headers(1, _status(), end_stream=True)
    _ = srv3.data_to_send()
    _ = srv3.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc3.encode(_req())))
    assert_true(srv3.is_closed(), "HEADERS reusing a closed id closes the connection")
    assert_equal_int(_goaway_code(srv3.data_to_send()), H2_PROTOCOL_ERROR, "GOAWAY(PROTOCOL_ERROR)")

    # Peer-reset highest stream: DATA is closed-stream, not idle.
    var srv2 = _server()
    var enc2 = HpackEncoder()
    var w2 = _frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc2.encode(_req()))
    w2.extend(Span(_frame(FRAME_RST_STREAM, 0, 1, _u32(H2_CANCEL))))
    w2.extend(Span(_frame(FRAME_DATA, 0, 1, List[Byte](length=10, fill=Byte(0x61)))))
    _ = srv2.receive_data(w2)
    assert_true(not srv2.is_closed(), "DATA after the peer's RST_STREAM is a stream error")
    assert_equal_int(_count_rst(srv2.data_to_send(), 1, H2_STREAM_CLOSED), 1, "RST_STREAM(STREAM_CLOSED)")
    print("PASS: test_late_frames_on_forgotten_stream_are_closed_not_idle")


def _rapid_reset(n: Int) raises -> H2Connection:
    var srv = _server()
    var enc = HpackEncoder()
    var sid = 1
    for _ in range(n):
        var w = _frame(FRAME_HEADERS, FLAG_END_HEADERS, sid, enc.encode(_req()))
        w.extend(Span(_frame(FRAME_RST_STREAM, 0, sid, _u32(H2_CANCEL))))
        _ = srv.receive_data(w)
        sid += 2
        if srv.is_closed():
            break
    return srv^


def test_rapid_reset_is_capped() raises:
    """CVE-2023-44487: HEADERS + RST_STREAM pairs past the reset limit end in GOAWAY(ENHANCE_YOUR_CALM)."""
    var ok = _rapid_reset(DEFAULT_MAX_LOCAL_RESET_STREAMS)
    assert_true(not ok.is_closed(), "up to the limit the connection stays up")
    var srv = _rapid_reset(DEFAULT_MAX_LOCAL_RESET_STREAMS + 1)
    assert_true(srv.is_closed(), "one past the limit closes the connection")
    assert_equal_int(_goaway_code(srv.data_to_send()), H2_ENHANCE_YOUR_CALM, "GOAWAY(ENHANCE_YOUR_CALM)")
    print("PASS: test_rapid_reset_is_capped")


def test_made_you_reset_is_capped() raises:
    """CVE-2025-8671: resets the server sends because of peer misbehaviour count toward the same limit."""
    var srv = _server()
    var enc = HpackEncoder()
    var sid = 1
    for _ in range(DEFAULT_MAX_LOCAL_RESET_STREAMS + 1):
        var w = _frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid, enc.encode(_req()))
        w.extend(Span(_frame(FRAME_WINDOW_UPDATE, 0, sid, _u32(0x7FFFFFFF))))
        _ = srv.receive_data(w)
        sid += 2
        if srv.is_closed():
            break
        _ = srv.data_to_send()
    assert_true(srv.is_closed(), "server-sent resets past the limit close the connection")
    assert_equal_int(_goaway_code(srv.data_to_send()), H2_ENHANCE_YOUR_CALM, "GOAWAY(ENHANCE_YOUR_CALM)")
    print("PASS: test_made_you_reset_is_capped")


def test_completed_streams_do_not_count_as_resets() raises:
    """Normal request/response streams past the reset limit keep the connection up."""
    var srv = _server()
    var enc = HpackEncoder()
    var sid = 1
    for _ in range(DEFAULT_MAX_LOCAL_RESET_STREAMS + 10):
        _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid, enc.encode(_req())))
        srv.send_headers(UInt32(sid), _status(), end_stream=True)
        _ = srv.data_to_send()
        sid += 2
    assert_true(not srv.is_closed(), "completed streams are not resets")
    print("PASS: test_completed_streams_do_not_count_as_resets")


def main() raises:
    test_closed_streams_are_forgotten()
    test_late_frames_on_forgotten_stream_are_closed_not_idle()
    test_rapid_reset_is_capped()
    test_made_you_reset_is_capped()
    test_completed_streams_do_not_count_as_resets()
