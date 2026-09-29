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
    STREAM_OPEN,
    STREAM_HALF_CLOSED_LOCAL,
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
    FRAME_WINDOW_UPDATE,
    FRAME_CONTINUATION,
    FRAME_PUSH_PROMISE,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_PADDED,
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
from tests.protect._prop import Rng


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


def _assert_window_conserved(srv: H2Connection, msg: String) raises:
    """Every received byte is either still debited or queued for credit: window + pending credit == initial."""
    assert_equal_int(srv._recv_window + srv._recv_window_consumed, 65535, "connection window conserved: " + msg)


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
    _assert_window_conserved(srv, "stream FLOW_CONTROL_ERROR")
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
    _assert_window_conserved(srv, "DATA after our reset")
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
    _assert_window_conserved(srv, "DATA on a closed stream")
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
    _assert_window_conserved(srv, "DATA on a refused stream")

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


def _active(srv: H2Connection) -> Int:
    """Streams in an open or half-closed state: what `open_stream_count` must equal."""
    var n = 0
    for e in srv._streams.items():
        var lc = e.value.lifecycle
        if lc == STREAM_OPEN or lc == STREAM_HALF_CLOSED_LOCAL or lc == STREAM_HALF_CLOSED_REMOTE:
            n += 1
    return n


def _status(code: String) -> List[Header]:
    var h = List[Header]()
    h.append(Header(":status", code))
    return h^


def test_reopened_closed_stream_is_connection_error() raises:
    """HEADERS re-opening a normally closed stream is a reused id, not trailers: PROTOCOL_ERROR, count untouched."""
    var srv = _server(1)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/"))))
    srv.send_headers(1, _status("200"), end_stream=True)
    _ = srv.data_to_send()
    assert_equal_int(srv.open_stream_count(), 0, "stream 1 closed")
    var ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/again"))))
    assert_equal_int(_requests(ev), 0, "no request event for a reused id")
    assert_true(srv.is_closed(), "HEADERS on a closed stream closes the connection")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    assert_equal_int(srv.open_stream_count(), 0, "count untouched")
    print("PASS: test_reopened_closed_stream_is_connection_error")


def test_headers_on_half_closed_remote_is_stream_closed() raises:
    """A second HEADERS after the peer's END_STREAM: stream error STREAM_CLOSED, the slot is released once."""
    var srv = _server(1)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/"))))
    _ = srv.data_to_send()
    var ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/again"))))
    assert_equal_int(_requests(ev), 0, "no second request event")
    assert_true(not srv.is_closed(), "a stream error, not a connection error")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 1, "RST_STREAM(STREAM_CLOSED)")
    assert_equal_int(srv.open_stream_count(), 0, "slot released")
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(_req("GET", "/next"))))
    assert_equal_int(_requests(ev), 1, "HPACK still in sync, next stream accepted")
    print("PASS: test_headers_on_half_closed_remote_is_stream_closed")


def test_app_response_after_peer_reset_keeps_count() raises:
    """Peer RST, then the application still answers, then the peer sends END_STREAM: a closed stream never reopens."""
    var srv = _server(1)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.receive_data(_frame(FRAME_RST_STREAM, 0, 1, _u32(H2_CANCEL)))
    assert_equal_int(srv.open_stream_count(), 0, "reset releases the slot")
    srv.send_headers(1, _status("200"), end_stream=True)
    _ = srv.data_to_send()
    var ev = srv.receive_data(_data(1, 0, end_stream=True))
    assert_true(srv.open_stream_count() >= 0, "count never negative")
    assert_equal_int(srv.open_stream_count(), _active(srv), "count equals open streams")
    for e in ev:
        assert_true(e.kind != H2_EVT_REQUEST_RECEIVED, "no event revives the stream")
    print("PASS: test_app_response_after_peer_reset_keeps_count")


def test_stream_count_matches_open_streams_property() raises:
    """Random HEADERS / DATA / RST_STREAM / WINDOW_UPDATE on fresh and reused ids, both directions: the count equals the open streams."""
    for seed in range(40):
        var rng = Rng(UInt64(seed) * 7919 + 1)
        var srv = _server(3)
        var enc = HpackEncoder()
        var next_id = 1
        for step in range(250):
            var op = rng.below(8)
            var sid = next_id if next_id > 1 and op != 0 else 1
            if next_id > 1:
                sid = 2 * rng.below(next_id // 2) + 1
            try:
                if op == 0:
                    var fl = FLAG_END_HEADERS | (FLAG_END_STREAM if rng.chance(50) else 0)
                    _ = srv.receive_data(_frame(FRAME_HEADERS, fl, next_id, enc.encode(_req("POST", "/"))))
                    next_id += 2
                elif op == 1:
                    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, sid, enc.encode(_req("GET", "/r"))))
                elif op == 2:
                    _ = srv.receive_data(_data(sid, rng.below(8), end_stream=rng.chance(50)))
                elif op == 3:
                    _ = srv.receive_data(_frame(FRAME_RST_STREAM, 0, sid, _u32(H2_CANCEL)))
                elif op == 4:
                    srv.send_headers(UInt32(sid), _status("200"), end_stream=rng.chance(60))
                elif op == 5:
                    srv.send_rst_stream(UInt32(sid), UInt32(H2_NO_ERROR))
                elif op == 6:
                    var inc = 0x7FFFFFFF if rng.chance(50) else 1 + rng.below(1000)
                    _ = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, sid, _u32(inc)))
                else:
                    srv.send_data(UInt32(sid), List[Byte](), end_stream=True)
            except:
                pass  # application calls on unusable streams raise; that is fine
            var msg = String("seed=", seed, " step=", step, " op=", op, " sid=", sid)
            assert_true(srv.open_stream_count() >= 0, "count never negative: " + msg)
            if srv.is_closed():
                srv = _server(3)
                enc = HpackEncoder()
                next_id = 1
                continue
            assert_equal_int(srv.open_stream_count(), _active(srv), "count equals open streams: " + msg)
            _ = srv.data_to_send()
    print("PASS: test_stream_count_matches_open_streams_property")


def test_closed_stream_older_than_window_is_connection_error() raises:
    """DATA on a closed id older than the 1,024-stream window closes the connection once; no RST_STREAM per frame."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 4099, enc.encode(_req("GET", "/"))))
    _ = srv.data_to_send()
    var wire = List[Byte]()
    for _ in range(100):
        wire.extend(Span(_data(1, 0)))
    _ = srv.receive_data(wire)
    assert_true(srv.is_closed(), "a never-opened id outside the window is a connection error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 0, "no RST_STREAM flood")
    assert_equal_int(_count(out, FRAME_GOAWAY, 0, H2_STREAM_CLOSED), 1, "one GOAWAY(STREAM_CLOSED)")

    var srv2 = _server(10)
    var enc2 = HpackEncoder()
    _ = srv2.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc2.encode(_req("GET", "/"))))
    srv2.send_headers(1, _status("200"), end_stream=True)
    _ = srv2.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 4099, enc2.encode(_req("GET", "/"))))
    _ = srv2.data_to_send()
    _ = srv2.receive_data(_data(1, 0))
    assert_true(srv2.is_closed(), "a closed stream outside the window is a connection error")
    assert_equal_int(_count(_frames(srv2.data_to_send()), FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 0, "no RST_STREAM answer")
    print("PASS: test_closed_stream_older_than_window_is_connection_error")


def _reset_post(mut srv: H2Connection, mut enc: HpackEncoder) raises:
    """Open POST stream 1 and reset it from our side, so it is locally closed."""
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    srv.send_rst_stream(1, UInt32(H2_CANCEL))
    _ = srv.data_to_send()


def test_trailers_across_continuation_on_marked_stream() raises:
    """Trailers split over HEADERS + CONTINUATION on a stream we reset: decoded, dropped, HPACK stays in sync."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _reset_post(srv, enc)
    var trailers = List[Header]()
    trailers.append(Header("x-trailer", "split"))
    var block = enc.encode(trailers)
    var half = len(block) // 2
    var wire = _frame(FRAME_HEADERS, FLAG_END_STREAM, 1, List[Byte](block[:half]))
    wire.extend(Span(_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, List[Byte](block[half:]))))
    var ev = srv.receive_data(wire)
    assert_equal_int(len(ev), 0, "trailers ignored")
    assert_true(srv.ignored_frames_locally_closed == 1, "one ignored block")
    var next_req = _req("GET", "/c")
    next_req.append(Header("x-trailer", "split"))
    ev = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc.encode(next_req)))
    assert_equal_int(_requests(ev), 1, "stream 3 accepted")
    var found = False
    for ref h in ev[0].headers:
        if h.name == "x-trailer" and h.value == "split":
            found = True
    assert_true(found, "HPACK in sync after the split discarded block")
    print("PASS: test_trailers_across_continuation_on_marked_stream")


def test_window_update_on_marked_stream_is_ignored() raises:
    var srv = _server(10)
    var enc = HpackEncoder()
    _reset_post(srv, enc)
    var ev = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(1000)))
    assert_equal_int(len(ev), 0, "no event")
    assert_true(srv.ignored_frames_locally_closed == 1, "counted as ignored")
    assert_equal_int(len(_frames(srv.data_to_send())), 0, "no answer")
    print("PASS: test_window_update_on_marked_stream_is_ignored")


def test_bad_padding_on_ignored_data_is_protocol_error() raises:
    """A pad length not smaller than the payload is a connection PROTOCOL_ERROR (RFC 9113 Section 6.1), even on an ignored stream."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _reset_post(srv, enc)
    var payload = List[Byte](length=3, fill=Byte(0x61))
    payload[0] = Byte(5)
    _ = srv.receive_data(_frame(FRAME_DATA, FLAG_PADDED, 1, payload))
    assert_true(srv.is_closed(), "invalid padding closes the connection")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    var srv2 = _server(10)
    var enc2 = HpackEncoder()
    _ = srv2.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, enc2.encode(_req("GET", "/"))))
    _ = srv2.receive_data(_frame(FRAME_DATA, FLAG_PADDED, 1, List[Byte]()))
    assert_true(srv2.is_closed(), "PADDED with no pad-length byte on a never-opened id closes the connection")
    assert_equal_int(_count(_frames(srv2.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    print("PASS: test_bad_padding_on_ignored_data_is_protocol_error")


def test_stream_window_update_overflow_resets_stream() raises:
    """A stream WINDOW_UPDATE past 2^31-1 is a stream FLOW_CONTROL_ERROR (RFC 9113 Section 6.9.1): RST sent, slot freed, stream marked."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(0x7FFFFFFF)))
    assert_true(not srv.is_closed(), "a stream error, not a connection error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_FLOW_CONTROL_ERROR), 1, "RST_STREAM(FLOW_CONTROL_ERROR)")
    assert_equal_int(srv.open_stream_count(), 0, "slot released")
    var ev = srv.receive_data(_data(1, 500))
    assert_equal_int(len(ev), 0, "later DATA is not delivered")
    assert_true(srv.ignored_frames_locally_closed == 1, "the stream is locally closed")
    assert_true(srv.window_credited_back_bytes == 500, "its bytes are credited back")
    _assert_window_conserved(srv, "DATA after the overflow reset")
    print("PASS: test_stream_window_update_overflow_resets_stream")


def test_undelivered_burst_past_connection_window_is_flow_control_error() raises:
    """DATA on a refused stream larger than the remaining connection window: GOAWAY(FLOW_CONTROL_ERROR), even though it is ignored."""
    var srv = _server(1, initial_window=100_000)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    var body = List[Byte]()
    for _ in range(4):
        body.extend(Span(_data(1, 15000)))
    _ = srv.receive_data(body)  # delivered, not yet consumed: 5,535 bytes of connection window left
    assert_true(not srv.is_closed(), "60,000 bytes fit the connection window")
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, enc.encode(_req("POST", "/b"))))
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_RST_STREAM, 3, H2_REFUSED_STREAM), 1, "stream 3 refused")
    _ = srv.receive_data(_data(3, 10000))
    assert_true(srv.is_closed(), "an ignored burst still counts against the connection window")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_FLOW_CONTROL_ERROR), 1, "GOAWAY FLOW_CONTROL_ERROR")
    print("PASS: test_undelivered_burst_past_connection_window_is_flow_control_error")


def test_window_update_on_idle_stream_is_protocol_error() raises:
    """WINDOW_UPDATE on an idle id (odd above the last, or an even id we never pushed) is a connection PROTOCOL_ERROR (RFC 9113 Section 5.1)."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 5, enc.encode(_req("POST", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 3, _u32(100)))
    assert_true(not srv.is_closed(), "a skipped lower id is closed, not idle: ignored")
    _ = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 5, _u32(100)))
    assert_true(not srv.is_closed(), "an open stream takes WINDOW_UPDATE")
    _ = srv.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 99, _u32(100)))
    assert_true(srv.is_closed(), "odd id above the last is idle")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    var srv2 = _server(10)
    var enc2 = HpackEncoder()
    _ = srv2.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 5, enc2.encode(_req("POST", "/"))))
    _ = srv2.data_to_send()
    _ = srv2.receive_data(_frame(FRAME_WINDOW_UPDATE, 0, 2, _u32(100)))
    assert_true(srv2.is_closed(), "an even id is ours and never pushed: idle")
    assert_equal_int(_count(_frames(srv2.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "GOAWAY PROTOCOL_ERROR")
    print("PASS: test_window_update_on_idle_stream_is_protocol_error")


def _push_promise(sid: Int, promised: Int, block: List[Byte]) -> List[Byte]:
    var payload = _u32(promised)
    payload.extend(Span(block))
    return _frame(FRAME_PUSH_PROMISE, FLAG_END_HEADERS, sid, payload)


def test_push_promise_is_protocol_error() raises:
    """PUSH_PROMISE to a server, or to our client (which sends ENABLE_PUSH=0): connection PROTOCOL_ERROR (RFC 9113 Section 8.4)."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, enc.encode(_req("POST", "/"))))
    _ = srv.data_to_send()
    _ = srv.receive_data(_push_promise(1, 2, enc.encode(_req("GET", "/pushed"))))
    assert_true(srv.is_closed(), "a client cannot push")
    assert_equal_int(_count(_frames(srv.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "server: GOAWAY PROTOCOL_ERROR")

    var cli = H2Connection(client_side=True)
    cli.initiate_connection()
    _ = cli.receive_data(_frame(FRAME_SETTINGS, 0, 0, List[Byte]()))
    var sid = cli.next_stream_id()
    cli.send_headers(sid, _req("GET", "/"), end_stream=True)
    _ = cli.data_to_send()
    var server_enc = HpackEncoder()
    _ = cli.receive_data(_push_promise(Int(sid), 2, server_enc.encode(_req("GET", "/pushed"))))
    assert_true(cli.is_closed(), "push is disabled on our client")
    assert_equal_int(_count(_frames(cli.data_to_send()), FRAME_GOAWAY, 0, H2_PROTOCOL_ERROR), 1, "client: GOAWAY PROTOCOL_ERROR")
    print("PASS: test_push_promise_is_protocol_error")


def _closed_stream_1(mut srv: H2Connection, mut enc: HpackEncoder, next_sid: Int) raises:
    """Stream 1 served and closed normally (never reset), then stream `next_sid` opened."""
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, enc.encode(_req("GET", "/"))))
    srv.send_headers(1, _status("200"), end_stream=True)
    _ = srv.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, next_sid, enc.encode(_req("GET", "/"))))
    _ = srv.data_to_send()


def test_window_update_overflow_on_closed_stream_older_than_window() raises:
    """Overflowing WINDOW_UPDATEs on a closed stream older than the 1,024-stream window close the connection once; no RST_STREAM per frame."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _closed_stream_1(srv, enc, 4099)
    var wire = List[Byte]()
    for _ in range(100):
        wire.extend(Span(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(0x7FFFFFFF))))
    _ = srv.receive_data(wire)
    assert_true(srv.is_closed(), "a closed stream outside the window is a connection error")
    var out = _frames(srv.data_to_send())
    assert_equal_int(_count(out, FRAME_RST_STREAM, 1, H2_FLOW_CONTROL_ERROR), 0, "no RST_STREAM flood")
    assert_equal_int(_count(out, FRAME_GOAWAY, 0, H2_STREAM_CLOSED), 1, "one GOAWAY(STREAM_CLOSED)")
    print("PASS: test_window_update_overflow_on_closed_stream_older_than_window")


def test_window_update_on_recently_closed_stream_is_ignored() raises:
    """WINDOW_UPDATE, overflowing or not, on a recently closed stream is ignored (RFC 9113 Section 5.1): no RST_STREAM, no event."""
    var srv = _server(10)
    var enc = HpackEncoder()
    _closed_stream_1(srv, enc, 3)
    var wire = List[Byte]()
    for _ in range(100):
        wire.extend(Span(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(0x7FFFFFFF))))
    wire.extend(Span(_frame(FRAME_WINDOW_UPDATE, 0, 1, _u32(100))))
    var ev = srv.receive_data(wire)
    assert_true(not srv.is_closed(), "the connection stays open")
    assert_equal_int(len(ev), 0, "no event")
    assert_equal_int(len(_frames(srv.data_to_send())), 0, "no answer")

    # Client side: a closed stream it opened ignores them the same way.
    var cli = H2Connection(client_side=True)
    cli.initiate_connection()
    _ = cli.receive_data(_frame(FRAME_SETTINGS, 0, 0, List[Byte]()))
    cli.send_headers(1, _req("GET", "/"), end_stream=True)
    var server_enc = HpackEncoder()
    _ = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, server_enc.encode(_status("200"))))
    _ = cli.data_to_send()
    ev = cli.receive_data(wire)
    assert_true(not cli.is_closed(), "client: the connection stays open")
    assert_equal_int(len(ev), 0, "client: no event")
    assert_equal_int(len(_frames(cli.data_to_send())), 0, "client: no answer")
    print("PASS: test_window_update_on_recently_closed_stream_is_ignored")


def test_client_data_on_closed_stream_resets_once() raises:
    """DATA on a stream the client already closed earns one RST_STREAM(STREAM_CLOSED), then later frames are ignored (RFC 9113 Section 5.1)."""
    var cli = H2Connection(client_side=True)
    cli.initiate_connection()
    _ = cli.receive_data(_frame(FRAME_SETTINGS, 0, 0, List[Byte]()))
    cli.send_headers(1, _req("GET", "/"), end_stream=True)
    var server_enc = HpackEncoder()
    _ = cli.receive_data(_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, server_enc.encode(_status("200"))))
    _ = cli.data_to_send()
    var wire = List[Byte]()
    for _ in range(100):
        wire.extend(Span(_data(1, 0)))
    _ = cli.receive_data(wire)
    assert_true(not cli.is_closed(), "a stream error, not a connection error")
    assert_equal_int(_count(_frames(cli.data_to_send()), FRAME_RST_STREAM, 1, H2_STREAM_CLOSED), 1, "one RST_STREAM, not one per frame")
    print("PASS: test_client_data_on_closed_stream_resets_once")


def main() raises:
    test_stream_flow_control_error_credits_connection()
    test_never_opened_lower_ids_are_closed()
    test_idle_and_reused_ids_stay_connection_errors()
    test_data_after_our_408_and_reset_is_ignored()
    test_data_on_closed_unmarked_stream_no_window_loss()
    test_refused_stream_keeps_connection_and_hpack()
    test_refused_block_with_bad_hpack_is_compression_error()
    test_reopened_closed_stream_is_connection_error()
    test_headers_on_half_closed_remote_is_stream_closed()
    test_app_response_after_peer_reset_keeps_count()
    test_stream_count_matches_open_streams_property()
    test_closed_stream_older_than_window_is_connection_error()
    test_trailers_across_continuation_on_marked_stream()
    test_window_update_on_marked_stream_is_ignored()
    test_bad_padding_on_ignored_data_is_protocol_error()
    test_stream_window_update_overflow_resets_stream()
    test_undelivered_burst_past_connection_window_is_flow_control_error()
    test_window_update_on_idle_stream_is_protocol_error()
    test_push_promise_is_protocol_error()
    test_window_update_overflow_on_closed_stream_older_than_window()
    test_window_update_on_recently_closed_stream_is_ignored()
    test_client_data_on_closed_stream_resets_once()
