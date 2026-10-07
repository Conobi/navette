# tests/h3/test_h3_stream_state_release.mojo
#
# Per-stream H3 receive state lives only as long as the stream: a
# long-lived connection that has served many requests must not keep one
# buffer (at its peak capacity) per finished or reset stream.

from std.collections import Span
from navette.h3.connection import H3Event
from navette.h3.error import H3_FRAME_UNEXPECTED
from navette.h3.frame import H3RawFrame, H3_FRAME_HEADERS
from navette.h3.qpack import FieldSection, QpackEncoder
from tests._test_util import assert_true, assert_false, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get, filler

comptime _REQUESTS = 24


def test_finished_streams_release_state() raises:
    var p = RawPair()
    for _ in range(_REQUESTS):
        var sid = p.cli.open_stream(True)
        var b = headers_get()
        b.append(0x00)  # DATA, 1000 bytes, so the buffer grew at some point
        b.append(0x43)
        b.append(0xE8)
        filler(b, 1000)
        p.send(sid, b, fin=True)
    assert_equal_int(p.ended_events, _REQUESTS, "every request ended")
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(len(p.srv._stream_bufs), 0, "no per-stream buffers kept")
    print("  test_finished_streams_release_state: PASS")


def test_reset_streams_release_state() raises:
    var p = RawPair()
    for _ in range(_REQUESTS):
        var sid = p.cli.open_stream(True)
        var b = headers_get()
        b.append(0x01)  # partial second HEADERS frame left in the buffer
        b.append(0x10)
        p.send(sid, b)
        assert_true(p.buffered(sid) > 0, "partial frame waits in the buffer")
        p.cli.reset_stream(sid, UInt64(0x10C))
        p.pump(10)
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(len(p.srv._stream_bufs), 0, "no per-stream buffers kept after RESET_STREAM")
    print("  test_reset_streams_release_state: PASS")


def _kinds_are(got: List[UInt8], var want: List[UInt8]) -> Bool:
    if len(got) != len(want):
        return False
    for i in range(len(want)):
        if got[i] != want[i]:
            return False
    return True


def test_headers_after_final_head_are_trailers() raises:
    """HEADERS, DATA, HEADERS, HEADERS, FIN: one request head, then trailers; a third section never re-opens the request."""
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    b.extend([UInt8(0x00), 0x03, 0x61, 0x62, 0x63])  # DATA "abc"
    var trailer: List[Byte] = [0x01, 0x03, 0x00, 0x00, 0xE7]  # HEADERS: cache-control no-cache
    b.extend(Span(trailer))
    b.extend(Span(trailer))
    p.send(sid, b, fin=True)
    var want: List[UInt8] = [
        H3Event.HEADERS_RECEIVED, H3Event.DATA_RECEIVED, H3Event.TRAILERS_RECEIVED,
        H3Event.TRAILERS_RECEIVED, H3Event.STREAM_ENDED,
    ]
    assert_true(_kinds_are(p.stream_kinds, want^), "head, data, trailers, trailers, end")
    assert_equal_int(p.close_code, -1, "no protocol error")
    assert_equal_int(len(p.srv._stream_bufs), 0, "stream state released")
    print("  test_headers_after_final_head_are_trailers: PASS")


def test_data_before_headers_still_closes() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    var b: List[Byte] = [0x00, 0x01, 0x61]  # DATA "a"
    b.extend(Span(headers_get()))
    p.send(sid, b)
    assert_equal_int(p.close_code, Int(H3_FRAME_UNEXPECTED), "DATA before HEADERS closes")
    assert_equal_int(p.headers_events, 0, "no head delivered")
    print("  test_data_before_headers_still_closes: PASS")


def test_interim_response_head_keeps_headers_unseen() raises:
    """Client side: 103 and 200 are both HEADERS_RECEIVED; only the final head sets `headers_seen`."""
    var p = RawPair()
    var enc = QpackEncoder(False)
    var seen = False
    var statuses: List[String] = ["103", "200", ""]
    for ref status in statuses:
        var block = List[Byte]()
        enc.encode(block, FieldSection(status=status))
        p.srv._handle_request_frame(UInt64(0), H3RawFrame(H3_FRAME_HEADERS, block^), seen, p.now)
        assert_true(seen == (status != "103"), "headers_seen after :status " + status)
    var kinds = List[UInt8]()
    var codes = List[String]()
    while True:
        var ev = p.srv.poll_event()
        if not ev:
            break
        kinds.append(ev.value().kind)
        codes.append(ev.value().section.status)
    var want: List[UInt8] = [H3Event.HEADERS_RECEIVED, H3Event.HEADERS_RECEIVED, H3Event.TRAILERS_RECEIVED]
    assert_true(_kinds_are(kinds, want^), "103, 200, trailers")
    assert_true(codes[0] == "103" and codes[1] == "200", "statuses in order")
    assert_false(Bool(p.srv.poll_event()), "queue drained")
    print("  test_interim_response_head_keeps_headers_unseen: PASS")


def main() raises:
    print("test_h3_stream_state_release:")
    test_finished_streams_release_state()
    test_reset_streams_release_state()
    test_headers_after_final_head_are_trailers()
    test_data_before_headers_still_closes()
    test_interim_response_head_keeps_headers_unseen()
    print("All test_h3_stream_state_release tests passed.")
