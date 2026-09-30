# tests/h3/test_h3_stream_state_release.mojo
#
# Per-stream H3 receive state lives only as long as the stream: a
# long-lived connection that has served many requests must not keep one
# buffer (at its peak capacity) per finished or reset stream.

from std.collections import Span
from tests._test_util import assert_true, assert_equal_int
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
    assert_equal_int(len(p.srv._request_headers_seen), 0, "no per-stream HEADERS flags kept")
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
    assert_equal_int(len(p.srv._request_headers_seen), 0, "no per-stream HEADERS flags kept")
    print("  test_reset_streams_release_state: PASS")


def main() raises:
    print("test_h3_stream_state_release:")
    test_finished_streams_release_state()
    test_reset_streams_release_state()
    print("All test_h3_stream_state_release tests passed.")
