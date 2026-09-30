# tests/h3/test_h3_frame_parse_cost.mojo
#
# Parsing one drain of many tiny frames must cost time linear in the
# bytes drained. A peer can make the first stream offset arrive last so a
# single drain returns the whole stream window; shifting the remaining
# buffer once per frame turns that into a quadratic CPU burn.

from std.collections import Span
from std.time import perf_counter_ns
from tests._test_util import assert_true, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get

# 32,768 zero-length reserved frames (0x21 0x00).
comptime _GREASE_BYTES = 64 * 1024
# Linear parsing takes a few milliseconds even at -O0 with ASSERT=all;
# the per-frame shift took seconds.
comptime _MAX_DRAIN_NS = 1_000_000_000


def test_many_tiny_frames_in_one_drain() raises:
    var p = RawPair(stream_window=UInt64(1 << 20))
    var sid = p.cli.open_stream(True)
    var b = headers_get()
    for _ in range(_GREASE_BYTES // 2):
        b.append(0x21)
        b.append(0x00)
    b.append(0x00)  # DATA, 1 byte: proves parsing reached the end
    b.append(0x01)
    b.append(0x5A)
    p.hold_server_events = True
    p.cli.send_stream_data(sid, Span(b), False)
    p.pump(60)
    var t0 = perf_counter_ns()
    p.release_server_events()
    var elapsed = Int(perf_counter_ns() - t0)
    assert_equal_int(p.headers_events, 1, "HEADERS delivered")
    assert_equal_int(len(p.data), 1, "trailing DATA byte delivered")
    assert_equal_int(p.close_code, -1, "reserved frames are not an error")
    assert_true(
        elapsed < _MAX_DRAIN_NS,
        "64 KiB of tiny frames drained in " + String(elapsed // 1_000_000) + " ms",
    )
    print("  test_many_tiny_frames_in_one_drain: PASS (" + String(elapsed // 1_000_000) + " ms)")


def main() raises:
    print("test_h3_frame_parse_cost:")
    test_many_tiny_frames_in_one_drain()
    print("All test_h3_frame_parse_cost tests passed.")
