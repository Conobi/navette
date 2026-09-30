# tests/quic/test_quic_stream_reset_edges.mojo
#
# Edge cases of aborting a QUIC stream.
#
# - Abandoning a stream the peer reset must not cut off a response whose
#   FIN the application already queued (RFC 9114 Section 4.1.2), whether
#   that FIN is still unframed, was framed and lost, or was acknowledged.

from std.collections import Span
from tests._test_util import assert_true, assert_false, assert_equal_int
from tests.h3._h3_raw_pair import RawPair
from navette.quic.stream import SendState

comptime _CANCELLED = UInt64(0x10C)


def _body(n: Int) -> List[Byte]:
    var b = List[Byte](capacity=n)
    for i in range(n):
        b.append(UInt8(i & 0xFF))
    return b^


def _was_reset(mut p: RawPair, sid: UInt64) raises -> Bool:
    """True if the client's send side of `sid` was reset (or the stream is
    gone because of it)."""
    var ptr = p.cli.stream_map.try_stream_ptr(Int(sid))
    if not ptr:
        return False
    var s = ptr.value()
    return s[].needs_reset_stream or (
        s[].send_state.value() == SendState.RESET_SENT
    )


def test_fin_queued_not_framed_is_not_reset() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    p.cli.send_stream_data(sid, Span(_body(10)), True)
    p.cli.reset_unfinished_stream(sid, _CANCELLED)
    assert_false(_was_reset(p, sid), "queued FIN survives an abandon")
    print("  test_fin_queued_not_framed_is_not_reset: PASS")


def test_fin_framed_and_lost_is_not_reset() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    p.cli.send_stream_data(sid, Span(_body(10)), True)
    var s = p.cli.stream_map.stream_ptr(Int(sid))
    _ = s[].send_buf.value().prepare_frame(1000)
    assert_true(Bool(s[].send_buf.value().fin_offset), "FIN framed")
    s[].send_buf.value().on_loss(UInt64(0), UInt64(10))
    p.cli.reset_unfinished_stream(sid, _CANCELLED)
    assert_false(_was_reset(p, sid), "lost FIN still survives an abandon")
    print("  test_fin_framed_and_lost_is_not_reset: PASS")


def test_fin_framed_and_acked_is_not_reset() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    p.cli.send_stream_data(sid, Span(_body(10)), True)
    p.pump(4)
    p.cli.reset_unfinished_stream(sid, _CANCELLED)
    assert_false(_was_reset(p, sid), "acked FIN is left alone")
    print("  test_fin_framed_and_acked_is_not_reset: PASS")


def test_no_fin_is_reset() raises:
    var p = RawPair()
    var sid = p.cli.open_stream(True)
    p.cli.send_stream_data(sid, Span(_body(10)), False)
    p.cli.reset_unfinished_stream(sid, _CANCELLED)
    assert_true(_was_reset(p, sid), "unfinished send side is reset")
    print("  test_no_fin_is_reset: PASS")


def main() raises:
    print("test_quic_stream_reset_edges:")
    test_fin_queued_not_framed_is_not_reset()
    test_fin_framed_and_lost_is_not_reset()
    test_fin_framed_and_acked_is_not_reset()
    test_no_fin_is_reset()
    print("All test_quic_stream_reset_edges tests passed.")
