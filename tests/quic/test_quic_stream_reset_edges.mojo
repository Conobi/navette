# tests/quic/test_quic_stream_reset_edges.mojo
#
# Edge cases of aborting a QUIC stream.
#
# - Abandoning a stream the peer reset must not cut off a response whose
#   FIN the application already queued (RFC 9114 Section 4.1.2), whether
#   that FIN is still unframed, was framed and lost, or was acknowledged.
# - The final size in the RESET_STREAM we send is the highest offset we
#   ever sent (RFC 9000 Section 4.5), even after loss rewound the send
#   cursor; anything lower makes the peer close with FINAL_SIZE_ERROR.
# - A repeated RESET_STREAM for a stream still in the map is idempotent:
#   the unsent gap is charged to connection flow control once, one
#   STREAM_RESET event is emitted, and the receive state never regresses.
#   A conflicting final size closes the connection with FINAL_SIZE_ERROR
#   instead of dropping the packet.

from std.collections import Span
from std.memory import Pointer
from tests._test_util import assert_true, assert_false, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get, put_varint
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent
from navette.quic.stream import SendState, RecvState

comptime _APP_SPACE = 2

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


def _dispatch(mut q: QuicConnection, mut buf: List[Byte], now: UInt64) raises -> Bool:
    """Run `buf` through the frame loop as a 1-RTT payload."""
    return q._parse_and_dispatch_frames(
        Pointer(to=buf[0]), 0, len(buf), _APP_SPACE, False, now
    )


def _sent_then_lost(mut p: RawPair, fin: Bool) raises -> UInt64:
    """A client stream whose 10 bytes (and FIN if `fin`) were framed and
    then declared lost, rewinding the send cursor to 0."""
    var sid = p.cli.open_stream(True)
    p.cli.send_stream_data(sid, Span(_body(10)), fin)
    var s = p.cli.stream_map.stream_ptr(Int(sid))
    _ = s[].send_buf.value().prepare_frame(1000)
    s[].send_buf.value().on_loss(UInt64(0), UInt64(10))
    assert_equal_int(
        Int(s[].send_buf.value().unsent_offset), 0, "loss rewound the cursor"
    )
    return sid


def _reset_final_size(mut p: RawPair, sid: UInt64) raises -> Int:
    var s = p.cli.stream_map.stream_ptr(Int(sid))
    assert_true(s[].needs_reset_stream, "RESET_STREAM queued")
    return Int(s[].reset_stream_final_size)


def test_reset_after_loss_keeps_sent_final_size() raises:
    var p = RawPair()
    var sid = _sent_then_lost(p, False)
    p.cli.reset_stream(sid, _CANCELLED)
    assert_equal_int(_reset_final_size(p, sid), 10, "final size = bytes sent")
    print("  test_reset_after_loss_keeps_sent_final_size: PASS")


def test_reset_after_partial_resend_keeps_sent_final_size() raises:
    var p = RawPair()
    var sid = _sent_then_lost(p, False)
    var s = p.cli.stream_map.stream_ptr(Int(sid))
    _ = s[].send_buf.value().prepare_frame(4)
    p.cli.reset_stream(sid, _CANCELLED)
    assert_equal_int(_reset_final_size(p, sid), 10, "final size = bytes sent")
    print("  test_reset_after_partial_resend_keeps_sent_final_size: PASS")


def test_reset_after_lost_fin_keeps_fin_offset() raises:
    var p = RawPair()
    var sid = _sent_then_lost(p, True)
    p.cli.reset_stream(sid, _CANCELLED)
    assert_equal_int(_reset_final_size(p, sid), 10, "final size = FIN offset")
    print("  test_reset_after_lost_fin_keeps_fin_offset: PASS")


def test_stop_sending_after_loss_keeps_sent_final_size() raises:
    var p = RawPair()
    var sid = _sent_then_lost(p, False)
    var buf: List[Byte] = [0x05]
    put_varint(buf, sid)
    put_varint(buf, _CANCELLED)
    buf.append(0x01)
    _ = _dispatch(p.cli, buf, p.now)
    assert_equal_int(_reset_final_size(p, sid), 10, "final size = bytes sent")
    print("  test_stop_sending_after_loss_keeps_sent_final_size: PASS")


def _reset_frame(sid: UInt64, final_size: Int) -> List[Byte]:
    """RESET_STREAM for `sid` followed by a PING."""
    var b: List[Byte] = [0x04]
    put_varint(b, sid)
    put_varint(b, _CANCELLED)
    put_varint(b, UInt64(final_size))
    b.append(0x01)
    return b^


def _request_awaiting_response(mut p: RawPair) raises -> UInt64:
    """A request whose headers the server received and has not answered,
    so the server keeps the stream after a peer reset."""
    var sid = p.cli.open_stream(True)
    var h = headers_get()
    p.cli.send_stream_data(sid, Span(h), False)
    p.pump(3)
    assert_true(Int(sid) in p.srv._quic.stream_map.streams, "request open")
    _ = _count_resets(p.srv._quic)
    return sid


def _count_resets(mut q: QuicConnection) -> Int:
    """Drain `q`'s events, counting STREAM_RESET."""
    var n = 0
    var ev = q.poll()
    while ev:
        if ev.value().type_id == QuicEvent.STREAM_RESET:
            n += 1
        ev = q.poll()
    return n


def _recv_state(mut q: QuicConnection, sid: UInt64) raises -> RecvState:
    return q.stream_map.stream_ptr(Int(sid))[].recv_state.value()


def test_duplicate_reset_is_idempotent() raises:
    var p = RawPair()
    var sid = _request_awaiting_response(p)
    var final_size = len(headers_get()) + 1000
    var before = Int(p.srv._quic.stream_map.conn_fc_recv.received)

    var f1 = _reset_frame(sid, final_size)
    _ = _dispatch(p.srv._quic, f1, p.now)
    var f2 = _reset_frame(sid, final_size)
    _ = _dispatch(p.srv._quic, f2, p.now)  # duplicate while Reset Recvd
    assert_equal_int(_count_resets(p.srv._quic), 1, "one STREAM_RESET event")
    assert_true(
        _recv_state(p.srv._quic, sid) == RecvState.RESET_READ, "Reset Read"
    )

    var f3 = _reset_frame(sid, final_size)
    _ = _dispatch(p.srv._quic, f3, p.now)  # duplicate once Reset Read
    assert_equal_int(_count_resets(p.srv._quic), 0, "no second STREAM_RESET")
    assert_true(
        _recv_state(p.srv._quic, sid) == RecvState.RESET_READ,
        "state does not regress to Reset Recvd",
    )
    assert_equal_int(
        Int(p.srv._quic.stream_map.conn_fc_recv.received) - before, 1000,
        "unsent gap charged to connection flow control once",
    )
    assert_true(not p.srv._quic.close.pending, "connection stays open")
    print("  test_duplicate_reset_is_idempotent: PASS")


def _expect_final_size_error(
    mut p: RawPair, sid: UInt64, final_size: Int, what: String
) raises:
    var f = _reset_frame(sid, final_size)
    var raised = False
    try:
        _ = _dispatch(p.srv._quic, f, p.now)
    except:
        raised = True
    assert_false(raised, what + ": handled without raising")
    assert_true(Bool(p.srv._quic.close.pending), what + ": connection closed")
    assert_equal_int(
        Int(p.srv._quic.close.pending.value().error_code), 0x06,
        what + ": FINAL_SIZE_ERROR",
    )


def test_conflicting_reset_final_size_closes() raises:
    var p = RawPair()
    var sid = _request_awaiting_response(p)
    var final_size = len(headers_get()) + 1000
    var f1 = _reset_frame(sid, final_size)
    _ = _dispatch(p.srv._quic, f1, p.now)
    _expect_final_size_error(p, sid, final_size + 1, "changed final size")
    print("  test_conflicting_reset_final_size_closes: PASS")


def test_reset_below_received_closes() raises:
    var p = RawPair()
    var sid = _request_awaiting_response(p)
    _expect_final_size_error(p, sid, 1, "final size below received")
    print("  test_reset_below_received_closes: PASS")


def main() raises:
    print("test_quic_stream_reset_edges:")
    test_fin_queued_not_framed_is_not_reset()
    test_fin_framed_and_lost_is_not_reset()
    test_fin_framed_and_acked_is_not_reset()
    test_no_fin_is_reset()
    test_reset_after_loss_keeps_sent_final_size()
    test_reset_after_partial_resend_keeps_sent_final_size()
    test_reset_after_lost_fin_keeps_fin_offset()
    test_stop_sending_after_loss_keeps_sent_final_size()
    test_duplicate_reset_is_idempotent()
    test_conflicting_reset_final_size_closes()
    test_reset_below_received_closes()
    print("All test_quic_stream_reset_edges tests passed.")
