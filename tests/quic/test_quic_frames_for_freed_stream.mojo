# tests/quic/test_quic_frames_for_freed_stream.mojo
#
# Once a stream is closed and freed, late or duplicate frames for it
# (a RESET_STREAM retransmitted because our ACK was lost, a straggling
# STREAM, STOP_SENDING, MAX_STREAM_DATA) must be ignored (RFC 9000
# Section 3). Raising instead dropped the whole packet unacknowledged,
# so the peer retransmitted it forever and lost every other frame in it.
# Frames for a locally-initiated stream we never opened remain a
# STREAM_STATE_ERROR.

from std.collections import Span
from std.memory import Pointer
from tests._test_util import assert_true, assert_equal_int
from tests.h3._h3_raw_pair import RawPair, headers_get, put_varint
from navette.quic.connection import QuicConnection

comptime _APP_SPACE = 2


def _freed_request(mut p: RawPair) raises -> UInt64:
    """Open a request, reset it from the client and FIN it from the server,
    returning its id once the server has freed it."""
    var sid = p.cli.open_stream(True)
    var h = headers_get()
    p.cli.send_stream_data(sid, Span(h), False)
    p.pump(3)
    p.cli.reset_stream(sid, UInt64(0x10C))
    p.pump(3)
    p.srv.send_data(sid, List[Byte](), True)
    p.pump(4)
    assert_true(
        Int(sid) not in p.srv._quic.stream_map.streams, "server freed the stream"
    )
    return sid


def _late_frames(sid: UInt64) -> List[Byte]:
    """RESET_STREAM, STOP_SENDING, STREAM (FIN), MAX_STREAM_DATA and
    STREAM_DATA_BLOCKED for `sid`, then a PING."""
    var b = List[Byte]()
    b.append(0x04)
    put_varint(b, sid)
    put_varint(b, UInt64(0x10C))
    put_varint(b, UInt64(len(headers_get())))
    b.append(0x05)
    put_varint(b, sid)
    put_varint(b, UInt64(0x10C))
    b.append(0x0F)  # STREAM with OFF, LEN, FIN
    put_varint(b, sid)
    put_varint(b, UInt64(0))
    put_varint(b, UInt64(1))
    b.append(0x00)
    b.append(0x11)
    put_varint(b, sid)
    put_varint(b, UInt64(1 << 20))
    b.append(0x15)
    put_varint(b, sid)
    put_varint(b, UInt64(0))
    b.append(0x01)
    return b^


def _dispatch(mut q: QuicConnection, mut buf: List[Byte], now: UInt64) raises -> Bool:
    """Run `buf` through the frame loop as a 1-RTT payload; the packet is
    recorded as received exactly when this returns."""
    return q._parse_and_dispatch_frames(
        Pointer(to=buf[0]), 0, len(buf), _APP_SPACE, False, now
    )


def test_late_frames_for_freed_peer_stream_are_ignored() raises:
    var p = RawPair()
    var sid = _freed_request(p)
    var opened = p.srv._quic.stream_map.peer_opened_bidi
    var buf = _late_frames(sid)
    var ack_eliciting = _dispatch(p.srv._quic, buf, p.now)
    assert_true(ack_eliciting, "packet accepted and ACK-eliciting")
    assert_true(not p.srv._quic.close.pending, "connection stays open")
    assert_true(
        Int(sid) not in p.srv._quic.stream_map.streams, "stream not resurrected"
    )
    assert_equal_int(
        Int(p.srv._quic.stream_map.peer_opened_bidi), Int(opened), "no new stream"
    )
    # The connection still works end to end afterwards.
    _ = _freed_request(p)
    assert_equal_int(p.close_code, -1, "no protocol error")
    print("  test_late_frames_for_freed_peer_stream_are_ignored: PASS")


def test_late_frames_for_freed_local_stream_are_ignored() raises:
    var p = RawPair()
    var sid = _freed_request(p)
    # Let the client finish reading the server's FIN so it frees its side.
    p.pump(4)
    var ev = p.cli.poll()
    while ev:
        ev = p.cli.poll()
    if Int(sid) in p.cli.stream_map.streams:
        _ = p.cli.recv_stream_data(sid)
    p.pump(2)
    assert_true(Int(sid) not in p.cli.stream_map.streams, "client freed the stream")
    var buf = _late_frames(sid)
    var ack_eliciting = _dispatch(p.cli, buf, p.now)
    assert_true(ack_eliciting, "packet accepted and ACK-eliciting")
    assert_true(not p.cli.close.pending, "connection stays open")
    assert_true(Int(sid) not in p.cli.stream_map.streams, "stream not resurrected")
    print("  test_late_frames_for_freed_local_stream_are_ignored: PASS")


def _expect_state_error(frame: List[Byte], what: String) raises:
    var p = RawPair()
    var buf = frame.copy()
    buf.append(0x01)
    _ = _dispatch(p.srv._quic, buf, p.now)
    assert_true(Bool(p.srv._quic.close.pending), what + ": connection closed")
    assert_equal_int(
        Int(p.srv._quic.close.pending.value().error_code), 0x05,
        what + ": STREAM_STATE_ERROR",
    )


def test_frames_for_never_opened_local_stream_are_errors() raises:
    # Server-initiated bidi id 1: the server has opened no bidi stream.
    var sid = UInt64(1)
    var stream: List[Byte] = [0x0B]
    put_varint(stream, sid)
    put_varint(stream, UInt64(1))
    stream.append(0x00)
    _expect_state_error(stream, "STREAM")
    var reset: List[Byte] = [0x04]
    put_varint(reset, sid)
    put_varint(reset, UInt64(0))
    put_varint(reset, UInt64(0))
    _expect_state_error(reset, "RESET_STREAM")
    var stop: List[Byte] = [0x05]
    put_varint(stop, sid)
    put_varint(stop, UInt64(0))
    _expect_state_error(stop, "STOP_SENDING")
    var msd: List[Byte] = [0x11]
    put_varint(msd, sid)
    put_varint(msd, UInt64(100))
    _expect_state_error(msd, "MAX_STREAM_DATA")
    print("  test_frames_for_never_opened_local_stream_are_errors: PASS")


def main() raises:
    print("test_quic_frames_for_freed_stream:")
    test_late_frames_for_freed_peer_stream_are_ignored()
    test_late_frames_for_freed_local_stream_are_ignored()
    test_frames_for_never_opened_local_stream_are_errors()
    print("All test_quic_frames_for_freed_stream tests passed.")
