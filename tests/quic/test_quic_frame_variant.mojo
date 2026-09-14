"""Frame Variant consistency tests.

Verifies that every factory method produces a Frame whose type_id and
active Variant type agree.
"""

from std.sys.info import size_of
from navette.quic.frame import (
    Frame, FramePayload,
    AckFrame, CryptoFrame, StreamFrame, ResetStreamFrame,
    StopSendingFrame, MaxStreamDataFrame, MaxStreamsFrame,
    NewConnectionIdFrame, ConnectionCloseFrame,
    StreamDataBlockedFrame, StreamsBlockedFrame,
    FRAME_PADDING, FRAME_PING, FRAME_ACK, FRAME_CRYPTO,
    FRAME_STREAM_BASE, FRAME_RESET_STREAM, FRAME_STOP_SENDING,
    FRAME_MAX_DATA, FRAME_MAX_STREAM_DATA, FRAME_MAX_STREAMS_BIDI,
    FRAME_DATA_BLOCKED, FRAME_STREAM_DATA_BLOCKED,
    FRAME_STREAMS_BLOCKED_BIDI, FRAME_NEW_CONNECTION_ID,
    FRAME_RETIRE_CONNECTION_ID, FRAME_PATH_CHALLENGE,
    FRAME_PATH_RESPONSE, FRAME_CONNECTION_CLOSE_TRANSPORT,
    FRAME_HANDSHAKE_DONE, FRAME_DATAGRAM, FRAME_DATAGRAM_LEN,
    FRAME_NEW_TOKEN,
)


def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise msg


def test_factory_variant_consistency() raises:
    """Every factory produces a Frame where type_id and active Variant agree."""
    # No-payload frames -> NoneType
    _assert(Frame.padding().payload.isa[NoneType](), "padding")
    _assert(Frame.ping().payload.isa[NoneType](), "ping")
    _assert(Frame.handshake_done().payload.isa[NoneType](), "handshake_done")
    _assert(Frame.unknown(UInt64(0xFF)).payload.isa[NoneType](), "unknown")

    # Struct-payload frames
    var ack = AckFrame()
    _assert(Frame.ack(ack).payload.isa[AckFrame](), "ack")

    var cf = CryptoFrame()
    _assert(Frame.crypto(cf).payload.isa[CryptoFrame](), "crypto")

    var sf = StreamFrame()
    _assert(Frame.stream(sf).payload.isa[StreamFrame](), "stream")

    var rsf = ResetStreamFrame(UInt64(0), UInt64(0), UInt64(0))
    _assert(Frame.reset_stream(rsf).payload.isa[ResetStreamFrame](), "reset_stream")

    var ssf = StopSendingFrame(UInt64(0), UInt64(0))
    _assert(Frame.stop_sending(ssf).payload.isa[StopSendingFrame](), "stop_sending")

    # UInt64-payload frames
    _assert(Frame.max_data(UInt64(100)).payload.isa[UInt64](), "max_data")
    _assert(Frame.data_blocked(UInt64(100)).payload.isa[UInt64](), "data_blocked")
    _assert(Frame.retire_connection_id(UInt64(1)).payload.isa[UInt64](), "retire_cid")

    # MaxStreamDataFrame-payload frames
    var msd = MaxStreamDataFrame(UInt64(0), UInt64(100))
    _assert(Frame.max_stream_data(msd).payload.isa[MaxStreamDataFrame](), "max_stream_data")
    var sdb = StreamDataBlockedFrame(UInt64(0), UInt64(100))
    _assert(Frame.stream_data_blocked(sdb).payload.isa[MaxStreamDataFrame](), "stream_data_blocked")

    # MaxStreamsFrame-payload frames
    var ms = MaxStreamsFrame(UInt64(10), True)
    _assert(Frame.max_streams(ms).payload.isa[MaxStreamsFrame](), "max_streams")
    var sb = StreamsBlockedFrame(UInt64(10), True)
    _assert(Frame.streams_blocked(sb).payload.isa[MaxStreamsFrame](), "streams_blocked")

    # NewConnectionIdFrame
    var ncid = NewConnectionIdFrame()
    _assert(Frame.new_connection_id(ncid).payload.isa[NewConnectionIdFrame](), "new_cid")

    # ConnectionCloseFrame
    var cc = ConnectionCloseFrame()
    _assert(Frame.connection_close(cc).payload.isa[ConnectionCloseFrame](), "conn_close")

    # List[UInt8]-payload frames
    var bytes = List[UInt8]()
    _assert(Frame.new_token(bytes).payload.isa[List[UInt8]](), "new_token")
    var path_bytes = List[UInt8]()
    for i in range(8):
        path_bytes.append(UInt8(i))
    _assert(Frame.path_challenge(path_bytes).payload.isa[List[UInt8]](), "path_challenge")
    _assert(Frame.path_response(path_bytes).payload.isa[List[UInt8]](), "path_response")
    var dg = List[UInt8]()
    _assert(Frame.datagram(dg).payload.isa[List[UInt8]](), "datagram")
    _assert(Frame.datagram_with_len(dg).payload.isa[List[UInt8]](), "datagram_with_len")


def test_frame_copy_independence() raises:
    """Copying a Frame produces an independent value."""
    var orig = Frame.max_data(UInt64(42))
    var copy = Frame(copy=orig)
    _assert(copy.payload.isa[UInt64](), "copy has UInt64 payload")
    _assert(
        copy.payload.unsafe_get[UInt64]() == UInt64(42),
        "copy payload value is 42",
    )
    _assert(copy.type_id == FRAME_MAX_DATA, "copy type_id is MAX_DATA")


def test_accessor_roundtrip() raises:
    """Accessors return the correct typed ref for each factory."""
    var ack = AckFrame()
    ack.largest_ack = UInt64(99)
    var f = Frame.ack(ack)
    _assert(f.as_ack().largest_ack == UInt64(99), "ack accessor")

    var cf = CryptoFrame()
    cf.offset = UInt64(42)
    var f2 = Frame.crypto(cf)
    _assert(f2.as_crypto().offset == UInt64(42), "crypto accessor")

    var f3 = Frame.max_data(UInt64(1000))
    _assert(f3.as_max_data() == UInt64(1000), "max_data accessor")

    var f4 = Frame.retire_connection_id(UInt64(7))
    _assert(f4.as_retire_connection_id() == UInt64(7), "retire_cid accessor")


def test_frame_sizeof_regression_gate() raises:
    """Frame must stay under 120 bytes — prevents reintroduction of the product-type anti-pattern."""
    comptime frame_size = size_of[Frame]()
    _assert(frame_size < 120, "Frame size regression: expected < 120 bytes, got " + String(frame_size))


def main() raises:
    print("test_quic_frame_variant:")

    print("  factory_variant_consistency ...", end="")
    test_factory_variant_consistency()
    print(" PASS")

    print("  frame_copy_independence ...", end="")
    test_frame_copy_independence()
    print(" PASS")

    print("  accessor_roundtrip ...", end="")
    test_accessor_roundtrip()
    print(" PASS")

    print("  frame_sizeof_regression_gate ...", end="")
    test_frame_sizeof_regression_gate()
    print(" PASS")

    print("All test_quic_frame_variant tests passed.")
