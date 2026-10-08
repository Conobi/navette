# src/quic/frame.mojo
# QUIC frame codec — RFC 9000 Section 19.
# Parse/serialize for all 20 QUIC frame types.

from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_at, write_u8_at, varint_decode, varint_len
from navette.quic.cid_buf import CidBuf
from navette.util.byte_vec import ByteVec
from std.memory import OwnedPointer
from std.utils import Variant

# ── Frame type constants (RFC 9000 §19) ──────────────────────────────

comptime FRAME_PADDING: UInt64 = 0x00
comptime FRAME_PING: UInt64 = 0x01
comptime FRAME_ACK: UInt64 = 0x02
comptime FRAME_ACK_ECN: UInt64 = 0x03
comptime FRAME_RESET_STREAM: UInt64 = 0x04
comptime FRAME_STOP_SENDING: UInt64 = 0x05
comptime FRAME_CRYPTO: UInt64 = 0x06
comptime FRAME_NEW_TOKEN: UInt64 = 0x07
comptime FRAME_STREAM_BASE: UInt64 = 0x08  # 0x08-0x0F
comptime FRAME_MAX_DATA: UInt64 = 0x10
comptime FRAME_MAX_STREAM_DATA: UInt64 = 0x11
comptime FRAME_MAX_STREAMS_BIDI: UInt64 = 0x12
comptime FRAME_MAX_STREAMS_UNI: UInt64 = 0x13
comptime FRAME_DATA_BLOCKED: UInt64 = 0x14
comptime FRAME_STREAM_DATA_BLOCKED: UInt64 = 0x15
comptime FRAME_STREAMS_BLOCKED_BIDI: UInt64 = 0x16
comptime FRAME_STREAMS_BLOCKED_UNI: UInt64 = 0x17
comptime FRAME_NEW_CONNECTION_ID: UInt64 = 0x18
comptime FRAME_RETIRE_CONNECTION_ID: UInt64 = 0x19
comptime FRAME_PATH_CHALLENGE: UInt64 = 0x1A
comptime FRAME_PATH_RESPONSE: UInt64 = 0x1B
comptime FRAME_CONNECTION_CLOSE_TRANSPORT: UInt64 = 0x1C
comptime FRAME_CONNECTION_CLOSE_APP: UInt64 = 0x1D
comptime FRAME_HANDSHAKE_DONE: UInt64 = 0x1E
# DATAGRAM extension frame types (RFC 9221 §4).
# 0x30 — DATAGRAM (no length, payload extends to end of packet).
# 0x31 — DATAGRAM_LEN (varint length-prefixed payload).
# Only legal in 1-RTT packets (RFC 9221 §5); the dispatch site is the
# authority for that — `frame_allowed_in_packet_type` returns False for any
# other packet type so the dispatch site can close with PROTOCOL_VIOLATION.
comptime FRAME_DATAGRAM: UInt64 = 0x30
comptime FRAME_DATAGRAM_LEN: UInt64 = 0x31
comptime MAX_ACK_RANGES: Int = 256


# ── Per-frame payload structs ─────────────────────────────────────────
# (FramePayload alias is defined AFTER these structs so all types resolve.)


struct AckRange(Copyable, Movable):
    var gap: UInt64
    var ack_range: UInt64

    def __init__(out self, gap: UInt64, ack_range: UInt64):
        self.gap = gap
        self.ack_range = ack_range

    def __init__(out self, *, other: Self):
        self.gap = other.gap
        self.ack_range = other.ack_range


struct AckFrame(Copyable, Movable):
    var largest_ack: UInt64
    var ack_delay: UInt64
    var first_ack_range: UInt64
    var ranges: List[AckRange]
    var ecn_ect0: UInt64
    var ecn_ect1: UInt64
    var ecn_ce: UInt64
    var has_ecn: Bool

    def __init__(out self):
        self.largest_ack = UInt64(0)
        self.ack_delay = UInt64(0)
        self.first_ack_range = UInt64(0)
        self.ranges = List[AckRange]()
        self.ecn_ect0 = UInt64(0)
        self.ecn_ect1 = UInt64(0)
        self.ecn_ce = UInt64(0)
        self.has_ecn = False

    def __init__(out self, *, other: Self):
        self.largest_ack = other.largest_ack
        self.ack_delay = other.ack_delay
        self.first_ack_range = other.first_ack_range
        self.ranges = List[AckRange](copy=other.ranges)
        self.ecn_ect0 = other.ecn_ect0
        self.ecn_ect1 = other.ecn_ect1
        self.ecn_ce = other.ecn_ce
        self.has_ecn = other.has_ecn


struct CryptoFrame(Copyable, Movable):
    var offset: UInt64
    var data: List[Byte]

    def __init__(out self):
        self.offset = UInt64(0)
        self.data = List[Byte]()

    def __init__(out self, offset: UInt64, data: List[Byte]):
        self.offset = offset
        self.data = List[Byte](copy=data)

    def __init__(out self, *, other: Self):
        self.offset = other.offset
        self.data = List[Byte](copy=other.data)


struct StreamFrame(Copyable, Movable):
    var stream_id: UInt64
    var offset: UInt64
    var data: List[Byte]
    var fin: Bool

    def __init__(out self):
        self.stream_id = UInt64(0)
        self.offset = UInt64(0)
        self.data = List[Byte]()
        self.fin = False

    def __init__(out self, stream_id: UInt64, offset: UInt64, data: List[Byte], fin: Bool):
        self.stream_id = stream_id
        self.offset = offset
        self.data = List[Byte](copy=data)
        self.fin = fin

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.offset = other.offset
        self.data = List[Byte](copy=other.data)
        self.fin = other.fin


struct ResetStreamFrame(Copyable, Movable):
    var stream_id: UInt64
    var error_code: UInt64
    var final_size: UInt64

    def __init__(out self, stream_id: UInt64, error_code: UInt64, final_size: UInt64):
        self.stream_id = stream_id
        self.error_code = error_code
        self.final_size = final_size

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.error_code = other.error_code
        self.final_size = other.final_size


struct StopSendingFrame(Copyable, Movable):
    var stream_id: UInt64
    var error_code: UInt64

    def __init__(out self, stream_id: UInt64, error_code: UInt64):
        self.stream_id = stream_id
        self.error_code = error_code

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.error_code = other.error_code


struct MaxStreamDataFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum


struct MaxStreamsFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi


struct StreamDataBlockedFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum


struct StreamsBlockedFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi


struct NewConnectionIdFrame(Copyable, Movable):
    var sequence: UInt64
    var retire_prior_to: UInt64
    var cid: CidBuf
    var stateless_reset_token: ByteVec[16]

    def __init__(out self):
        self.sequence = UInt64(0)
        self.retire_prior_to = UInt64(0)
        self.cid = CidBuf.empty()
        self.stateless_reset_token = ByteVec[16]()

    def __init__(out self, *, other: Self):
        self.sequence = other.sequence
        self.retire_prior_to = other.retire_prior_to
        self.cid = CidBuf(copy=other.cid)
        self.stateless_reset_token = other.stateless_reset_token.copy()


comptime MAX_CLOSE_REASON_BYTES: Int = 128
"""Inline capacity of a CONNECTION_CLOSE reason phrase, sent or received.

Longer phrases are truncated. Kept inline (not heap) so building or parsing
a close allocates nothing; 128 bytes holds every guard tag plus its detail
text (the longest, a transport-parameter rejection, is about 85 bytes).
"""


struct ConnectionCloseFrame(Copyable, Movable):
    """CONNECTION_CLOSE payload; `reason` holds at most MAX_CLOSE_REASON_BYTES."""

    var is_transport: Bool
    var error_code: UInt64
    var frame_type: UInt64
    var reason: ByteVec[MAX_CLOSE_REASON_BYTES]

    def __init__(out self):
        self.is_transport = True
        self.error_code = UInt64(0)
        self.frame_type = UInt64(0)
        self.reason = ByteVec[MAX_CLOSE_REASON_BYTES]()

    def __init__(out self, *, other: Self):
        self.is_transport = other.is_transport
        self.error_code = other.error_code
        self.frame_type = other.frame_type
        self.reason = other.reason.copy()


struct BoxedCloseFrame(Copyable, Movable):
    """Heap-boxed CONNECTION_CLOSE payload, so its inline reason buffer does
    not inflate every Frame (the variant is as large as its largest member).
    Closes are rare; the one allocation per emitted close is the price."""

    var frame: OwnedPointer[ConnectionCloseFrame]

    def __init__(out self, var frame: ConnectionCloseFrame):
        self.frame = OwnedPointer(frame^)

    def __init__(out self, *, copy: Self):
        self.frame = OwnedPointer(ConnectionCloseFrame(other=copy.frame[]))


# ── Tagged Frame container ────────────────────────────────────────────

comptime FramePayload = Variant[
    NoneType,              # Padding, Ping, HandshakeDone, Unknown
    AckFrame,              # ACK, ACK_ECN
    CryptoFrame,           # CRYPTO
    StreamFrame,           # STREAM 0x08-0x0F
    ResetStreamFrame,      # RESET_STREAM
    StopSendingFrame,      # STOP_SENDING
    UInt64,                # MAX_DATA, DATA_BLOCKED, RETIRE_CID
    MaxStreamDataFrame,    # MAX_STREAM_DATA, STREAM_DATA_BLOCKED
    MaxStreamsFrame,        # MAX_STREAMS_*, STREAMS_BLOCKED_*
    NewConnectionIdFrame,  # NEW_CONNECTION_ID
    BoxedCloseFrame,       # CONNECTION_CLOSE_TRANSPORT/APP
    List[Byte],           # NEW_TOKEN, PATH_CHALLENGE, PATH_RESPONSE, DATAGRAM, DATAGRAM_LEN
]


struct Frame(Copyable, Movable):
    """QUIC frame container with discriminated Variant payload.

    `type_id` identifies the wire frame type (RFC 9000 section 19);
    `payload` holds the active payload via a 12-element Variant.
    Factory methods are the sole construction path, ensuring
    type_id-payload consistency.
    """

    var type_id: UInt64
    var payload: FramePayload

    def __init__(out self, type_id: UInt64, var payload: FramePayload):
        self.type_id = type_id
        self.payload = payload^

    def __init__(out self, *, copy: Self):
        self.type_id = copy.type_id
        self.payload = FramePayload(copy=copy.payload)

    # ── Factory methods ───────────────────────────────────────────────

    @staticmethod
    def padding() -> Frame:
        return Frame(FRAME_PADDING, FramePayload(NoneType()))

    @staticmethod
    def ping() -> Frame:
        return Frame(FRAME_PING, FramePayload(NoneType()))

    @staticmethod
    def ack(f: AckFrame) -> Frame:
        return Frame(
            FRAME_ACK if not f.has_ecn else FRAME_ACK_ECN,
            FramePayload(AckFrame(other=f)),
        )

    @staticmethod
    def crypto(f: CryptoFrame) -> Frame:
        return Frame(FRAME_CRYPTO, FramePayload(CryptoFrame(other=f)))

    @staticmethod
    def stream(f: StreamFrame, type_id: UInt64 = FRAME_STREAM_BASE) -> Frame:
        return Frame(type_id, FramePayload(StreamFrame(other=f)))

    @staticmethod
    def reset_stream(f: ResetStreamFrame) -> Frame:
        return Frame(FRAME_RESET_STREAM, FramePayload(ResetStreamFrame(other=f)))

    @staticmethod
    def stop_sending(f: StopSendingFrame) -> Frame:
        return Frame(FRAME_STOP_SENDING, FramePayload(StopSendingFrame(other=f)))

    @staticmethod
    def max_data(maximum: UInt64) -> Frame:
        return Frame(FRAME_MAX_DATA, FramePayload(maximum))

    @staticmethod
    def max_stream_data(f: MaxStreamDataFrame) -> Frame:
        return Frame(FRAME_MAX_STREAM_DATA, FramePayload(MaxStreamDataFrame(other=f)))

    @staticmethod
    def max_streams(f: MaxStreamsFrame) -> Frame:
        return Frame(
            FRAME_MAX_STREAMS_BIDI if f.bidi else FRAME_MAX_STREAMS_UNI,
            FramePayload(MaxStreamsFrame(other=f)),
        )

    @staticmethod
    def data_blocked(maximum: UInt64) -> Frame:
        return Frame(FRAME_DATA_BLOCKED, FramePayload(maximum))

    @staticmethod
    def stream_data_blocked(f: StreamDataBlockedFrame) -> Frame:
        return Frame(
            FRAME_STREAM_DATA_BLOCKED,
            FramePayload(MaxStreamDataFrame(f.stream_id, f.maximum)),
        )

    @staticmethod
    def streams_blocked(f: StreamsBlockedFrame) -> Frame:
        return Frame(
            FRAME_STREAMS_BLOCKED_BIDI if f.bidi else FRAME_STREAMS_BLOCKED_UNI,
            FramePayload(MaxStreamsFrame(f.maximum, f.bidi)),
        )

    @staticmethod
    def new_connection_id(f: NewConnectionIdFrame) -> Frame:
        return Frame(FRAME_NEW_CONNECTION_ID, FramePayload(NewConnectionIdFrame(other=f)))

    @staticmethod
    def retire_connection_id(sequence: UInt64) -> Frame:
        return Frame(FRAME_RETIRE_CONNECTION_ID, FramePayload(sequence))

    @staticmethod
    def connection_close(f: ConnectionCloseFrame) -> Frame:
        return Frame(
            FRAME_CONNECTION_CLOSE_TRANSPORT if f.is_transport else FRAME_CONNECTION_CLOSE_APP,
            FramePayload(BoxedCloseFrame(ConnectionCloseFrame(other=f))),
        )

    @staticmethod
    def new_token(token: List[Byte]) -> Frame:
        return Frame(FRAME_NEW_TOKEN, FramePayload(List[Byte](copy=token)))

    @staticmethod
    def path_challenge(data: List[Byte]) -> Frame:
        return Frame(FRAME_PATH_CHALLENGE, FramePayload(List[Byte](copy=data)))

    @staticmethod
    def path_response(data: List[Byte]) -> Frame:
        return Frame(FRAME_PATH_RESPONSE, FramePayload(List[Byte](copy=data)))

    @staticmethod
    def handshake_done() -> Frame:
        return Frame(FRAME_HANDSHAKE_DONE, FramePayload(NoneType()))

    @staticmethod
    def datagram(payload: List[Byte]) -> Frame:
        """RFC 9221 DATAGRAM (0x30, no length prefix).

        Payload extends to end of QUIC packet. Not subject to congestion
        control, flow control, or retransmission.
        """
        return Frame(FRAME_DATAGRAM, FramePayload(List[Byte](copy=payload)))

    @staticmethod
    def datagram_with_len(payload: List[Byte]) -> Frame:
        """RFC 9221 DATAGRAM_LEN (0x31, varint length prefix).

        Allows multiplexing with other frames in the same packet.
        Not subject to congestion control, flow control, or retransmission.
        """
        return Frame(FRAME_DATAGRAM_LEN, FramePayload(List[Byte](copy=payload)))

    @staticmethod
    def unknown(type_id: UInt64) -> Frame:
        """Sentinel for unknown QUIC frame types (RFC 9000 section 12.4).

        Preserves the unknown wire `type_id` so the dispatch site can close
        with FRAME_ENCODING_ERROR. No payload is decoded.
        """
        return Frame(type_id, FramePayload(NoneType()))

    # ── Predicates ────────────────────────────────────────────────────

    def is_padding(self) -> Bool:
        return self.type_id == FRAME_PADDING

    def is_ping(self) -> Bool:
        return self.type_id == FRAME_PING

    def is_ack(self) -> Bool:
        return self.type_id == FRAME_ACK or self.type_id == FRAME_ACK_ECN

    def is_crypto(self) -> Bool:
        return self.type_id == FRAME_CRYPTO

    def is_stream(self) -> Bool:
        return (self.type_id & UInt64(0xF8)) == FRAME_STREAM_BASE

    def is_reset_stream(self) -> Bool:
        return self.type_id == FRAME_RESET_STREAM

    def is_stop_sending(self) -> Bool:
        return self.type_id == FRAME_STOP_SENDING

    def is_max_data(self) -> Bool:
        return self.type_id == FRAME_MAX_DATA

    def is_max_stream_data(self) -> Bool:
        return self.type_id == FRAME_MAX_STREAM_DATA

    def is_max_streams(self) -> Bool:
        return self.type_id == FRAME_MAX_STREAMS_BIDI or self.type_id == FRAME_MAX_STREAMS_UNI

    def is_data_blocked(self) -> Bool:
        return self.type_id == FRAME_DATA_BLOCKED

    def is_stream_data_blocked(self) -> Bool:
        return self.type_id == FRAME_STREAM_DATA_BLOCKED

    def is_streams_blocked(self) -> Bool:
        return self.type_id == FRAME_STREAMS_BLOCKED_BIDI or self.type_id == FRAME_STREAMS_BLOCKED_UNI

    def is_new_connection_id(self) -> Bool:
        return self.type_id == FRAME_NEW_CONNECTION_ID

    def is_retire_connection_id(self) -> Bool:
        return self.type_id == FRAME_RETIRE_CONNECTION_ID

    def is_connection_close(self) -> Bool:
        return self.type_id == FRAME_CONNECTION_CLOSE_TRANSPORT or self.type_id == FRAME_CONNECTION_CLOSE_APP

    def is_new_token(self) -> Bool:
        return self.type_id == FRAME_NEW_TOKEN

    def is_path_challenge(self) -> Bool:
        return self.type_id == FRAME_PATH_CHALLENGE

    def is_path_response(self) -> Bool:
        return self.type_id == FRAME_PATH_RESPONSE

    def is_handshake_done(self) -> Bool:
        return self.type_id == FRAME_HANDSHAKE_DONE

    def is_datagram(self) -> Bool:
        """True for either RFC 9221 §4 DATAGRAM variant (0x30 or 0x31)."""
        return self.type_id == FRAME_DATAGRAM or self.type_id == FRAME_DATAGRAM_LEN

    def is_unknown(self) -> Bool:
        """True if `type_id` does not match any RFC 9000 §19 frame type.

        Mirrors the dispatch fall-through in `_dispatch_frame`: returns True
        for everything outside the closed set 0x00..0x1E (with STREAM 0x08-0x0F
        encoded via the FRAME_STREAM_BASE mask). Used by the dispatch site
        to gate the F10 close-transport guard.
        """
        var tid = self.type_id
        if tid <= UInt64(0x07):  # PADDING..NEW_TOKEN (covers ACK/ACK_ECN/RESET/STOP/CRYPTO)
            return False
        if tid >= FRAME_STREAM_BASE and tid <= FRAME_STREAM_BASE + UInt64(7):
            return False
        if tid >= UInt64(0x10) and tid <= UInt64(0x1E):  # MAX_DATA..HANDSHAKE_DONE
            return False
        # DATAGRAM / DATAGRAM_LEN (RFC 9221 §4) — extension frames; not
        # part of RFC 9000 §19's closed set but recognized by this stack.
        if tid == FRAME_DATAGRAM or tid == FRAME_DATAGRAM_LEN:
            return False
        return True

    def wire_len(self) -> Int:
        """Exact serialized length of this frame on the wire."""
        var tid = self.type_id
        if tid == FRAME_PADDING or tid == FRAME_PING or tid == FRAME_HANDSHAKE_DONE:
            return 1
        if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
            ref ack = self.payload.unsafe_get[AckFrame]()
            var n = varint_len(tid) + varint_len(ack.largest_ack) + varint_len(ack.ack_delay)
            n += varint_len(UInt64(len(ack.ranges))) + varint_len(ack.first_ack_range)
            for ref r in ack.ranges:
                n += varint_len(r.gap) + varint_len(r.ack_range)
            if ack.has_ecn:
                n += varint_len(ack.ecn_ect0) + varint_len(ack.ecn_ect1) + varint_len(ack.ecn_ce)
            return n
        if tid == FRAME_RESET_STREAM:
            ref rs = self.payload.unsafe_get[ResetStreamFrame]()
            return 1 + varint_len(rs.stream_id) + varint_len(rs.error_code) + varint_len(rs.final_size)
        if tid == FRAME_STOP_SENDING:
            ref ss = self.payload.unsafe_get[StopSendingFrame]()
            return 1 + varint_len(ss.stream_id) + varint_len(ss.error_code)
        if tid == FRAME_CRYPTO:
            ref cf = self.payload.unsafe_get[CryptoFrame]()
            return 1 + varint_len(cf.offset) + varint_len(UInt64(len(cf.data))) + len(cf.data)
        if tid == FRAME_NEW_TOKEN:
            var token_len = len(self.payload.unsafe_get[List[Byte]]())
            return 1 + varint_len(UInt64(token_len)) + token_len
        if (tid & UInt64(0xF8)) == FRAME_STREAM_BASE:
            ref sf = self.payload.unsafe_get[StreamFrame]()
            var n = 1 + varint_len(sf.stream_id)
            if sf.offset != UInt64(0):
                n += varint_len(sf.offset)
            return n + varint_len(UInt64(len(sf.data))) + len(sf.data)
        if tid == FRAME_MAX_DATA or tid == FRAME_DATA_BLOCKED:
            return 1 + varint_len(self.payload.unsafe_get[UInt64]())
        if tid == FRAME_MAX_STREAM_DATA or tid == FRAME_STREAM_DATA_BLOCKED:
            ref msd = self.payload.unsafe_get[MaxStreamDataFrame]()
            return 1 + varint_len(msd.stream_id) + varint_len(msd.maximum)
        if (tid == FRAME_MAX_STREAMS_BIDI or tid == FRAME_MAX_STREAMS_UNI
                or tid == FRAME_STREAMS_BLOCKED_BIDI or tid == FRAME_STREAMS_BLOCKED_UNI):
            return 1 + varint_len(self.payload.unsafe_get[MaxStreamsFrame]().maximum)
        if tid == FRAME_NEW_CONNECTION_ID:
            ref ncid = self.payload.unsafe_get[NewConnectionIdFrame]()
            return (1 + varint_len(ncid.sequence) + varint_len(ncid.retire_prior_to)
                    + 1 + len(ncid.cid) + len(ncid.stateless_reset_token))
        if tid == FRAME_RETIRE_CONNECTION_ID:
            return 1 + varint_len(self.payload.unsafe_get[UInt64]())
        if tid == FRAME_PATH_CHALLENGE or tid == FRAME_PATH_RESPONSE:
            return 1 + len(self.payload.unsafe_get[List[Byte]]())
        if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
            ref cc = self.payload.unsafe_get[BoxedCloseFrame]().frame[]
            var n = 1 + varint_len(cc.error_code)
            if cc.is_transport:
                n += varint_len(cc.frame_type)
            return n + varint_len(UInt64(len(cc.reason))) + len(cc.reason)
        if tid == FRAME_DATAGRAM:
            return 1 + len(self.payload.unsafe_get[List[Byte]]())
        if tid == FRAME_DATAGRAM_LEN:
            var dl = len(self.payload.unsafe_get[List[Byte]]())
            return 1 + varint_len(UInt64(dl)) + dl
        return 0

    def is_ack_eliciting(self) -> Bool:
        # ACK-eliciting: everything EXCEPT PADDING, ACK/ACK_ECN, CONNECTION_CLOSE
        if self.type_id == FRAME_PADDING:
            return False
        if self.type_id == FRAME_ACK or self.type_id == FRAME_ACK_ECN:
            return False
        if self.type_id == FRAME_CONNECTION_CLOSE_TRANSPORT or self.type_id == FRAME_CONNECTION_CLOSE_APP:
            return False
        return True

    # ── Accessors ─────────────────────────────────────────────────────

    def as_ack(self) raises -> ref [self.payload] AckFrame:
        if not self.payload.isa[AckFrame]():
            raise "Frame is not an ACK frame"
        return self.payload.unsafe_get[AckFrame]()

    def as_crypto(self) raises -> ref [self.payload] CryptoFrame:
        if not self.payload.isa[CryptoFrame]():
            raise "Frame is not a CRYPTO frame"
        return self.payload.unsafe_get[CryptoFrame]()

    def as_stream(self) raises -> ref [self.payload] StreamFrame:
        if not self.payload.isa[StreamFrame]():
            raise "Frame is not a STREAM frame"
        return self.payload.unsafe_get[StreamFrame]()

    def as_reset_stream(self) raises -> ref [self.payload] ResetStreamFrame:
        if not self.payload.isa[ResetStreamFrame]():
            raise "Frame is not a RESET_STREAM frame"
        return self.payload.unsafe_get[ResetStreamFrame]()

    def as_stop_sending(self) raises -> ref [self.payload] StopSendingFrame:
        if not self.payload.isa[StopSendingFrame]():
            raise "Frame is not a STOP_SENDING frame"
        return self.payload.unsafe_get[StopSendingFrame]()

    def as_max_data(self) raises -> UInt64:
        if not self.payload.isa[UInt64]():
            raise "Frame is not a MAX_DATA/DATA_BLOCKED frame"
        return self.payload.unsafe_get[UInt64]()

    def as_max_stream_data(self) raises -> ref [self.payload] MaxStreamDataFrame:
        if not self.payload.isa[MaxStreamDataFrame]():
            raise "Frame is not a MAX_STREAM_DATA/STREAM_DATA_BLOCKED frame"
        return self.payload.unsafe_get[MaxStreamDataFrame]()

    def as_max_streams(self) raises -> ref [self.payload] MaxStreamsFrame:
        if not self.payload.isa[MaxStreamsFrame]():
            raise "Frame is not a MAX_STREAMS/STREAMS_BLOCKED frame"
        return self.payload.unsafe_get[MaxStreamsFrame]()

    def as_new_connection_id(self) raises -> ref [self.payload] NewConnectionIdFrame:
        if not self.payload.isa[NewConnectionIdFrame]():
            raise "Frame is not a NEW_CONNECTION_ID frame"
        return self.payload.unsafe_get[NewConnectionIdFrame]()

    def as_retire_connection_id(self) raises -> UInt64:
        if not self.payload.isa[UInt64]():
            raise "Frame is not a RETIRE_CONNECTION_ID frame"
        return self.payload.unsafe_get[UInt64]()

    def as_connection_close(self) raises -> ref [self.payload.unsafe_get[BoxedCloseFrame]().frame[]] ConnectionCloseFrame:
        if not self.payload.isa[BoxedCloseFrame]():
            raise "Frame is not a CONNECTION_CLOSE frame"
        return self.payload.unsafe_get[BoxedCloseFrame]().frame[]

    def as_new_token(self) raises -> ref [self.payload] List[Byte]:
        if not self.payload.isa[List[Byte]]():
            raise "Frame is not a NEW_TOKEN frame"
        return self.payload.unsafe_get[List[Byte]]()

    def as_path_data(self) raises -> ref [self.payload] List[Byte]:
        if not self.payload.isa[List[Byte]]():
            raise "Frame is not a PATH_CHALLENGE/PATH_RESPONSE frame"
        return self.payload.unsafe_get[List[Byte]]()

    def as_datagram_payload(self) raises -> ref [self.payload] List[Byte]:
        """Both DATAGRAM wire variants (0x30 and 0x31) share this accessor."""
        if not self.payload.isa[List[Byte]]():
            raise "Frame is not a DATAGRAM frame"
        return self.payload.unsafe_get[List[Byte]]()


# ── Parse functions ───────────────────────────────────────────────────


def parse_frame[origin: Origin](mut reader: ByteReader[origin]) raises -> Frame:
    var frame_type = varint_decode(reader)
    return parse_frame_with_type(reader, frame_type)


def parse_frame_with_type[origin: Origin](mut reader: ByteReader[origin], frame_type: UInt64) raises -> Frame:
    """Parse a frame whose type varint has already been consumed."""

    # PADDING (0x00): consume consecutive padding bytes
    if frame_type == FRAME_PADDING:
        while reader.remaining() > 0:
            var next_byte = reader.peek_u8()
            if next_byte != UInt8(0):
                break
            _ = reader.read_u8()
        return Frame.padding()

    # PING (0x01)
    if frame_type == FRAME_PING:
        return Frame.ping()

    # ACK (0x02) / ACK_ECN (0x03)
    if frame_type == FRAME_ACK or frame_type == FRAME_ACK_ECN:
        var ack = AckFrame()
        ack.largest_ack = varint_decode(reader)
        ack.ack_delay = varint_decode(reader)
        var ack_range_count = varint_decode(reader)
        ack.first_ack_range = varint_decode(reader)
        if ack.first_ack_range > ack.largest_ack:
            raise "ACK: first_ack_range exceeds largest_ack"
        var count = Int(ack_range_count)
        if count > MAX_ACK_RANGES:
            raise "ACK: range count " + String(count) + " exceeds maximum " + String(MAX_ACK_RANGES)
        # Track running PN for underflow detection
        var smallest_ack = ack.largest_ack - ack.first_ack_range
        for _ in range(count):
            var gap = varint_decode(reader)
            var ack_range = varint_decode(reader)
            # gap+2 accounts for the implicit 1-packet gap between ranges
            var needed = gap + 2 + ack_range
            if needed > smallest_ack:
                raise "ACK: range underflow (gap+range exceeds remaining PN space)"
            smallest_ack = smallest_ack - needed
            ack.ranges.append(AckRange(gap, ack_range))
        if frame_type == FRAME_ACK_ECN:
            ack.ecn_ect0 = varint_decode(reader)
            ack.ecn_ect1 = varint_decode(reader)
            ack.ecn_ce = varint_decode(reader)
            ack.has_ecn = True
        return Frame(
            FRAME_ACK if not ack.has_ecn else FRAME_ACK_ECN,
            FramePayload(ack^),
        )

    # RESET_STREAM (0x04)
    if frame_type == FRAME_RESET_STREAM:
        var stream_id = varint_decode(reader)
        var error_code = varint_decode(reader)
        var final_size = varint_decode(reader)
        return Frame.reset_stream(ResetStreamFrame(stream_id, error_code, final_size))

    # STOP_SENDING (0x05)
    if frame_type == FRAME_STOP_SENDING:
        var stream_id = varint_decode(reader)
        var error_code = varint_decode(reader)
        return Frame.stop_sending(StopSendingFrame(stream_id, error_code))

    # CRYPTO (0x06)
    if frame_type == FRAME_CRYPTO:
        var offset = varint_decode(reader)
        var length = varint_decode(reader)
        var data = reader.read_bytes(Int(length))
        var cf = CryptoFrame()
        cf.offset = offset
        cf.data = data^
        return Frame(FRAME_CRYPTO, FramePayload(cf^))

    # NEW_TOKEN (0x07)
    if frame_type == FRAME_NEW_TOKEN:
        var token_length = varint_decode(reader)
        var token = reader.read_bytes(Int(token_length))
        return Frame(FRAME_NEW_TOKEN, FramePayload(token^))

    # STREAM (0x08-0x0F)
    if (frame_type & UInt64(0xF8)) == FRAME_STREAM_BASE:
        var has_off = Bool(frame_type & UInt64(0x04))
        var has_len = Bool(frame_type & UInt64(0x02))
        var has_fin = Bool(frame_type & UInt64(0x01))
        var stream_id = varint_decode(reader)
        var offset = UInt64(0)
        if has_off:
            offset = varint_decode(reader)
        var data: List[Byte]
        if has_len:
            var length = varint_decode(reader)
            data = reader.read_bytes(Int(length))
        else:
            data = reader.read_bytes(reader.remaining())
        var sf = StreamFrame()
        sf.stream_id = stream_id
        sf.offset = offset
        sf.data = data^
        sf.fin = has_fin
        return Frame(frame_type, FramePayload(sf^))

    # MAX_DATA (0x10)
    if frame_type == FRAME_MAX_DATA:
        var maximum = varint_decode(reader)
        return Frame.max_data(maximum)

    # MAX_STREAM_DATA (0x11)
    if frame_type == FRAME_MAX_STREAM_DATA:
        var stream_id = varint_decode(reader)
        var maximum = varint_decode(reader)
        return Frame.max_stream_data(MaxStreamDataFrame(stream_id, maximum))

    # MAX_STREAMS_BIDI (0x12) / MAX_STREAMS_UNI (0x13)
    if frame_type == FRAME_MAX_STREAMS_BIDI or frame_type == FRAME_MAX_STREAMS_UNI:
        var maximum = varint_decode(reader)
        var bidi = frame_type == FRAME_MAX_STREAMS_BIDI
        return Frame.max_streams(MaxStreamsFrame(maximum, bidi))

    # DATA_BLOCKED (0x14)
    if frame_type == FRAME_DATA_BLOCKED:
        var maximum = varint_decode(reader)
        return Frame.data_blocked(maximum)

    # STREAM_DATA_BLOCKED (0x15)
    if frame_type == FRAME_STREAM_DATA_BLOCKED:
        var stream_id = varint_decode(reader)
        var maximum = varint_decode(reader)
        return Frame.stream_data_blocked(StreamDataBlockedFrame(stream_id, maximum))

    # STREAMS_BLOCKED_BIDI (0x16) / STREAMS_BLOCKED_UNI (0x17)
    if frame_type == FRAME_STREAMS_BLOCKED_BIDI or frame_type == FRAME_STREAMS_BLOCKED_UNI:
        var maximum = varint_decode(reader)
        var bidi = frame_type == FRAME_STREAMS_BLOCKED_BIDI
        return Frame.streams_blocked(StreamsBlockedFrame(maximum, bidi))

    # NEW_CONNECTION_ID (0x18)
    if frame_type == FRAME_NEW_CONNECTION_ID:
        # The parser surfaces RFC 9000 §19.15 wire-encoding violations
        # (`retire_prior_to > sequence` and `cid_length` outside 1..20)
        # to the dispatch site via the parsed struct rather than raising.
        # The F22 and F23 guards at connection.mojo:FRAME_NEW_CONNECTION_ID
        # close the connection with FRAME_ENCODING_ERROR. A `cid_length`
        # above 20 still raises because the read would consume more
        # bytes than RFC 9000 allows; the dispatch-level guard is what
        # surfaces the F23 reason on a zero-length CID.
        var ncid = NewConnectionIdFrame()
        ncid.sequence = varint_decode(reader)
        ncid.retire_prior_to = varint_decode(reader)
        var cid_length = Int(reader.read_u8())
        if cid_length > 20:
            raise "NEW_CONNECTION_ID: cid_length must be <= 20"
        ncid.cid = CidBuf.from_span(reader.read_span(cid_length))
        var srt_span = reader.read_span(16)
        ncid.stateless_reset_token.extend(srt_span)
        return Frame(FRAME_NEW_CONNECTION_ID, FramePayload(ncid^))

    # RETIRE_CONNECTION_ID (0x19)
    if frame_type == FRAME_RETIRE_CONNECTION_ID:
        var sequence = varint_decode(reader)
        return Frame.retire_connection_id(sequence)

    # PATH_CHALLENGE (0x1A)
    if frame_type == FRAME_PATH_CHALLENGE:
        var data = reader.read_bytes(8)
        return Frame(FRAME_PATH_CHALLENGE, FramePayload(data^))

    # PATH_RESPONSE (0x1B)
    if frame_type == FRAME_PATH_RESPONSE:
        var data = reader.read_bytes(8)
        return Frame(FRAME_PATH_RESPONSE, FramePayload(data^))

    # CONNECTION_CLOSE (0x1C / 0x1D)
    if frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT or frame_type == FRAME_CONNECTION_CLOSE_APP:
        var cc = ConnectionCloseFrame()
        cc.is_transport = frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT
        cc.error_code = varint_decode(reader)
        if cc.is_transport:
            cc.frame_type = varint_decode(reader)
        var reason_length = varint_decode(reader)
        var reason_span = reader.read_span(Int(reason_length))
        _ = cc.reason.extend_truncated(reason_span)
        return Frame(
            FRAME_CONNECTION_CLOSE_TRANSPORT if cc.is_transport else FRAME_CONNECTION_CLOSE_APP,
            FramePayload(BoxedCloseFrame(cc^)),
        )

    # HANDSHAKE_DONE (0x1E)
    if frame_type == FRAME_HANDSHAKE_DONE:
        return Frame.handshake_done()

    # DATAGRAM (0x30) — RFC 9221 §4. No length prefix; the payload extends
    # to the end of the QUIC packet. The dispatch-site permission check
    # (`frame_allowed_in_packet_type`) restricts this to 1-RTT packets;
    # at the parse layer we trust the caller to have framed the reader to
    # the packet boundary, so consuming all remaining bytes is correct.
    if frame_type == FRAME_DATAGRAM:
        var data = reader.read_bytes(reader.remaining())
        return Frame(FRAME_DATAGRAM, FramePayload(data^))

    # DATAGRAM_LEN (0x31) — RFC 9221 §4. Length-prefixed variant; reads
    # exactly `length` bytes. Allows multiplexing with other frames in the
    # same packet.
    if frame_type == FRAME_DATAGRAM_LEN:
        var length = varint_decode(reader)
        var data = reader.read_bytes(Int(length))
        return Frame(FRAME_DATAGRAM_LEN, FramePayload(data^))

    # F10 — RFC 9000 §12.4: unknown frame type. Surface the unknown type
    # back to the caller via the `Frame.unknown` sentinel so the dispatch
    # site can close with FRAME_ENCODING_ERROR (0x07) without aborting
    # parse_frames mid-packet. Returning instead of raising preserves the
    # coalesced-packet decode invariants in connection.recv_from_buffer.
    return Frame.unknown(frame_type)


def parse_frames[origin: Origin](mut reader: ByteReader[origin]) raises -> List[Frame]:
    var frames = List[Frame]()
    while reader.remaining() > 0:
        frames.append(parse_frame(reader))
    return frames^


# ── Serialize functions ───────────────────────────────────────────────


def serialize_frame(frame: Frame, mut writer: ByteWriter) raises:
    var tid = frame.type_id

    # PADDING
    if tid == FRAME_PADDING:
        varint_encode(writer, FRAME_PADDING)
        return

    # PING
    if tid == FRAME_PING:
        varint_encode(writer, FRAME_PING)
        return

    # ACK / ACK_ECN
    if tid == FRAME_ACK or tid == FRAME_ACK_ECN:
        ref ack = frame.as_ack()
        varint_encode(writer, tid)
        varint_encode(writer, ack.largest_ack)
        varint_encode(writer, ack.ack_delay)
        varint_encode(writer, UInt64(len(ack.ranges)))
        varint_encode(writer, ack.first_ack_range)
        for ref r in ack.ranges:
            varint_encode(writer, r.gap)
            varint_encode(writer, r.ack_range)
        if ack.has_ecn:
            varint_encode(writer, ack.ecn_ect0)
            varint_encode(writer, ack.ecn_ect1)
            varint_encode(writer, ack.ecn_ce)
        return

    # RESET_STREAM
    if tid == FRAME_RESET_STREAM:
        ref rs = frame.as_reset_stream()
        varint_encode(writer, FRAME_RESET_STREAM)
        varint_encode(writer, rs.stream_id)
        varint_encode(writer, rs.error_code)
        varint_encode(writer, rs.final_size)
        return

    # STOP_SENDING
    if tid == FRAME_STOP_SENDING:
        ref ss = frame.as_stop_sending()
        varint_encode(writer, FRAME_STOP_SENDING)
        varint_encode(writer, ss.stream_id)
        varint_encode(writer, ss.error_code)
        return

    # CRYPTO
    if tid == FRAME_CRYPTO:
        ref cf = frame.as_crypto()
        varint_encode(writer, FRAME_CRYPTO)
        varint_encode(writer, cf.offset)
        varint_encode(writer, UInt64(len(cf.data)))
        writer.write_bytes(Span[Byte, origin_of(cf.data)](cf.data))
        return

    # NEW_TOKEN
    if tid == FRAME_NEW_TOKEN:
        ref token = frame.as_new_token()
        varint_encode(writer, FRAME_NEW_TOKEN)
        varint_encode(writer, UInt64(len(token)))
        writer.write_bytes(Span[Byte, origin_of(token)](token))
        return

    # STREAM (0x08-0x0F): always set LEN bit
    if (tid & UInt64(0xF8)) == FRAME_STREAM_BASE:
        ref sf = frame.as_stream()
        # Compute type byte: OFF if offset != 0, LEN always set, FIN from frame
        var stype = FRAME_STREAM_BASE | UInt64(0x02)  # LEN bit always set
        if sf.offset != UInt64(0):
            stype = stype | UInt64(0x04)
        if sf.fin:
            stype = stype | UInt64(0x01)
        varint_encode(writer, stype)
        varint_encode(writer, sf.stream_id)
        if sf.offset != UInt64(0):
            varint_encode(writer, sf.offset)
        varint_encode(writer, UInt64(len(sf.data)))
        writer.write_bytes(Span[Byte, origin_of(sf.data)](sf.data))
        return

    # MAX_DATA
    if tid == FRAME_MAX_DATA:
        varint_encode(writer, FRAME_MAX_DATA)
        varint_encode(writer, frame.as_max_data())
        return

    # MAX_STREAM_DATA
    if tid == FRAME_MAX_STREAM_DATA:
        ref msd = frame.as_max_stream_data()
        varint_encode(writer, FRAME_MAX_STREAM_DATA)
        varint_encode(writer, msd.stream_id)
        varint_encode(writer, msd.maximum)
        return

    # MAX_STREAMS_BIDI / MAX_STREAMS_UNI
    if tid == FRAME_MAX_STREAMS_BIDI or tid == FRAME_MAX_STREAMS_UNI:
        ref ms = frame.as_max_streams()
        varint_encode(writer, tid)
        varint_encode(writer, ms.maximum)
        return

    # DATA_BLOCKED
    if tid == FRAME_DATA_BLOCKED:
        varint_encode(writer, FRAME_DATA_BLOCKED)
        varint_encode(writer, frame.as_max_data())
        return

    # STREAM_DATA_BLOCKED
    if tid == FRAME_STREAM_DATA_BLOCKED:
        ref msd = frame.as_max_stream_data()
        varint_encode(writer, FRAME_STREAM_DATA_BLOCKED)
        varint_encode(writer, msd.stream_id)
        varint_encode(writer, msd.maximum)
        return

    # STREAMS_BLOCKED_BIDI / STREAMS_BLOCKED_UNI
    if tid == FRAME_STREAMS_BLOCKED_BIDI or tid == FRAME_STREAMS_BLOCKED_UNI:
        ref ms = frame.as_max_streams()
        varint_encode(writer, tid)
        varint_encode(writer, ms.maximum)
        return

    # NEW_CONNECTION_ID
    if tid == FRAME_NEW_CONNECTION_ID:
        ref ncid = frame.as_new_connection_id()
        varint_encode(writer, FRAME_NEW_CONNECTION_ID)
        varint_encode(writer, ncid.sequence)
        varint_encode(writer, ncid.retire_prior_to)
        writer.write_u8(UInt8(len(ncid.cid)))
        writer.write_bytes(ncid.cid.as_span())
        writer.write_bytes(ncid.stateless_reset_token.as_span())
        return

    # RETIRE_CONNECTION_ID
    if tid == FRAME_RETIRE_CONNECTION_ID:
        varint_encode(writer, FRAME_RETIRE_CONNECTION_ID)
        varint_encode(writer, frame.as_retire_connection_id())
        return

    # PATH_CHALLENGE
    if tid == FRAME_PATH_CHALLENGE:
        ref data = frame.as_path_data()
        varint_encode(writer, FRAME_PATH_CHALLENGE)
        writer.write_bytes(Span[Byte, origin_of(data)](data))
        return

    # PATH_RESPONSE
    if tid == FRAME_PATH_RESPONSE:
        ref data = frame.as_path_data()
        varint_encode(writer, FRAME_PATH_RESPONSE)
        writer.write_bytes(Span[Byte, origin_of(data)](data))
        return

    # CONNECTION_CLOSE
    if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
        ref cc = frame.as_connection_close()
        varint_encode(writer, tid)
        varint_encode(writer, cc.error_code)
        if cc.is_transport:
            varint_encode(writer, cc.frame_type)
        varint_encode(writer, UInt64(len(cc.reason)))
        writer.write_bytes(cc.reason.as_span())
        return

    # HANDSHAKE_DONE
    if tid == FRAME_HANDSHAKE_DONE:
        varint_encode(writer, FRAME_HANDSHAKE_DONE)
        return

    # DATAGRAM (0x30) — RFC 9221 §4. No length prefix; payload to end of packet.
    if tid == FRAME_DATAGRAM:
        ref data = frame.as_datagram_payload()
        varint_encode(writer, FRAME_DATAGRAM)
        writer.write_bytes(Span[Byte, origin_of(data)](data))
        return

    # DATAGRAM_LEN (0x31) — RFC 9221 §4. Length-prefixed payload.
    if tid == FRAME_DATAGRAM_LEN:
        ref data = frame.as_datagram_payload()
        varint_encode(writer, FRAME_DATAGRAM_LEN)
        varint_encode(writer, UInt64(len(data)))
        writer.write_bytes(Span[Byte, origin_of(data)](data))
        return

    raise "serialize_frame: unknown frame type: " + String(Int(tid))


def serialize_frames(frames: List[Frame], mut writer: ByteWriter) raises:
    for ref frame in frames:
        serialize_frame(frame, writer)


# ── Packet-type permission check (RFC 9000 §12.4, erratum #7365) ─────


def frame_allowed_in_packet_type(frame_type: UInt64, packet_type_value: UInt8) -> Bool:
    # Packet type values: 0=Initial, 1=ZeroRTT, 2=Handshake, 4=OneRTT
    var initial = packet_type_value == UInt8(0)
    var zero_rtt = packet_type_value == UInt8(1)
    var handshake = packet_type_value == UInt8(2)
    var one_rtt = packet_type_value == UInt8(4)

    # PADDING, PING: all packet types
    if frame_type == FRAME_PADDING or frame_type == FRAME_PING:
        return True

    # ACK, ACK_ECN: Initial, Handshake, 1-RTT (NOT 0-RTT)
    if frame_type == FRAME_ACK or frame_type == FRAME_ACK_ECN:
        return initial or handshake or one_rtt

    # CRYPTO: Initial, Handshake, 1-RTT (NOT 0-RTT)
    if frame_type == FRAME_CRYPTO:
        return initial or handshake or one_rtt

    # NEW_TOKEN: 1-RTT only
    if frame_type == FRAME_NEW_TOKEN:
        return one_rtt

    # STREAM (0x08-0x0F): 0-RTT, 1-RTT
    if (frame_type & UInt64(0xF8)) == FRAME_STREAM_BASE:
        return zero_rtt or one_rtt

    # RESET_STREAM, STOP_SENDING: 0-RTT, 1-RTT
    if frame_type == FRAME_RESET_STREAM or frame_type == FRAME_STOP_SENDING:
        return zero_rtt or one_rtt

    # MAX_DATA, MAX_STREAM_DATA: 0-RTT, 1-RTT
    if frame_type == FRAME_MAX_DATA or frame_type == FRAME_MAX_STREAM_DATA:
        return zero_rtt or one_rtt

    # MAX_STREAMS: 0-RTT, 1-RTT
    if frame_type == FRAME_MAX_STREAMS_BIDI or frame_type == FRAME_MAX_STREAMS_UNI:
        return zero_rtt or one_rtt

    # DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED: 0-RTT, 1-RTT
    if frame_type == FRAME_DATA_BLOCKED or frame_type == FRAME_STREAM_DATA_BLOCKED:
        return zero_rtt or one_rtt
    if frame_type == FRAME_STREAMS_BLOCKED_BIDI or frame_type == FRAME_STREAMS_BLOCKED_UNI:
        return zero_rtt or one_rtt

    # NEW_CONNECTION_ID, RETIRE_CONNECTION_ID: 0-RTT, 1-RTT
    # Erratum #7365: NEW_CONNECTION_ID is also allowed in 0-RTT
    if frame_type == FRAME_NEW_CONNECTION_ID or frame_type == FRAME_RETIRE_CONNECTION_ID:
        return zero_rtt or one_rtt

    # PATH_CHALLENGE, PATH_RESPONSE: 0-RTT, 1-RTT
    # Erratum #7365: PATH_CHALLENGE/PATH_RESPONSE allowed in 0-RTT
    if frame_type == FRAME_PATH_CHALLENGE or frame_type == FRAME_PATH_RESPONSE:
        return zero_rtt or one_rtt

    # CONNECTION_CLOSE (transport): Initial, Handshake, 1-RTT (NOT 0-RTT)
    # CONNECTION_CLOSE (app): 0-RTT, 1-RTT
    if frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT:
        return initial or handshake or one_rtt
    if frame_type == FRAME_CONNECTION_CLOSE_APP:
        return zero_rtt or one_rtt

    # HANDSHAKE_DONE: 1-RTT only
    if frame_type == FRAME_HANDSHAKE_DONE:
        return one_rtt

    # DATAGRAM / DATAGRAM_LEN: 1-RTT only (RFC 9221 §5 — DATAGRAMs MUST NOT
    # appear in Initial or Handshake packets; 0-RTT carries app data that is
    # forward-secured separately and is out of scope for this server-only
    # implementation, so deny it here as well).
    if frame_type == FRAME_DATAGRAM or frame_type == FRAME_DATAGRAM_LEN:
        return one_rtt

    return False
struct FrameCursor[origin: Origin]:
    """Zero-alloc frame iterator returning type_id scalars.

    Populates flat scalar fields instead of constructing Frame values.
    No Variant construction, Optional[Frame] wrapping, or destroy overhead.

    ACK ranges go into _ack_buf (read via ack_ranges_span());
    CC reason / STREAM / CRYPTO / token / path data go into _byte_data
    (read via byte_data_span()), borrowing directly from the packet buffer.
    """

    var _buf: Span[Byte, Self.origin]
    var _pos: Int
    var _count: Int
    var _ack_buf: InlineArray[AckRange, MAX_ACK_RANGES]
    var _ack_buf_len: Int
    var _byte_data: Span[Byte, Self.origin]
    var type_id: UInt64
    var stream_id: UInt64
    var offset: UInt64
    var fin: Bool
    var error_code: UInt64
    var final_size: UInt64
    var is_transport: Bool
    var frame_type_field: UInt64
    var maximum: UInt64
    var bidi: Bool
    var sequence: UInt64
    var retire_prior_to: UInt64
    var largest_ack: UInt64
    var ack_delay: UInt64
    var first_ack_range: UInt64
    var has_ecn: Bool
    var ecn_ect0: UInt64
    var ecn_ect1: UInt64
    var ecn_ce: UInt64

    def __init__(out self, buf: Span[Byte, Self.origin]):
        """Create a cursor over the given payload bytes."""
        self._buf = buf
        self._pos = 0
        self._count = 0
        self._ack_buf = InlineArray[AckRange, MAX_ACK_RANGES](uninitialized=True)
        self._ack_buf_len = 0
        self._byte_data = Span[Byte, Self.origin]()
        self.type_id = UInt64(0)
        self.stream_id = UInt64(0)
        self.offset = UInt64(0)
        self.fin = False
        self.error_code = UInt64(0)
        self.final_size = UInt64(0)
        self.is_transport = False
        self.frame_type_field = UInt64(0)
        self.maximum = UInt64(0)
        self.bidi = False
        self.sequence = UInt64(0)
        self.retire_prior_to = UInt64(0)
        self.largest_ack = UInt64(0)
        self.ack_delay = UInt64(0)
        self.first_ack_range = UInt64(0)
        self.has_ecn = False
        self.ecn_ect0 = UInt64(0)
        self.ecn_ect1 = UInt64(0)
        self.ecn_ce = UInt64(0)

    def next(mut self) raises -> Optional[UInt64]:
        """Return the next frame's type_id, or None when exhausted.

        Populates flat scalar fields on the cursor for the dispatch site
        to read directly.  No Frame/Variant/Optional[Frame] overhead.
        """
        if self._pos >= len(self._buf):
            return None
        self._ack_buf_len = 0
        self._byte_data = Span[Byte, Self.origin]()
        var reader = ByteReader(self._buf)
        reader.pos = self._pos
        var frame_type = varint_decode(reader)

        # PADDING (0x00): one raise-free scan; per-byte reads dominated padded Initials.
        if frame_type == FRAME_PADDING:
            var pos = reader.pos
            for b in self._buf[pos:]:
                if b != 0:
                    break
                pos += 1
            self.type_id = FRAME_PADDING
            self._pos = pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # PING (0x01)
        if frame_type == FRAME_PING:
            self.type_id = FRAME_PING
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # ACK (0x02) / ACK_ECN (0x03)
        if frame_type == FRAME_ACK or frame_type == FRAME_ACK_ECN:
            self.type_id = frame_type
            self.largest_ack = varint_decode(reader)
            self.ack_delay = varint_decode(reader)
            var ack_range_count = varint_decode(reader)
            self.first_ack_range = varint_decode(reader)
            if self.first_ack_range > self.largest_ack:
                raise "ACK: first_ack_range exceeds largest_ack"
            var rc = Int(ack_range_count)
            if rc > MAX_ACK_RANGES:
                raise "ACK: range count " + String(rc) + " exceeds maximum " + String(MAX_ACK_RANGES)
            var smallest_ack = self.largest_ack - self.first_ack_range
            for _ in range(rc):
                var gap = varint_decode(reader)
                var ack_range_val = varint_decode(reader)
                var needed = gap + 2 + ack_range_val
                if needed > smallest_ack:
                    raise "ACK: range underflow (gap+range exceeds remaining PN space)"
                smallest_ack = smallest_ack - needed
                if self._ack_buf_len < MAX_ACK_RANGES:
                    self._ack_buf[self._ack_buf_len] = AckRange(gap, ack_range_val)
                    self._ack_buf_len += 1
            self.has_ecn = False
            self.ecn_ect0 = UInt64(0)
            self.ecn_ect1 = UInt64(0)
            self.ecn_ce = UInt64(0)
            if frame_type == FRAME_ACK_ECN:
                self.ecn_ect0 = varint_decode(reader)
                self.ecn_ect1 = varint_decode(reader)
                self.ecn_ce = varint_decode(reader)
                self.has_ecn = True
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # RESET_STREAM (0x04)
        if frame_type == FRAME_RESET_STREAM:
            self.type_id = FRAME_RESET_STREAM
            self.stream_id = varint_decode(reader)
            self.error_code = varint_decode(reader)
            self.final_size = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # STOP_SENDING (0x05)
        if frame_type == FRAME_STOP_SENDING:
            self.type_id = FRAME_STOP_SENDING
            self.stream_id = varint_decode(reader)
            self.error_code = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # CRYPTO (0x06)
        if frame_type == FRAME_CRYPTO:
            self.type_id = FRAME_CRYPTO
            self.offset = varint_decode(reader)
            var length = varint_decode(reader)
            self._byte_data = reader.read_span(Int(length))
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # NEW_TOKEN (0x07)
        if frame_type == FRAME_NEW_TOKEN:
            self.type_id = FRAME_NEW_TOKEN
            var token_length = varint_decode(reader)
            self._byte_data = reader.read_span(Int(token_length))
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # STREAM (0x08-0x0F)
        if (frame_type & UInt64(0xF8)) == FRAME_STREAM_BASE:
            self.type_id = frame_type
            var has_off = Bool(frame_type & UInt64(0x04))
            var has_len = Bool(frame_type & UInt64(0x02))
            var has_fin = Bool(frame_type & UInt64(0x01))
            self.stream_id = varint_decode(reader)
            self.offset = UInt64(0)
            if has_off:
                self.offset = varint_decode(reader)
            if has_len:
                var length = varint_decode(reader)
                self._byte_data = reader.read_span(Int(length))
            else:
                self._byte_data = reader.read_span(reader.remaining())
            self.fin = has_fin
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # MAX_DATA (0x10)
        if frame_type == FRAME_MAX_DATA:
            self.type_id = FRAME_MAX_DATA
            self.maximum = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # MAX_STREAM_DATA (0x11)
        if frame_type == FRAME_MAX_STREAM_DATA:
            self.type_id = FRAME_MAX_STREAM_DATA
            self.stream_id = varint_decode(reader)
            self.maximum = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # MAX_STREAMS_BIDI (0x12) / MAX_STREAMS_UNI (0x13)
        if frame_type == FRAME_MAX_STREAMS_BIDI or frame_type == FRAME_MAX_STREAMS_UNI:
            self.type_id = frame_type
            self.maximum = varint_decode(reader)
            self.bidi = frame_type == FRAME_MAX_STREAMS_BIDI
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # DATA_BLOCKED (0x14)
        if frame_type == FRAME_DATA_BLOCKED:
            self.type_id = FRAME_DATA_BLOCKED
            self.maximum = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # STREAM_DATA_BLOCKED (0x15)
        if frame_type == FRAME_STREAM_DATA_BLOCKED:
            self.type_id = FRAME_STREAM_DATA_BLOCKED
            self.stream_id = varint_decode(reader)
            self.maximum = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # STREAMS_BLOCKED_BIDI (0x16) / STREAMS_BLOCKED_UNI (0x17)
        if frame_type == FRAME_STREAMS_BLOCKED_BIDI or frame_type == FRAME_STREAMS_BLOCKED_UNI:
            self.type_id = frame_type
            self.maximum = varint_decode(reader)
            self.bidi = frame_type == FRAME_STREAMS_BLOCKED_BIDI
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # NEW_CONNECTION_ID (0x18)
        if frame_type == FRAME_NEW_CONNECTION_ID:
            self.type_id = FRAME_NEW_CONNECTION_ID
            self.sequence = varint_decode(reader)
            self.retire_prior_to = varint_decode(reader)
            var cid_length = Int(reader.read_u8())
            if cid_length > 20:
                raise "NEW_CONNECTION_ID: cid_length must be <= 20"
            var total = cid_length + 16
            self._byte_data = reader.read_span(total)
            self.offset = UInt64(cid_length)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # RETIRE_CONNECTION_ID (0x19)
        if frame_type == FRAME_RETIRE_CONNECTION_ID:
            self.type_id = FRAME_RETIRE_CONNECTION_ID
            self.sequence = varint_decode(reader)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # PATH_CHALLENGE (0x1A)
        if frame_type == FRAME_PATH_CHALLENGE:
            self.type_id = FRAME_PATH_CHALLENGE
            self._byte_data = reader.read_span(8)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # PATH_RESPONSE (0x1B)
        if frame_type == FRAME_PATH_RESPONSE:
            self.type_id = FRAME_PATH_RESPONSE
            self._byte_data = reader.read_span(8)
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # CONNECTION_CLOSE (0x1C / 0x1D)
        if frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT or frame_type == FRAME_CONNECTION_CLOSE_APP:
            self.type_id = frame_type
            self.is_transport = frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT
            self.error_code = varint_decode(reader)
            self.frame_type_field = UInt64(0)
            if self.is_transport:
                self.frame_type_field = varint_decode(reader)
            var reason_length = varint_decode(reader)
            self._byte_data = reader.read_span(Int(reason_length))
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # HANDSHAKE_DONE (0x1E)
        if frame_type == FRAME_HANDSHAKE_DONE:
            self.type_id = FRAME_HANDSHAKE_DONE
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # DATAGRAM (0x30)
        if frame_type == FRAME_DATAGRAM:
            self.type_id = FRAME_DATAGRAM
            self._byte_data = reader.read_span(reader.remaining())
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # DATAGRAM_LEN (0x31)
        if frame_type == FRAME_DATAGRAM_LEN:
            self.type_id = FRAME_DATAGRAM_LEN
            var length = varint_decode(reader)
            self._byte_data = reader.read_span(Int(length))
            self._pos = reader.pos
            self._count += 1
            return Optional[UInt64](self.type_id)

        # Unknown frame type
        self.type_id = frame_type
        self._pos = reader.pos
        self._count += 1
        return Optional[UInt64](self.type_id)

    def ack_ranges_span(self) -> Span[AckRange, origin_of(self._ack_buf)]:
        """Span view of ACK ranges decoded by the last next() call."""
        return Span(unsafe_ptr=self._ack_buf.unsafe_ptr(), length=self._ack_buf_len)

    def byte_data_span(self) -> Span[Byte, Self.origin]:
        """Span view of CC reason / STREAM data / CRYPTO data from the
        last next() call. Empty for non-data-carrying frame types."""
        return self._byte_data

    def count(self) -> Int:
        """Number of frames yielded so far."""
        return self._count


# ── Serialize functions ───────────────────────────────────────────────


# ── Direct STREAM frame writer ──────────────────────────────────────


def write_stream_frame_direct(
    mut pkt_buf: List[Byte],
    budget: Int,
    stream_id: UInt64,
    offset: UInt64,
    data: Span[Byte, _],
    fin: Bool,
) -> Int:
    """Write a STREAM frame directly into pkt_buf, bypassing Frame allocation.

    Appends the encoded STREAM frame (header + payload) to `pkt_buf` using
    the reserve-copy-encode pattern: the type byte, varint fields, and data
    bytes are written in one pass with no intermediate Frame or StreamFrame
    struct.  Always sets the LEN bit; sets the OFF bit only when offset > 0.

    Returns the total bytes written (header + data), or 0 if the budget
    cannot hold even a minimal frame (header + 1 data byte, or a FIN-only
    header).
    """
    var has_off = offset > UInt64(0)

    # Fixed header: type byte + stream_id varint + optional offset varint.
    var fixed_hdr = 1 + varint_len(stream_id)
    if has_off:
        fixed_hdr += varint_len(offset)

    # Nothing to emit when there is no data and no FIN.
    if len(data) == 0 and not fin:
        return 0

    # FIN-only: header + 1-byte length varint (encoding 0).
    if len(data) == 0 and fin:
        var total = fixed_hdr + 1  # varint_len(0) == 1
        if total > budget:
            return 0
        var stype = UInt8(FRAME_STREAM_BASE | UInt64(0x02) | UInt64(0x01))
        if has_off:
            stype = stype | UInt8(0x04)
        var base = len(pkt_buf)
        pkt_buf.resize(base + total, Byte(0))
        var pos = base
        pos += write_u8_at(pkt_buf, pos, stype)
        pos += varint_encode_at(pkt_buf, pos, stream_id)
        if has_off:
            pos += varint_encode_at(pkt_buf, pos, offset)
        pos += varint_encode_at(pkt_buf, pos, UInt64(0))
        return total

    # Compute how much data fits.  Start by assuming a 2-byte length varint
    # (covers payloads up to 16383); if the result turns out < 64 bytes the
    # actual varint is 1 byte and we get one extra byte of room.
    var max_data = budget - fixed_hdr - 2
    if max_data <= 0:
        # Try with 1-byte length varint.
        max_data = budget - fixed_hdr - 1
        if max_data <= 0:
            return 0

    var data_len = len(data)
    if data_len > max_data:
        data_len = max_data

    # Recompute with the actual length-varint size.
    var len_vl = varint_len(UInt64(data_len))
    var room = budget - fixed_hdr - len_vl
    if room <= 0:
        return 0
    if data_len > room:
        data_len = room
        # Shrinking might reduce the varint size; recompute once more.
        len_vl = varint_len(UInt64(data_len))
        room = budget - fixed_hdr - len_vl
        if room <= 0:
            return 0
        if data_len > room:
            data_len = room

    # Type byte: LEN always set; OFF if offset > 0; FIN if fin AND we are
    # writing all the remaining data (or the caller already sliced to the
    # final chunk, so `fin` is authoritative).
    var stype = UInt8(FRAME_STREAM_BASE | UInt64(0x02))
    if has_off:
        stype = stype | UInt8(0x04)
    if fin:
        stype = stype | UInt8(0x01)

    var hdr_size = fixed_hdr + len_vl
    var base = len(pkt_buf)
    pkt_buf.resize(base + hdr_size, Byte(0))
    var pos = base
    pos += write_u8_at(pkt_buf, pos, stype)
    pos += varint_encode_at(pkt_buf, pos, stream_id)
    if has_off:
        pos += varint_encode_at(pkt_buf, pos, offset)
    pos += varint_encode_at(pkt_buf, pos, UInt64(data_len))
    pkt_buf.extend(data[:data_len])

    return hdr_size + data_len


# ── Direct ACK frame writer ───────────────────────────────────────────


def write_ack_frame_direct(
    mut payload: List[Byte],
    budget: Int,
    ref ack: AckFrame,
) -> Int:
    """Write an ACK frame directly into a payload buffer, bypassing Frame allocation.

    Returns bytes written, or 0 if the frame exceeds the budget.
    """
    var tid = FRAME_ACK_ECN if ack.has_ecn else FRAME_ACK
    var size = varint_len(tid) + varint_len(ack.largest_ack) + varint_len(ack.ack_delay)
    size += varint_len(UInt64(len(ack.ranges))) + varint_len(ack.first_ack_range)
    for ref r in ack.ranges:
        size += varint_len(r.gap) + varint_len(r.ack_range)
    if ack.has_ecn:
        size += varint_len(ack.ecn_ect0) + varint_len(ack.ecn_ect1) + varint_len(ack.ecn_ce)

    if size > budget:
        return 0

    var base = len(payload)
    payload.resize(base + size, Byte(0))
    var pos = base
    pos += varint_encode_at(payload, pos, tid)
    pos += varint_encode_at(payload, pos, ack.largest_ack)
    pos += varint_encode_at(payload, pos, ack.ack_delay)
    pos += varint_encode_at(payload, pos, UInt64(len(ack.ranges)))
    pos += varint_encode_at(payload, pos, ack.first_ack_range)
    for ref r in ack.ranges:
        pos += varint_encode_at(payload, pos, r.gap)
        pos += varint_encode_at(payload, pos, r.ack_range)
    if ack.has_ecn:
        pos += varint_encode_at(payload, pos, ack.ecn_ect0)
        pos += varint_encode_at(payload, pos, ack.ecn_ect1)
        pos += varint_encode_at(payload, pos, ack.ecn_ce)

    return size


# ── Direct CRYPTO frame writer ───────────────────────────────────────


def write_crypto_frame_direct(
    mut payload: List[Byte],
    budget: Int,
    offset: UInt64,
    data: Span[Byte, _],
) -> Int:
    """Write a CRYPTO frame directly into a payload buffer.

    Truncates data to fit budget if necessary. Returns total bytes
    written (header + data), or 0 if even the header + 1 byte exceeds
    the budget.
    """
    # Fixed header: type varint (1 byte for 0x06) + offset varint.
    var fixed_hdr = 1 + varint_len(offset)

    # Start by assuming a 2-byte length varint (covers up to 16383);
    # if the result turns out < 64 bytes the actual varint is 1 byte.
    var max_data = budget - fixed_hdr - 2
    if max_data <= 0:
        max_data = budget - fixed_hdr - 1
        if max_data <= 0:
            return 0

    var data_len = len(data)
    if data_len > max_data:
        data_len = max_data

    # Recompute with the actual length-varint size.
    var len_vl = varint_len(UInt64(data_len))
    var room = budget - fixed_hdr - len_vl
    if room <= 0:
        return 0
    if data_len > room:
        data_len = room
        # Shrinking might reduce the varint size; recompute once more.
        len_vl = varint_len(UInt64(data_len))
        room = budget - fixed_hdr - len_vl
        if room <= 0:
            return 0
        if data_len > room:
            data_len = room

    var hdr_size = fixed_hdr + len_vl
    var base = len(payload)
    payload.resize(base + hdr_size, Byte(0))
    var pos = base
    pos += varint_encode_at(payload, pos, FRAME_CRYPTO)
    pos += varint_encode_at(payload, pos, offset)
    pos += varint_encode_at(payload, pos, UInt64(data_len))
    payload.extend(data[:data_len])

    return hdr_size + data_len


# ── Packet-type permission check (RFC 9000 §12.4, erratum #7365) ─────


