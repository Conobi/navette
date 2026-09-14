# src/quic/frame.mojo
# QUIC frame codec — RFC 9000 Section 19.
# Parse/serialize for all 20 QUIC frame types.

from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
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

    def __init__(out self, *, deinit move: Self):
        self.gap = move.gap
        self.ack_range = move.ack_range


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

    def __init__(out self, *, deinit move: Self):
        self.largest_ack = move.largest_ack
        self.ack_delay = move.ack_delay
        self.first_ack_range = move.first_ack_range
        self.ranges = move.ranges^
        self.ecn_ect0 = move.ecn_ect0
        self.ecn_ect1 = move.ecn_ect1
        self.ecn_ce = move.ecn_ce
        self.has_ecn = move.has_ecn


struct CryptoFrame(Copyable, Movable):
    var offset: UInt64
    var data: List[UInt8]

    def __init__(out self):
        self.offset = UInt64(0)
        self.data = List[UInt8]()

    def __init__(out self, offset: UInt64, data: List[UInt8]):
        self.offset = offset
        self.data = List[UInt8](copy=data)

    def __init__(out self, *, other: Self):
        self.offset = other.offset
        self.data = List[UInt8](copy=other.data)

    def __init__(out self, *, deinit move: Self):
        self.offset = move.offset
        self.data = move.data^


struct StreamFrame(Copyable, Movable):
    var stream_id: UInt64
    var offset: UInt64
    var data: List[UInt8]
    var fin: Bool

    def __init__(out self):
        self.stream_id = UInt64(0)
        self.offset = UInt64(0)
        self.data = List[UInt8]()
        self.fin = False

    def __init__(out self, stream_id: UInt64, offset: UInt64, data: List[UInt8], fin: Bool):
        self.stream_id = stream_id
        self.offset = offset
        self.data = List[UInt8](copy=data)
        self.fin = fin

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.offset = other.offset
        self.data = List[UInt8](copy=other.data)
        self.fin = other.fin

    def __init__(out self, *, deinit move: Self):
        self.stream_id = move.stream_id
        self.offset = move.offset
        self.data = move.data^
        self.fin = move.fin


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

    def __init__(out self, *, deinit move: Self):
        self.stream_id = move.stream_id
        self.error_code = move.error_code
        self.final_size = move.final_size


struct StopSendingFrame(Copyable, Movable):
    var stream_id: UInt64
    var error_code: UInt64

    def __init__(out self, stream_id: UInt64, error_code: UInt64):
        self.stream_id = stream_id
        self.error_code = error_code

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.error_code = other.error_code

    def __init__(out self, *, deinit move: Self):
        self.stream_id = move.stream_id
        self.error_code = move.error_code


struct MaxStreamDataFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum

    def __init__(out self, *, deinit move: Self):
        self.stream_id = move.stream_id
        self.maximum = move.maximum


struct MaxStreamsFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi

    def __init__(out self, *, deinit move: Self):
        self.maximum = move.maximum
        self.bidi = move.bidi


struct StreamDataBlockedFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum

    def __init__(out self, *, deinit move: Self):
        self.stream_id = move.stream_id
        self.maximum = move.maximum


struct StreamsBlockedFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi

    def __init__(out self, *, deinit move: Self):
        self.maximum = move.maximum
        self.bidi = move.bidi


struct NewConnectionIdFrame(Copyable, Movable):
    var sequence: UInt64
    var retire_prior_to: UInt64
    var cid: List[UInt8]
    var stateless_reset_token: List[UInt8]

    def __init__(out self):
        self.sequence = UInt64(0)
        self.retire_prior_to = UInt64(0)
        self.cid = List[UInt8]()
        self.stateless_reset_token = List[UInt8]()

    def __init__(out self, *, other: Self):
        self.sequence = other.sequence
        self.retire_prior_to = other.retire_prior_to
        self.cid = List[UInt8](copy=other.cid)
        self.stateless_reset_token = List[UInt8](copy=other.stateless_reset_token)

    def __init__(out self, *, deinit move: Self):
        self.sequence = move.sequence
        self.retire_prior_to = move.retire_prior_to
        self.cid = move.cid^
        self.stateless_reset_token = move.stateless_reset_token^


struct ConnectionCloseFrame(Copyable, Movable):
    var is_transport: Bool
    var error_code: UInt64
    var frame_type: UInt64
    var reason: List[UInt8]

    def __init__(out self):
        self.is_transport = True
        self.error_code = UInt64(0)
        self.frame_type = UInt64(0)
        self.reason = List[UInt8]()

    def __init__(out self, *, other: Self):
        self.is_transport = other.is_transport
        self.error_code = other.error_code
        self.frame_type = other.frame_type
        self.reason = List[UInt8](copy=other.reason)

    def __init__(out self, *, deinit move: Self):
        self.is_transport = move.is_transport
        self.error_code = move.error_code
        self.frame_type = move.frame_type
        self.reason = move.reason^


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
    ConnectionCloseFrame,  # CONNECTION_CLOSE_TRANSPORT/APP
    List[UInt8],           # NEW_TOKEN, PATH_CHALLENGE, PATH_RESPONSE, DATAGRAM, DATAGRAM_LEN
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

    def __init__(out self, *, deinit move: Self):
        self.type_id = move.type_id
        self.payload = move.payload^

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
            FramePayload(ConnectionCloseFrame(other=f)),
        )

    @staticmethod
    def new_token(token: List[UInt8]) -> Frame:
        return Frame(FRAME_NEW_TOKEN, FramePayload(List[UInt8](copy=token)))

    @staticmethod
    def path_challenge(data: List[UInt8]) -> Frame:
        return Frame(FRAME_PATH_CHALLENGE, FramePayload(List[UInt8](copy=data)))

    @staticmethod
    def path_response(data: List[UInt8]) -> Frame:
        return Frame(FRAME_PATH_RESPONSE, FramePayload(List[UInt8](copy=data)))

    @staticmethod
    def handshake_done() -> Frame:
        return Frame(FRAME_HANDSHAKE_DONE, FramePayload(NoneType()))

    @staticmethod
    def datagram(payload: List[UInt8]) -> Frame:
        """RFC 9221 DATAGRAM (0x30, no length prefix).

        Payload extends to end of QUIC packet. Not subject to congestion
        control, flow control, or retransmission.
        """
        return Frame(FRAME_DATAGRAM, FramePayload(List[UInt8](copy=payload)))

    @staticmethod
    def datagram_with_len(payload: List[UInt8]) -> Frame:
        """RFC 9221 DATAGRAM_LEN (0x31, varint length prefix).

        Allows multiplexing with other frames in the same packet.
        Not subject to congestion control, flow control, or retransmission.
        """
        return Frame(FRAME_DATAGRAM_LEN, FramePayload(List[UInt8](copy=payload)))

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

    def as_connection_close(self) raises -> ref [self.payload] ConnectionCloseFrame:
        if not self.payload.isa[ConnectionCloseFrame]():
            raise "Frame is not a CONNECTION_CLOSE frame"
        return self.payload.unsafe_get[ConnectionCloseFrame]()

    def as_new_token(self) raises -> ref [self.payload] List[UInt8]:
        if not self.payload.isa[List[UInt8]]():
            raise "Frame is not a NEW_TOKEN frame"
        return self.payload.unsafe_get[List[UInt8]]()

    def as_path_data(self) raises -> ref [self.payload] List[UInt8]:
        if not self.payload.isa[List[UInt8]]():
            raise "Frame is not a PATH_CHALLENGE/PATH_RESPONSE frame"
        return self.payload.unsafe_get[List[UInt8]]()

    def as_datagram_payload(self) raises -> ref [self.payload] List[UInt8]:
        """Both DATAGRAM wire variants (0x30 and 0x31) share this accessor."""
        if not self.payload.isa[List[UInt8]]():
            raise "Frame is not a DATAGRAM frame"
        return self.payload.unsafe_get[List[UInt8]]()


# ── Parse functions ───────────────────────────────────────────────────


def parse_frame[origin: Origin](mut reader: ByteReader[origin]) raises -> Frame:
    var frame_type = varint_decode(reader)

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
        var data: List[UInt8]
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
        ncid.cid = reader.read_bytes(cid_length)
        ncid.stateless_reset_token = reader.read_bytes(16)
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
        cc.reason = reader.read_bytes(Int(reason_length))
        return Frame(
            FRAME_CONNECTION_CLOSE_TRANSPORT if cc.is_transport else FRAME_CONNECTION_CLOSE_APP,
            FramePayload(cc^),
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
        for i in range(len(ack.ranges)):
            varint_encode(writer, ack.ranges[i].gap)
            varint_encode(writer, ack.ranges[i].ack_range)
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
        writer.write_bytes(Span[UInt8, origin_of(cf.data)](cf.data))
        return

    # NEW_TOKEN
    if tid == FRAME_NEW_TOKEN:
        ref token = frame.as_new_token()
        varint_encode(writer, FRAME_NEW_TOKEN)
        varint_encode(writer, UInt64(len(token)))
        writer.write_bytes(Span[UInt8, origin_of(token)](token))
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
        writer.write_bytes(Span[UInt8, origin_of(sf.data)](sf.data))
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
        writer.write_bytes(Span[UInt8, origin_of(ncid.cid)](ncid.cid))
        writer.write_bytes(Span[UInt8, origin_of(ncid.stateless_reset_token)](ncid.stateless_reset_token))
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
        writer.write_bytes(Span[UInt8, origin_of(data)](data))
        return

    # PATH_RESPONSE
    if tid == FRAME_PATH_RESPONSE:
        ref data = frame.as_path_data()
        varint_encode(writer, FRAME_PATH_RESPONSE)
        writer.write_bytes(Span[UInt8, origin_of(data)](data))
        return

    # CONNECTION_CLOSE
    if tid == FRAME_CONNECTION_CLOSE_TRANSPORT or tid == FRAME_CONNECTION_CLOSE_APP:
        ref cc = frame.as_connection_close()
        varint_encode(writer, tid)
        varint_encode(writer, cc.error_code)
        if cc.is_transport:
            varint_encode(writer, cc.frame_type)
        varint_encode(writer, UInt64(len(cc.reason)))
        writer.write_bytes(Span[UInt8, origin_of(cc.reason)](cc.reason))
        return

    # HANDSHAKE_DONE
    if tid == FRAME_HANDSHAKE_DONE:
        varint_encode(writer, FRAME_HANDSHAKE_DONE)
        return

    # DATAGRAM (0x30) — RFC 9221 §4. No length prefix; payload to end of packet.
    if tid == FRAME_DATAGRAM:
        ref data = frame.as_datagram_payload()
        varint_encode(writer, FRAME_DATAGRAM)
        writer.write_bytes(Span[UInt8, origin_of(data)](data))
        return

    # DATAGRAM_LEN (0x31) — RFC 9221 §4. Length-prefixed payload.
    if tid == FRAME_DATAGRAM_LEN:
        ref data = frame.as_datagram_payload()
        varint_encode(writer, FRAME_DATAGRAM_LEN)
        varint_encode(writer, UInt64(len(data)))
        writer.write_bytes(Span[UInt8, origin_of(data)](data))
        return

    raise "serialize_frame: unknown frame type: " + String(Int(tid))


def serialize_frames(frames: List[Frame], mut writer: ByteWriter) raises:
    for i in range(len(frames)):
        serialize_frame(frames[i], writer)


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
