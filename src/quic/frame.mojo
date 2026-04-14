# src/quic/frame.mojo
# QUIC frame codec — RFC 9000 Section 19.
# Parse/serialize for all 20 QUIC frame types.

from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len

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
comptime MAX_ACK_RANGES: Int = 256


# ── Per-frame payload structs ─────────────────────────────────────────


struct AckRange(Copyable, Movable):
    var gap: UInt64
    var ack_range: UInt64

    def __init__(out self, gap: UInt64, ack_range: UInt64):
        self.gap = gap
        self.ack_range = ack_range

    def __init__(out self, *, other: Self):
        self.gap = other.gap
        self.ack_range = other.ack_range

    def __init__(out self, *, deinit take: Self):
        self.gap = take.gap
        self.ack_range = take.ack_range


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

    def __init__(out self, *, deinit take: Self):
        self.largest_ack = take.largest_ack
        self.ack_delay = take.ack_delay
        self.first_ack_range = take.first_ack_range
        self.ranges = take.ranges^
        self.ecn_ect0 = take.ecn_ect0
        self.ecn_ect1 = take.ecn_ect1
        self.ecn_ce = take.ecn_ce
        self.has_ecn = take.has_ecn


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

    def __init__(out self, *, deinit take: Self):
        self.offset = take.offset
        self.data = take.data^


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

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.offset = take.offset
        self.data = take.data^
        self.fin = take.fin


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

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.error_code = take.error_code
        self.final_size = take.final_size


struct StopSendingFrame(Copyable, Movable):
    var stream_id: UInt64
    var error_code: UInt64

    def __init__(out self, stream_id: UInt64, error_code: UInt64):
        self.stream_id = stream_id
        self.error_code = error_code

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.error_code = other.error_code

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.error_code = take.error_code


struct MaxStreamDataFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.maximum = take.maximum


struct MaxStreamsFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi

    def __init__(out self, *, deinit take: Self):
        self.maximum = take.maximum
        self.bidi = take.bidi


struct StreamDataBlockedFrame(Copyable, Movable):
    var stream_id: UInt64
    var maximum: UInt64

    def __init__(out self, stream_id: UInt64, maximum: UInt64):
        self.stream_id = stream_id
        self.maximum = maximum

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.maximum = other.maximum

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.maximum = take.maximum


struct StreamsBlockedFrame(Copyable, Movable):
    var maximum: UInt64
    var bidi: Bool

    def __init__(out self, maximum: UInt64, bidi: Bool):
        self.maximum = maximum
        self.bidi = bidi

    def __init__(out self, *, other: Self):
        self.maximum = other.maximum
        self.bidi = other.bidi

    def __init__(out self, *, deinit take: Self):
        self.maximum = take.maximum
        self.bidi = take.bidi


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

    def __init__(out self, *, deinit take: Self):
        self.sequence = take.sequence
        self.retire_prior_to = take.retire_prior_to
        self.cid = take.cid^
        self.stateless_reset_token = take.stateless_reset_token^


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

    def __init__(out self, *, deinit take: Self):
        self.is_transport = take.is_transport
        self.error_code = take.error_code
        self.frame_type = take.frame_type
        self.reason = take.reason^


# ── Tagged Frame container ────────────────────────────────────────────


struct Frame(Copyable, Movable):
    var type_id: UInt64
    var _ack: Optional[AckFrame]
    var _crypto: Optional[CryptoFrame]
    var _stream: Optional[StreamFrame]
    var _reset_stream: Optional[ResetStreamFrame]
    var _stop_sending: Optional[StopSendingFrame]
    var _max_data: Optional[UInt64]
    var _max_stream_data: Optional[MaxStreamDataFrame]
    var _max_streams: Optional[MaxStreamsFrame]
    var _new_cid: Optional[NewConnectionIdFrame]
    var _retire_cid: Optional[UInt64]
    var _conn_close: Optional[ConnectionCloseFrame]
    var _new_token: Optional[List[UInt8]]
    var _path_data: Optional[List[UInt8]]

    def __init__(out self, type_id: UInt64):
        self.type_id = type_id
        self._ack = None
        self._crypto = None
        self._stream = None
        self._reset_stream = None
        self._stop_sending = None
        self._max_data = None
        self._max_stream_data = None
        self._max_streams = None
        self._new_cid = None
        self._retire_cid = None
        self._conn_close = None
        self._new_token = None
        self._path_data = None

    def __init__(out self, *, other: Self):
        self.type_id = other.type_id
        self._ack = Optional[AckFrame](copy=other._ack)
        self._crypto = Optional[CryptoFrame](copy=other._crypto)
        self._stream = Optional[StreamFrame](copy=other._stream)
        self._reset_stream = Optional[ResetStreamFrame](copy=other._reset_stream)
        self._stop_sending = Optional[StopSendingFrame](copy=other._stop_sending)
        self._max_data = Optional[UInt64](copy=other._max_data)
        self._max_stream_data = Optional[MaxStreamDataFrame](copy=other._max_stream_data)
        self._max_streams = Optional[MaxStreamsFrame](copy=other._max_streams)
        self._new_cid = Optional[NewConnectionIdFrame](copy=other._new_cid)
        self._retire_cid = Optional[UInt64](copy=other._retire_cid)
        self._conn_close = Optional[ConnectionCloseFrame](copy=other._conn_close)
        self._new_token = Optional[List[UInt8]](copy=other._new_token)
        self._path_data = Optional[List[UInt8]](copy=other._path_data)

    def __init__(out self, *, deinit take: Self):
        self.type_id = take.type_id
        self._ack = take._ack^
        self._crypto = take._crypto^
        self._stream = take._stream^
        self._reset_stream = take._reset_stream^
        self._stop_sending = take._stop_sending^
        self._max_data = take._max_data^
        self._max_stream_data = take._max_stream_data^
        self._max_streams = take._max_streams^
        self._new_cid = take._new_cid^
        self._retire_cid = take._retire_cid^
        self._conn_close = take._conn_close^
        self._new_token = take._new_token^
        self._path_data = take._path_data^

    # ── Factory methods ───────────────────────────────────────────────

    @staticmethod
    def padding() -> Frame:
        return Frame(FRAME_PADDING)

    @staticmethod
    def ping() -> Frame:
        return Frame(FRAME_PING)

    @staticmethod
    def ack(f: AckFrame) -> Frame:
        var frame = Frame(FRAME_ACK if not f.has_ecn else FRAME_ACK_ECN)
        frame._ack = AckFrame(other=f)
        return frame^

    @staticmethod
    def crypto(f: CryptoFrame) -> Frame:
        var frame = Frame(FRAME_CRYPTO)
        frame._crypto = CryptoFrame(other=f)
        return frame^

    @staticmethod
    def stream(f: StreamFrame) -> Frame:
        # type_id will be computed at serialize time; store base
        var frame = Frame(FRAME_STREAM_BASE)
        frame._stream = StreamFrame(other=f)
        return frame^

    @staticmethod
    def reset_stream(f: ResetStreamFrame) -> Frame:
        var frame = Frame(FRAME_RESET_STREAM)
        frame._reset_stream = ResetStreamFrame(other=f)
        return frame^

    @staticmethod
    def stop_sending(f: StopSendingFrame) -> Frame:
        var frame = Frame(FRAME_STOP_SENDING)
        frame._stop_sending = StopSendingFrame(other=f)
        return frame^

    @staticmethod
    def max_data(maximum: UInt64) -> Frame:
        var frame = Frame(FRAME_MAX_DATA)
        frame._max_data = maximum
        return frame^

    @staticmethod
    def max_stream_data(f: MaxStreamDataFrame) -> Frame:
        var frame = Frame(FRAME_MAX_STREAM_DATA)
        frame._max_stream_data = MaxStreamDataFrame(other=f)
        return frame^

    @staticmethod
    def max_streams(f: MaxStreamsFrame) -> Frame:
        var frame = Frame(FRAME_MAX_STREAMS_BIDI if f.bidi else FRAME_MAX_STREAMS_UNI)
        frame._max_streams = MaxStreamsFrame(other=f)
        return frame^

    @staticmethod
    def data_blocked(maximum: UInt64) -> Frame:
        var frame = Frame(FRAME_DATA_BLOCKED)
        frame._max_data = maximum
        return frame^

    @staticmethod
    def stream_data_blocked(f: StreamDataBlockedFrame) -> Frame:
        var frame = Frame(FRAME_STREAM_DATA_BLOCKED)
        frame._max_stream_data = MaxStreamDataFrame(f.stream_id, f.maximum)
        return frame^

    @staticmethod
    def streams_blocked(f: StreamsBlockedFrame) -> Frame:
        var frame = Frame(FRAME_STREAMS_BLOCKED_BIDI if f.bidi else FRAME_STREAMS_BLOCKED_UNI)
        frame._max_streams = MaxStreamsFrame(f.maximum, f.bidi)
        return frame^

    @staticmethod
    def new_connection_id(f: NewConnectionIdFrame) -> Frame:
        var frame = Frame(FRAME_NEW_CONNECTION_ID)
        frame._new_cid = NewConnectionIdFrame(other=f)
        return frame^

    @staticmethod
    def retire_connection_id(sequence: UInt64) -> Frame:
        var frame = Frame(FRAME_RETIRE_CONNECTION_ID)
        frame._retire_cid = sequence
        return frame^

    @staticmethod
    def connection_close(f: ConnectionCloseFrame) -> Frame:
        var frame = Frame(
            FRAME_CONNECTION_CLOSE_TRANSPORT if f.is_transport else FRAME_CONNECTION_CLOSE_APP
        )
        frame._conn_close = ConnectionCloseFrame(other=f)
        return frame^

    @staticmethod
    def new_token(token: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_NEW_TOKEN)
        frame._new_token = List[UInt8](copy=token)
        return frame^

    @staticmethod
    def path_challenge(data: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_PATH_CHALLENGE)
        frame._path_data = List[UInt8](copy=data)
        return frame^

    @staticmethod
    def path_response(data: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_PATH_RESPONSE)
        frame._path_data = List[UInt8](copy=data)
        return frame^

    @staticmethod
    def handshake_done() -> Frame:
        return Frame(FRAME_HANDSHAKE_DONE)

    # ── Internal factory (takes ownership via mut) ────────────────────

    @staticmethod
    def _ack_move(mut f: AckFrame) -> Frame:
        var frame = Frame(FRAME_ACK if not f.has_ecn else FRAME_ACK_ECN)
        var empty = AckFrame()
        # Swap to take ownership
        var taken = f^
        f = empty^
        frame._ack = taken^
        return frame^

    @staticmethod
    def _crypto_move(mut f: CryptoFrame) -> Frame:
        var frame = Frame(FRAME_CRYPTO)
        var empty = CryptoFrame()
        var taken = f^
        f = empty^
        frame._crypto = taken^
        return frame^

    @staticmethod
    def _stream_move(mut f: StreamFrame) -> Frame:
        var frame = Frame(FRAME_STREAM_BASE)
        var empty = StreamFrame()
        var taken = f^
        f = empty^
        frame._stream = taken^
        return frame^

    @staticmethod
    def _stream_move_with_type(mut f: StreamFrame, type_id: UInt64) -> Frame:
        var frame = Frame(type_id)
        var empty = StreamFrame()
        var taken = f^
        f = empty^
        frame._stream = taken^
        return frame^

    @staticmethod
    def _new_cid_move(mut f: NewConnectionIdFrame) -> Frame:
        var frame = Frame(FRAME_NEW_CONNECTION_ID)
        var empty = NewConnectionIdFrame()
        var taken = f^
        f = empty^
        frame._new_cid = taken^
        return frame^

    @staticmethod
    def _conn_close_move(mut f: ConnectionCloseFrame) -> Frame:
        var frame = Frame(
            FRAME_CONNECTION_CLOSE_TRANSPORT if f.is_transport else FRAME_CONNECTION_CLOSE_APP
        )
        var empty = ConnectionCloseFrame()
        var taken = f^
        f = empty^
        frame._conn_close = taken^
        return frame^

    @staticmethod
    def _new_token_move(mut token: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_NEW_TOKEN)
        var empty = List[UInt8]()
        var taken = token^
        token = empty^
        frame._new_token = taken^
        return frame^

    @staticmethod
    def _path_challenge_move(mut data: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_PATH_CHALLENGE)
        var empty = List[UInt8]()
        var taken = data^
        data = empty^
        frame._path_data = taken^
        return frame^

    @staticmethod
    def _path_response_move(mut data: List[UInt8]) -> Frame:
        var frame = Frame(FRAME_PATH_RESPONSE)
        var empty = List[UInt8]()
        var taken = data^
        data = empty^
        frame._path_data = taken^
        return frame^

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

    def as_ack(self) raises -> ref [self._ack._value] AckFrame:
        if not self._ack:
            raise "Frame is not an ACK frame"
        return self._ack.value()

    def as_crypto(self) raises -> ref [self._crypto._value] CryptoFrame:
        if not self._crypto:
            raise "Frame is not a CRYPTO frame"
        return self._crypto.value()

    def as_stream(self) raises -> ref [self._stream._value] StreamFrame:
        if not self._stream:
            raise "Frame is not a STREAM frame"
        return self._stream.value()

    def as_reset_stream(self) raises -> ref [self._reset_stream._value] ResetStreamFrame:
        if not self._reset_stream:
            raise "Frame is not a RESET_STREAM frame"
        return self._reset_stream.value()

    def as_stop_sending(self) raises -> ref [self._stop_sending._value] StopSendingFrame:
        if not self._stop_sending:
            raise "Frame is not a STOP_SENDING frame"
        return self._stop_sending.value()

    def as_max_data(self) raises -> UInt64:
        if not self._max_data:
            raise "Frame is not a MAX_DATA/DATA_BLOCKED frame"
        return self._max_data.value()

    def as_max_stream_data(self) raises -> ref [self._max_stream_data._value] MaxStreamDataFrame:
        if not self._max_stream_data:
            raise "Frame is not a MAX_STREAM_DATA/STREAM_DATA_BLOCKED frame"
        return self._max_stream_data.value()

    def as_max_streams(self) raises -> ref [self._max_streams._value] MaxStreamsFrame:
        if not self._max_streams:
            raise "Frame is not a MAX_STREAMS/STREAMS_BLOCKED frame"
        return self._max_streams.value()

    def as_new_connection_id(self) raises -> ref [self._new_cid._value] NewConnectionIdFrame:
        if not self._new_cid:
            raise "Frame is not a NEW_CONNECTION_ID frame"
        return self._new_cid.value()

    def as_retire_connection_id(self) raises -> UInt64:
        if not self._retire_cid:
            raise "Frame is not a RETIRE_CONNECTION_ID frame"
        return self._retire_cid.value()

    def as_connection_close(self) raises -> ref [self._conn_close._value] ConnectionCloseFrame:
        if not self._conn_close:
            raise "Frame is not a CONNECTION_CLOSE frame"
        return self._conn_close.value()

    def as_new_token(self) raises -> ref [self._new_token._value] List[UInt8]:
        if not self._new_token:
            raise "Frame is not a NEW_TOKEN frame"
        return self._new_token.value()

    def as_path_data(self) raises -> ref [self._path_data._value] List[UInt8]:
        if not self._path_data:
            raise "Frame is not a PATH_CHALLENGE/PATH_RESPONSE frame"
        return self._path_data.value()


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
            count = MAX_ACK_RANGES
        for _ in range(count):
            var gap = varint_decode(reader)
            var ack_range = varint_decode(reader)
            ack.ranges.append(AckRange(gap, ack_range))
        if frame_type == FRAME_ACK_ECN:
            ack.ecn_ect0 = varint_decode(reader)
            ack.ecn_ect1 = varint_decode(reader)
            ack.ecn_ce = varint_decode(reader)
            ack.has_ecn = True
        return Frame._ack_move(ack)

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
        return Frame._crypto_move(cf)

    # NEW_TOKEN (0x07)
    if frame_type == FRAME_NEW_TOKEN:
        var token_length = varint_decode(reader)
        var token = reader.read_bytes(Int(token_length))
        return Frame._new_token_move(token)

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
        return Frame._stream_move_with_type(sf, frame_type)

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
        var ncid = NewConnectionIdFrame()
        ncid.sequence = varint_decode(reader)
        ncid.retire_prior_to = varint_decode(reader)
        var cid_length = Int(reader.read_u8())
        if cid_length < 1 or cid_length > 20:
            raise "NEW_CONNECTION_ID: cid_length must be 1-20"
        if ncid.retire_prior_to > ncid.sequence:
            raise "NEW_CONNECTION_ID: retire_prior_to exceeds sequence"
        ncid.cid = reader.read_bytes(cid_length)
        ncid.stateless_reset_token = reader.read_bytes(16)
        return Frame._new_cid_move(ncid)

    # RETIRE_CONNECTION_ID (0x19)
    if frame_type == FRAME_RETIRE_CONNECTION_ID:
        var sequence = varint_decode(reader)
        return Frame.retire_connection_id(sequence)

    # PATH_CHALLENGE (0x1A)
    if frame_type == FRAME_PATH_CHALLENGE:
        var data = reader.read_bytes(8)
        return Frame._path_challenge_move(data)

    # PATH_RESPONSE (0x1B)
    if frame_type == FRAME_PATH_RESPONSE:
        var data = reader.read_bytes(8)
        return Frame._path_response_move(data)

    # CONNECTION_CLOSE (0x1C / 0x1D)
    if frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT or frame_type == FRAME_CONNECTION_CLOSE_APP:
        var cc = ConnectionCloseFrame()
        cc.is_transport = frame_type == FRAME_CONNECTION_CLOSE_TRANSPORT
        cc.error_code = varint_decode(reader)
        if cc.is_transport:
            cc.frame_type = varint_decode(reader)
        var reason_length = varint_decode(reader)
        cc.reason = reader.read_bytes(Int(reason_length))
        return Frame._conn_close_move(cc)

    # HANDSHAKE_DONE (0x1E)
    if frame_type == FRAME_HANDSHAKE_DONE:
        return Frame.handshake_done()

    raise "unknown frame type: " + String(Int(frame_type))


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

    return False
