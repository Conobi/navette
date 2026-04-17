# src/h3/connection.mojo
#
# H3Connection — sans-I/O HTTP/3 state machine wrapping a QuicConnection.
# H3Event — flat-tag event struct emitted to callers.
# _H3StreamBuf — per-stream byte accumulator.

from std.collections import Dict, Optional
from std.memory import Span

from src.quic.connection import QuicConnection
from src.h3.frame import (
    H3RawFrame,
    DataFrame,
    HeadersFrame,
    SettingsFrame,
    SettingsPair,
    H3_FRAME_DATA,
    H3_FRAME_HEADERS,
    H3_FRAME_SETTINGS,
    H3_FRAME_GOAWAY,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_MAX_FIELD_SECTION_SIZE,
    parse_h3_frame,
)
from src.h3.qpack import QpackEncoder, QpackDecoder, QpackHeaderField


# ---------------------------------------------------------------------------
# H3Event — flat-tag event emitted by H3Connection
# ---------------------------------------------------------------------------


struct H3Event(Copyable, Movable):
    """Event emitted by H3Connection for the application layer."""

    comptime HANDSHAKE_COMPLETE: UInt8 = 1
    comptime SETTINGS_RECEIVED:  UInt8 = 2
    comptime HEADERS_RECEIVED:   UInt8 = 3
    comptime DATA_RECEIVED:      UInt8 = 4
    comptime STREAM_ENDED:       UInt8 = 5
    comptime STREAM_RESET:       UInt8 = 6
    comptime GOAWAY_RECEIVED:    UInt8 = 7
    comptime CONNECTION_CLOSED:  UInt8 = 8

    var kind:          UInt8
    var stream_id:     UInt64
    var fields:        List[QpackHeaderField]
    var data:          List[UInt8]
    var fin:           Bool
    var error_code:    UInt64
    var reason:        String
    var last_stream_id: UInt64

    def __init__(out self, kind: UInt8):
        self.kind = kind
        self.stream_id = UInt64(0)
        self.fields = List[QpackHeaderField]()
        self.data = List[UInt8]()
        self.fin = False
        self.error_code = UInt64(0)
        self.reason = String("")
        self.last_stream_id = UInt64(0)

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.stream_id = other.stream_id
        self.fields = List[QpackHeaderField](copy=other.fields)
        self.data = List[UInt8](copy=other.data)
        self.fin = other.fin
        self.error_code = other.error_code
        self.reason = other.reason
        self.last_stream_id = other.last_stream_id

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.stream_id = take.stream_id
        self.fields = take.fields^
        self.data = take.data^
        self.fin = take.fin
        self.error_code = take.error_code
        self.reason = take.reason^
        self.last_stream_id = take.last_stream_id


# ---------------------------------------------------------------------------
# _H3StreamBuf — per-stream byte accumulator (Copyable for Dict storage)
# ---------------------------------------------------------------------------


struct _H3StreamBuf(Copyable, Movable):
    var buf:       List[UInt8]
    var type_byte: Optional[UInt8]
    var is_uni:    Bool

    def __init__(out self):
        self.buf = List[UInt8]()
        self.type_byte = Optional[UInt8]()
        self.is_uni = False

    def __init__(out self, *, other: Self):
        self.buf = List[UInt8](copy=other.buf)
        self.type_byte = other.type_byte.copy()
        self.is_uni = other.is_uni

    def __init__(out self, *, deinit take: Self):
        self.buf = take.buf^
        self.type_byte = take.type_byte^
        self.is_uni = take.is_uni


# ---------------------------------------------------------------------------
# H3Connection — state machine
# ---------------------------------------------------------------------------


struct H3Connection(Movable):
    var _quic:                       QuicConnection
    var _is_server:                  Bool
    var _stream_bufs:                Dict[Int, _H3StreamBuf]
    var _h3_events:                  List[H3Event]
    var _local_ctrl_sid:             Optional[UInt64]
    var _local_qenc_sid:             Optional[UInt64]
    var _local_qdec_sid:             Optional[UInt64]
    var _init_done:                  Bool
    var _peer_ctrl_sid:              Optional[UInt64]
    var _peer_qenc_sid:              Optional[UInt64]
    var _peer_qdec_sid:              Optional[UInt64]
    var _peer_ctrl_first_frame_seen: Bool
    var _peer_ctrl_settings:         Bool
    var _goaway_sent:                Optional[UInt64]
    var _peer_goaway_sid:            Optional[UInt64]
    var _enc:                        QpackEncoder
    var _dec:                        QpackDecoder

    def __init__(out self, var quic: QuicConnection, is_server: Bool):
        self._quic = quic^
        self._is_server = is_server
        self._stream_bufs = Dict[Int, _H3StreamBuf]()
        self._h3_events = List[H3Event]()
        self._local_ctrl_sid = Optional[UInt64]()
        self._local_qenc_sid = Optional[UInt64]()
        self._local_qdec_sid = Optional[UInt64]()
        self._init_done = False
        self._peer_ctrl_sid = Optional[UInt64]()
        self._peer_qenc_sid = Optional[UInt64]()
        self._peer_qdec_sid = Optional[UInt64]()
        self._peer_ctrl_first_frame_seen = False
        self._peer_ctrl_settings = False
        self._goaway_sent = Optional[UInt64]()
        self._peer_goaway_sid = Optional[UInt64]()
        self._enc = QpackEncoder(False)
        self._dec = QpackDecoder()

    def __init__(out self, *, deinit take: Self):
        self._quic = take._quic^
        self._is_server = take._is_server
        self._stream_bufs = take._stream_bufs^
        self._h3_events = take._h3_events^
        self._local_ctrl_sid = take._local_ctrl_sid^
        self._local_qenc_sid = take._local_qenc_sid^
        self._local_qdec_sid = take._local_qdec_sid^
        self._init_done = take._init_done
        self._peer_ctrl_sid = take._peer_ctrl_sid^
        self._peer_qenc_sid = take._peer_qenc_sid^
        self._peer_qdec_sid = take._peer_qdec_sid^
        self._peer_ctrl_first_frame_seen = take._peer_ctrl_first_frame_seen
        self._peer_ctrl_settings = take._peer_ctrl_settings
        self._goaway_sent = take._goaway_sent^
        self._peer_goaway_sid = take._peer_goaway_sid^
        self._enc = take._enc^
        self._dec = take._dec^

    @staticmethod
    def server(var quic: QuicConnection) raises -> H3Connection:
        """Wrap a server-side QuicConnection."""
        return H3Connection(quic^, True)

    @staticmethod
    def client(var quic: QuicConnection) raises -> H3Connection:
        """Wrap a client-side QuicConnection."""
        return H3Connection(quic^, False)

    def is_established(self) -> Bool:
        return self._quic.is_established()

    def is_closed(self) -> Bool:
        return self._quic.is_closed()

    def _is_peer_initiated(self, stream_id: UInt64) -> Bool:
        if self._is_server:
            return (stream_id & UInt64(1)) == 0
        else:
            return (stream_id & UInt64(1)) == 1

    def _is_request_stream(self, stream_id: UInt64) -> Bool:
        return (stream_id & UInt64(0x02)) == 0

    def poll_event(mut self) -> Optional[H3Event]:
        """Return the next pending H3Event, or None if the queue is empty."""
        if len(self._h3_events) == 0:
            return Optional[H3Event]()
        var ev = H3Event(other=self._h3_events[0])
        var rest = List[H3Event]()
        for i in range(1, len(self._h3_events)):
            rest.append(H3Event(other=self._h3_events[i]))
        self._h3_events = rest^
        return Optional[H3Event](ev^)

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Stub — implemented in Task 1."""
        pass

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Stub — implemented in Task 1."""
        return List[List[UInt8]]()

    def send_headers(mut self, stream_id: UInt64, fields: List[QpackHeaderField], fin: Bool) raises:
        """Stub — implemented in Task 1."""
        pass

    def send_data(mut self, stream_id: UInt64, data: List[UInt8], fin: Bool) raises:
        """Stub — implemented in Task 1."""
        pass

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Stub — implemented in Task 1."""
        pass

    def reset_stream(mut self, stream_id: UInt64, error_code: UInt64) raises:
        """Stub — implemented in Task 1."""
        pass

    def open_bidi_stream(mut self) raises -> UInt64:
        """Stub — implemented in Task 1."""
        return UInt64(0)
