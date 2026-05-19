# src/h2/connection.mojo
#
# HTTP/2 connection state machine.
# Sans-I/O: receive_data(bytes) -> List[H2Event], data_to_send() -> List[UInt8].

from std.collections import Dict
from std.memory import memmove

from .frame import (
    Frame,
    decode_frame,
    encode_frame,
    H2FrameConfig,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_PRIORITY,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_PUSH_PROMISE,
    FRAME_PING,
    FRAME_GOAWAY,
    FRAME_WINDOW_UPDATE,
    FRAME_CONTINUATION,
    FLAG_END_STREAM,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_PADDED,
    FLAG_PRIORITY,
    H2_NO_ERROR,
    H2_PROTOCOL_ERROR,
    H2_INTERNAL_ERROR,
    H2_FLOW_CONTROL_ERROR,
    H2_SETTINGS_TIMEOUT,
    H2_STREAM_CLOSED,
    H2_FRAME_SIZE_ERROR,
    H2_REFUSED_STREAM,
    H2_CANCEL,
    H2_COMPRESSION_ERROR,
    H2_CONNECT_ERROR,
    H2_ENHANCE_YOUR_CALM,
    H2_INADEQUATE_SECURITY,
    H2_HTTP_1_1_REQUIRED,
    SCOPE_STREAM,
    SCOPE_CONNECTION,
)
from .payloads import (
    SettingsPayload,
    decode_settings_payload,
    Setting,
    PingPayload,
    decode_ping_payload,
    GoawayPayload,
    decode_goaway_payload,
    WindowUpdatePayload,
    decode_window_update_payload,
    HeadersPayload,
    decode_headers_payload,
    ContinuationPayload,
    decode_continuation_payload,
    DataPayload,
    decode_data_payload,
    RstStreamPayload,
    decode_rst_stream_payload,
)
from .hpack import HpackEncoder, HpackDecoder, HpackConfig
from .header import Header

# ---------------------------------------------------------------------------
# SETTINGS identifiers (RFC 9113 §6.5.2)
# ---------------------------------------------------------------------------
comptime SETTINGS_HEADER_TABLE_SIZE = 1
comptime SETTINGS_ENABLE_PUSH = 2
comptime SETTINGS_MAX_CONCURRENT_STREAMS = 3
comptime SETTINGS_INITIAL_WINDOW_SIZE = 4
comptime SETTINGS_MAX_FRAME_SIZE = 5
comptime SETTINGS_MAX_HEADER_LIST_SIZE = 6
comptime SETTINGS_ENABLE_CONNECT_PROTOCOL = 8

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
comptime DEFAULT_INITIAL_WINDOW_SIZE = 65535
comptime DEFAULT_MAX_FRAME_SIZE = 16384
comptime DEFAULT_HEADER_TABLE_SIZE = 4096
comptime DEFAULT_MAX_CONCURRENT_STREAMS = 200
comptime DEFAULT_MAX_HEADER_LIST_SIZE = 16384
comptime DEFAULT_MAX_CLOSED_STREAMS = 1024
comptime DEFAULT_CONNECTION_WINDOW = 65535


# ---------------------------------------------------------------------------
# H2Config — user-facing configuration
# ---------------------------------------------------------------------------
struct H2Config(Copyable, Movable):
    var client_side: Bool
    var initial_window_size: UInt32
    var max_concurrent_streams: UInt32
    var max_frame_size: UInt32
    var max_header_list_size: UInt32
    var header_table_size: UInt32
    var enable_connect_protocol: Bool

    def __init__(out self, *, client_side: Bool = True):
        self.client_side = client_side
        self.initial_window_size = UInt32(DEFAULT_INITIAL_WINDOW_SIZE)
        self.max_concurrent_streams = UInt32(DEFAULT_MAX_CONCURRENT_STREAMS)
        self.max_frame_size = UInt32(DEFAULT_MAX_FRAME_SIZE)
        self.max_header_list_size = UInt32(DEFAULT_MAX_HEADER_LIST_SIZE)
        self.header_table_size = UInt32(DEFAULT_HEADER_TABLE_SIZE)
        self.enable_connect_protocol = False

    def __init__(out self, *, other: Self):
        self.client_side = other.client_side
        self.initial_window_size = other.initial_window_size
        self.max_concurrent_streams = other.max_concurrent_streams
        self.max_frame_size = other.max_frame_size
        self.max_header_list_size = other.max_header_list_size
        self.header_table_size = other.header_table_size
        self.enable_connect_protocol = other.enable_connect_protocol

    def __init__(out self, *, deinit take: Self):
        self.client_side = take.client_side
        self.initial_window_size = take.initial_window_size
        self.max_concurrent_streams = take.max_concurrent_streams
        self.max_frame_size = take.max_frame_size
        self.max_header_list_size = take.max_header_list_size
        self.header_table_size = take.header_table_size
        self.enable_connect_protocol = take.enable_connect_protocol


# ---------------------------------------------------------------------------
# H2Settings — protocol-facing negotiated settings
# ---------------------------------------------------------------------------
struct H2Settings(Copyable, Movable):
    var header_table_size: UInt32
    var enable_push: Bool
    var max_concurrent_streams: UInt32
    var initial_window_size: UInt32
    var max_frame_size: UInt32
    var max_header_list_size: UInt32
    var enable_connect_protocol: Bool

    def __init__(out self):
        """RFC 9113 §6.5.2 defaults."""
        self.header_table_size = UInt32(4096)
        self.enable_push = True
        self.max_concurrent_streams = UInt32(0xFFFFFFFF)
        self.initial_window_size = UInt32(65535)
        self.max_frame_size = UInt32(16384)
        self.max_header_list_size = UInt32(0xFFFFFFFF)
        self.enable_connect_protocol = False

    @staticmethod
    def defaults() -> Self:
        return Self()

    @staticmethod
    def from_config(config: H2Config) -> Self:
        var s = Self()
        s.header_table_size = config.header_table_size
        s.enable_push = False
        s.max_concurrent_streams = config.max_concurrent_streams
        s.initial_window_size = config.initial_window_size
        s.max_frame_size = config.max_frame_size
        s.max_header_list_size = config.max_header_list_size
        s.enable_connect_protocol = config.enable_connect_protocol
        return s^

    def __init__(out self, *, other: Self):
        self.header_table_size = other.header_table_size
        self.enable_push = other.enable_push
        self.max_concurrent_streams = other.max_concurrent_streams
        self.initial_window_size = other.initial_window_size
        self.max_frame_size = other.max_frame_size
        self.max_header_list_size = other.max_header_list_size
        self.enable_connect_protocol = other.enable_connect_protocol

    def __init__(out self, *, deinit take: Self):
        self.header_table_size = take.header_table_size
        self.enable_push = take.enable_push
        self.max_concurrent_streams = take.max_concurrent_streams
        self.initial_window_size = take.initial_window_size
        self.max_frame_size = take.max_frame_size
        self.max_header_list_size = take.max_header_list_size
        self.enable_connect_protocol = take.enable_connect_protocol


# ---------------------------------------------------------------------------
# H2Event kind constants
# ---------------------------------------------------------------------------
comptime H2_EVT_REQUEST_RECEIVED = 0
comptime H2_EVT_RESPONSE_RECEIVED = 1
comptime H2_EVT_DATA_RECEIVED = 2
comptime H2_EVT_TRAILERS_RECEIVED = 3
comptime H2_EVT_STREAM_ENDED = 4
comptime H2_EVT_STREAM_RESET = 5
comptime H2_EVT_SETTINGS_ACKNOWLEDGED = 6
comptime H2_EVT_PING_RECEIVED = 7
comptime H2_EVT_PING_ACKNOWLEDGED = 8
comptime H2_EVT_GOAWAY_RECEIVED = 9
comptime H2_EVT_WINDOW_UPDATED = 10
comptime H2_EVT_CONNECTION_TERMINATED = 11
comptime H2_EVT_SETTINGS_CHANGED = 12


# ---------------------------------------------------------------------------
# H2Event — tagged union for connection events
# ---------------------------------------------------------------------------
struct H2Event(Copyable, Movable):
    var kind: Int
    var stream_id: UInt32
    var headers: List[Header]
    var data: List[UInt8]
    var error_code: UInt32
    var stream_ended: Bool
    var last_stream_id: UInt32
    var window_increment: UInt32
    var flow_controlled_length: Int
    var message: String

    def __init__(out self):
        self.kind = 0
        self.stream_id = UInt32(0)
        self.headers = List[Header]()
        self.data = List[UInt8]()
        self.error_code = UInt32(0)
        self.stream_ended = False
        self.last_stream_id = UInt32(0)
        self.window_increment = UInt32(0)
        self.flow_controlled_length = 0
        self.message = String("")

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.stream_id = other.stream_id
        self.headers = other.headers.copy()
        self.data = other.data.copy()
        self.error_code = other.error_code
        self.stream_ended = other.stream_ended
        self.last_stream_id = other.last_stream_id
        self.window_increment = other.window_increment
        self.flow_controlled_length = other.flow_controlled_length
        self.message = other.message

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.stream_id = take.stream_id
        self.headers = take.headers^
        self.data = take.data^
        self.error_code = take.error_code
        self.stream_ended = take.stream_ended
        self.last_stream_id = take.last_stream_id
        self.window_increment = take.window_increment
        self.flow_controlled_length = take.flow_controlled_length
        self.message = take.message^

    @staticmethod
    def settings_acknowledged() -> Self:
        var e = Self()
        e.kind = H2_EVT_SETTINGS_ACKNOWLEDGED
        return e^

    @staticmethod
    def settings_changed() -> Self:
        var e = Self()
        e.kind = H2_EVT_SETTINGS_CHANGED
        return e^

    @staticmethod
    def ping_received(opaque_data: List[UInt8]) -> Self:
        var e = Self()
        e.kind = H2_EVT_PING_RECEIVED
        e.data = opaque_data.copy()
        return e^

    @staticmethod
    def ping_acknowledged(opaque_data: List[UInt8]) -> Self:
        var e = Self()
        e.kind = H2_EVT_PING_ACKNOWLEDGED
        e.data = opaque_data.copy()
        return e^

    @staticmethod
    def goaway_received(last_stream_id: UInt32, error_code: UInt32, debug_data: List[UInt8]) -> Self:
        var e = Self()
        e.kind = H2_EVT_GOAWAY_RECEIVED
        e.last_stream_id = last_stream_id
        e.error_code = error_code
        e.data = debug_data.copy()
        return e^

    @staticmethod
    def window_updated(stream_id: UInt32, increment: UInt32) -> Self:
        var e = Self()
        e.kind = H2_EVT_WINDOW_UPDATED
        e.stream_id = stream_id
        e.window_increment = increment
        return e^

    @staticmethod
    def connection_terminated(last_stream_id: UInt32, error_code: UInt32, message: String) -> Self:
        var e = Self()
        e.kind = H2_EVT_CONNECTION_TERMINATED
        e.last_stream_id = last_stream_id
        e.error_code = error_code
        e.message = message
        return e^

    @staticmethod
    def request_received(stream_id: UInt32, headers: List[Header], stream_ended: Bool) -> Self:
        var e = Self()
        e.kind = H2_EVT_REQUEST_RECEIVED
        e.stream_id = stream_id
        e.headers = headers.copy()
        e.stream_ended = stream_ended
        return e^

    @staticmethod
    def response_received(stream_id: UInt32, headers: List[Header], stream_ended: Bool) -> Self:
        var e = Self()
        e.kind = H2_EVT_RESPONSE_RECEIVED
        e.stream_id = stream_id
        e.headers = headers.copy()
        e.stream_ended = stream_ended
        return e^

    @staticmethod
    def data_received(stream_id: UInt32, data: List[UInt8], flow_controlled_length: Int, stream_ended: Bool) -> Self:
        var e = Self()
        e.kind = H2_EVT_DATA_RECEIVED
        e.stream_id = stream_id
        e.data = data.copy()
        e.flow_controlled_length = flow_controlled_length
        e.stream_ended = stream_ended
        return e^

    @staticmethod
    def stream_reset(stream_id: UInt32, error_code: UInt32) -> Self:
        var e = Self()
        e.kind = H2_EVT_STREAM_RESET
        e.stream_id = stream_id
        e.error_code = error_code
        return e^

    @staticmethod
    def make_stream_ended(stream_id: UInt32) -> Self:
        var e = Self()
        e.kind = H2_EVT_STREAM_ENDED
        e.stream_id = stream_id
        return e^

    @staticmethod
    def trailers_received(stream_id: UInt32, headers: List[Header]) -> Self:
        var e = Self()
        e.kind = H2_EVT_TRAILERS_RECEIVED
        e.stream_id = stream_id
        e.headers = headers.copy()
        e.stream_ended = True
        return e^


# ---------------------------------------------------------------------------
# Connection state constants
# ---------------------------------------------------------------------------
comptime CONN_IDLE = 0
comptime CONN_OPEN = 1
comptime CONN_GOAWAY = 2
comptime CONN_CLOSED = 3

# ---------------------------------------------------------------------------
# Stream lifecycle constants (RFC 9113 §5.1, no RESERVED — push is disabled)
# ---------------------------------------------------------------------------
comptime STREAM_IDLE = 0
comptime STREAM_OPEN = 1
comptime STREAM_HALF_CLOSED_LOCAL = 2
comptime STREAM_HALF_CLOSED_REMOTE = 3
comptime STREAM_CLOSED = 4

# ---------------------------------------------------------------------------
# Client connection preface magic (RFC 9113 §3.4)
# ---------------------------------------------------------------------------
comptime H2_CLIENT_MAGIC_LEN = 24


def _client_magic() -> List[UInt8]:
    """'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n' — 24 bytes."""
    var m = List[UInt8]()
    var s = String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    var b = s.as_bytes()
    for i in range(s.byte_length()):
        m.append(b[i])
    return m^


# ---------------------------------------------------------------------------
# StreamState
# ---------------------------------------------------------------------------
struct StreamState(Copyable, Movable):
    var lifecycle: Int
    var send_window: Int
    var recv_window: Int
    var recv_window_consumed: Int
    var expects_continuation: Bool
    var header_block_buffer: List[UInt8]
    var headers_end_stream: Bool
    var data_received: Bool

    def __init__(out self, *, lifecycle: Int = STREAM_IDLE, send_window: Int = DEFAULT_INITIAL_WINDOW_SIZE, recv_window: Int = DEFAULT_INITIAL_WINDOW_SIZE):
        self.lifecycle = lifecycle
        self.send_window = send_window
        self.recv_window = recv_window
        self.recv_window_consumed = 0
        self.expects_continuation = False
        self.header_block_buffer = List[UInt8]()
        self.headers_end_stream = False
        self.data_received = False

    def __init__(out self, *, other: Self):
        self.lifecycle = other.lifecycle
        self.send_window = other.send_window
        self.recv_window = other.recv_window
        self.recv_window_consumed = other.recv_window_consumed
        self.expects_continuation = other.expects_continuation
        self.header_block_buffer = other.header_block_buffer.copy()
        self.headers_end_stream = other.headers_end_stream
        self.data_received = other.data_received

    def __init__(out self, *, deinit take: Self):
        self.lifecycle = take.lifecycle
        self.send_window = take.send_window
        self.recv_window = take.recv_window
        self.recv_window_consumed = take.recv_window_consumed
        self.expects_continuation = take.expects_continuation
        self.header_block_buffer = take.header_block_buffer^
        self.headers_end_stream = take.headers_end_stream
        self.data_received = take.data_received


# ---------------------------------------------------------------------------
# PendingDataChunk — DATA bytes that didn't fit in the window when
# `send_data` was called and are queued until WINDOW_UPDATE arrives.
# ---------------------------------------------------------------------------
struct PendingDataChunk(Copyable, Movable):
    var data: List[UInt8]
    var end_stream: Bool

    def __init__(out self, var data: List[UInt8], end_stream: Bool):
        self.data = data^
        self.end_stream = end_stream

    def __init__(out self, *, other: Self):
        self.data = other.data.copy()
        self.end_stream = other.end_stream

    def __init__(out self, *, deinit take: Self):
        self.data = take.data^
        self.end_stream = take.end_stream


# ---------------------------------------------------------------------------
# Helper: append a 6-byte SETTINGS entry to a payload
# ---------------------------------------------------------------------------
def _append_setting(mut payload: List[UInt8], id: Int, value: Int):
    payload.append(UInt8((id >> 8) & 0xFF))
    payload.append(UInt8(id & 0xFF))
    payload.append(UInt8((value >> 24) & 0xFF))
    payload.append(UInt8((value >> 16) & 0xFF))
    payload.append(UInt8((value >> 8) & 0xFF))
    payload.append(UInt8(value & 0xFF))


# ---------------------------------------------------------------------------
# H2Connection — sans-I/O HTTP/2 connection state machine
# ---------------------------------------------------------------------------
struct H2Connection(Movable):
    var _config: H2Config
    var _state: Int
    var _client_side: Bool
    var _local_settings: H2Settings
    var _remote_settings: H2Settings
    var _settings_acked: Bool
    var _inbuf: List[UInt8]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, StreamState]
    var _next_stream_id: UInt32
    var _last_recv_stream_id: UInt32
    var _active_stream_count: Int
    var _send_window: Int
    var _recv_window: Int
    var _recv_window_consumed: Int
    var _hpack_encoder: HpackEncoder
    var _hpack_decoder: HpackDecoder
    var _expecting_continuation_for: UInt32
    var _client_magic_validated: Bool
    var _closed_stream_count: Int
    var _pending_data: Dict[Int, List[PendingDataChunk]]

    def __init__(out self, *, client_side: Bool, config: H2Config = H2Config()):
        self._config = H2Config(other=config)
        self._config.client_side = client_side
        self._state = CONN_IDLE
        self._client_side = client_side
        self._local_settings = H2Settings.from_config(self._config)
        self._remote_settings = H2Settings.defaults()
        self._settings_acked = False
        # Pre-size to one default H2 max-frame-size + frame header so the
        # common path lands in one allocation per connection.
        self._inbuf = List[UInt8](capacity=16 * 1024)
        self._outbuf = List[UInt8](capacity=16 * 1024)
        self._streams = Dict[Int, StreamState]()
        self._next_stream_id = UInt32(1) if client_side else UInt32(2)
        self._last_recv_stream_id = UInt32(0)
        self._active_stream_count = 0
        self._send_window = DEFAULT_CONNECTION_WINDOW
        self._recv_window = DEFAULT_CONNECTION_WINDOW
        self._recv_window_consumed = 0
        var hpack_config = HpackConfig()
        hpack_config.max_header_list_size = Int(self._config.max_header_list_size)
        hpack_config.max_header_table_size = Int(self._config.header_table_size)
        self._hpack_encoder = HpackEncoder(hpack_config)
        self._hpack_decoder = HpackDecoder(hpack_config)
        self._expecting_continuation_for = UInt32(0)
        self._client_magic_validated = client_side
        self._closed_stream_count = 0
        self._pending_data = Dict[Int, List[PendingDataChunk]]()

    def __init__(out self, *, deinit take: Self):
        self._config = take._config^
        self._state = take._state
        self._client_side = take._client_side
        self._local_settings = take._local_settings^
        self._remote_settings = take._remote_settings^
        self._settings_acked = take._settings_acked
        self._inbuf = take._inbuf^
        self._outbuf = take._outbuf^
        self._streams = take._streams^
        self._next_stream_id = take._next_stream_id
        self._last_recv_stream_id = take._last_recv_stream_id
        self._active_stream_count = take._active_stream_count
        self._send_window = take._send_window
        self._recv_window = take._recv_window
        self._recv_window_consumed = take._recv_window_consumed
        self._hpack_encoder = take._hpack_encoder^
        self._hpack_decoder = take._hpack_decoder^
        self._expecting_continuation_for = take._expecting_continuation_for
        self._client_magic_validated = take._client_magic_validated
        self._closed_stream_count = take._closed_stream_count
        self._pending_data = take._pending_data^

    def initiate_connection(mut self) raises:
        """Send connection preface. Must be called before any other operation."""
        if self._state != CONN_IDLE:
            raise Error("Connection already initiated")
        if self._client_side:
            var magic = _client_magic()
            for i in range(len(magic)):
                self._outbuf.append(magic[i])
        self._queue_settings_frame()
        self._state = CONN_OPEN

    def data_to_send(mut self) -> List[UInt8]:
        """Drain outbound buffer."""
        var data = self._outbuf^
        self._outbuf = List[UInt8]()
        return data^

    def is_closed(self) -> Bool:
        return self._state == CONN_CLOSED

    def open_stream_count(self) -> Int:
        return self._active_stream_count

    def next_stream_id(self) -> UInt32:
        """Return the next stream ID that will be allocated."""
        return self._next_stream_id

    def local_settings(self) -> H2Settings:
        return H2Settings(other=self._local_settings)

    def remote_settings(self) -> H2Settings:
        return H2Settings(other=self._remote_settings)

    # --- Internal helpers ---

    def _queue_settings_frame(mut self):
        """Build and queue initial SETTINGS frame."""
        var payload = List[UInt8]()
        _append_setting(payload, SETTINGS_ENABLE_PUSH, 0)
        _append_setting(payload, SETTINGS_MAX_CONCURRENT_STREAMS, Int(self._config.max_concurrent_streams))
        _append_setting(payload, SETTINGS_MAX_HEADER_LIST_SIZE, Int(self._config.max_header_list_size))
        if Int(self._config.initial_window_size) != DEFAULT_INITIAL_WINDOW_SIZE:
            _append_setting(payload, SETTINGS_INITIAL_WINDOW_SIZE, Int(self._config.initial_window_size))
        if Int(self._config.max_frame_size) != DEFAULT_MAX_FRAME_SIZE:
            _append_setting(payload, SETTINGS_MAX_FRAME_SIZE, Int(self._config.max_frame_size))
        if Int(self._config.header_table_size) != DEFAULT_HEADER_TABLE_SIZE:
            _append_setting(payload, SETTINGS_HEADER_TABLE_SIZE, Int(self._config.header_table_size))
        if self._config.enable_connect_protocol:
            _append_setting(payload, SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)
        var frame = Frame(len(payload), FRAME_SETTINGS, 0, 0, payload)
        self._queue_frame(frame)

    def _queue_frame(mut self, frame: Frame):
        """Encode frame and append to outbound buffer."""
        var encoded = encode_frame(frame)
        self._outbuf.extend(encoded^)

    def _trim_inbuf(mut self, count: Int):
        """Remove first `count` bytes from the inbound buffer.

        Uses an in-place memmove + resize instead of building a fresh
        List byte-by-byte. memmove handles the overlapping src/dest
        correctly (unlike memcpy).
        """
        if count <= 0:
            return
        var n = len(self._inbuf)
        if count >= n:
            self._inbuf.clear()
            return
        var remaining = n - count
        var ptr = self._inbuf.unsafe_ptr()
        memmove(dest=ptr, src=ptr + count, count=remaining)
        self._inbuf.resize(unsafe_uninit_length=remaining)

    def _connection_error(mut self, mut events: List[H2Event], error_code: Int, message: String):
        """Send GOAWAY and emit ConnectionTerminated event."""
        var payload = List[UInt8]()
        var lsid = Int(self._last_recv_stream_id)
        payload.append(UInt8((lsid >> 24) & 0x7F))
        payload.append(UInt8((lsid >> 16) & 0xFF))
        payload.append(UInt8((lsid >> 8) & 0xFF))
        payload.append(UInt8(lsid & 0xFF))
        payload.append(UInt8((error_code >> 24) & 0xFF))
        payload.append(UInt8((error_code >> 16) & 0xFF))
        payload.append(UInt8((error_code >> 8) & 0xFF))
        payload.append(UInt8(error_code & 0xFF))
        var frame = Frame(len(payload), FRAME_GOAWAY, 0, 0, payload)
        self._queue_frame(frame)
        events.append(H2Event.connection_terminated(
            UInt32(lsid), UInt32(error_code), message
        ))
        self._state = CONN_CLOSED

    def receive_data(mut self, data: List[UInt8]) raises -> List[H2Event]:
        """Feed wire bytes, decode frames, return events."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        for i in range(len(data)):
            self._inbuf.append(data[i])
        var events = List[H2Event]()
        var pos = 0
        # Server: validate client magic
        if not self._client_magic_validated:
            if len(self._inbuf) < H2_CLIENT_MAGIC_LEN:
                return events^
            var magic = _client_magic()
            for i in range(H2_CLIENT_MAGIC_LEN):
                if self._inbuf[i] != magic[i]:
                    self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid connection preface"))
                    self._trim_inbuf(len(self._inbuf))
                    return events^
            self._client_magic_validated = True
            pos = H2_CLIENT_MAGIC_LEN
        # Parse frames
        while pos < len(self._inbuf):
            var result = decode_frame(self._inbuf, pos)
            var frame = result[0].copy()
            var consumed = result[1]
            if consumed == 0:
                break
            if not frame.ok():
                self._connection_error(events, frame.error_code, String(frame.error))
                pos += consumed
                break
            # CONTINUATION interleave check
            if self._expecting_continuation_for != UInt32(0) and frame.frame_type != FRAME_CONTINUATION:
                self._connection_error(events, H2_PROTOCOL_ERROR, String("Expected CONTINUATION"))
                pos += consumed
                break
            # Dispatch
            if frame.frame_type == FRAME_SETTINGS:
                self._handle_settings(frame, events)
            elif frame.frame_type == FRAME_PING:
                self._handle_ping(frame, events)
            elif frame.frame_type == FRAME_GOAWAY:
                self._handle_goaway(frame, events)
            elif frame.frame_type == FRAME_WINDOW_UPDATE:
                self._handle_window_update(frame, events)
            elif frame.frame_type == FRAME_HEADERS:
                self._handle_headers(frame, events)
            elif frame.frame_type == FRAME_CONTINUATION:
                self._handle_continuation(frame, events)
            elif frame.frame_type == FRAME_DATA:
                self._handle_data(frame, events)
            elif frame.frame_type == FRAME_RST_STREAM:
                self._handle_rst_stream(frame, events)
            elif frame.frame_type == FRAME_PRIORITY:
                pass  # Accept and ignore (RFC 9113 §5.3.2)
            pos += consumed
            if self._state == CONN_CLOSED:
                break
        self._trim_inbuf(pos)
        return events^

    def _handle_settings(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound SETTINGS frame."""
        var sp = decode_settings_payload(frame)
        if not sp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid SETTINGS: " + sp.error))
            return
        if sp.ack:
            if not self._settings_acked:
                self._settings_acked = True
                events.append(H2Event.settings_acknowledged())
            return
        # Apply remote settings
        for i in range(len(sp.settings)):
            var s = sp.settings[i].copy()
            if s.id == SETTINGS_HEADER_TABLE_SIZE:
                self._remote_settings.header_table_size = UInt32(s.value)
                self._hpack_encoder.set_max_table_size(s.value)
            elif s.id == SETTINGS_ENABLE_PUSH:
                self._remote_settings.enable_push = s.value != 0
            elif s.id == SETTINGS_MAX_CONCURRENT_STREAMS:
                self._remote_settings.max_concurrent_streams = UInt32(s.value)
            elif s.id == SETTINGS_INITIAL_WINDOW_SIZE:
                if s.value > 2147483647:
                    self._connection_error(events, H2_FLOW_CONTROL_ERROR, String("INITIAL_WINDOW_SIZE > 2^31-1"))
                    return
                var old_value = Int(self._remote_settings.initial_window_size)
                var new_value = s.value
                var delta = new_value - old_value
                self._remote_settings.initial_window_size = UInt32(new_value)
                if delta != 0:
                    self._adjust_stream_send_windows(delta)
                    if delta > 0:
                        self._drain_pending_data(0)
            elif s.id == SETTINGS_MAX_FRAME_SIZE:
                if s.value < 16384 or s.value > 16777215:
                    self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid MAX_FRAME_SIZE"))
                    return
                self._remote_settings.max_frame_size = UInt32(s.value)
            elif s.id == SETTINGS_MAX_HEADER_LIST_SIZE:
                self._remote_settings.max_header_list_size = UInt32(s.value)
            elif s.id == SETTINGS_ENABLE_CONNECT_PROTOCOL:
                self._remote_settings.enable_connect_protocol = s.value != 0
        # Send ACK
        var ack = Frame(0, FRAME_SETTINGS, FLAG_ACK, 0, List[UInt8]())
        self._queue_frame(ack)
        events.append(H2Event.settings_changed())

    def _adjust_stream_send_windows(mut self, delta: Int):
        """Adjust send window of all open/half-closed streams by delta."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            try:
                var s = self._streams[stream_ids[i]].copy()
                if s.lifecycle == STREAM_OPEN or s.lifecycle == STREAM_HALF_CLOSED_LOCAL or s.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                    s.send_window += delta
                    self._streams[stream_ids[i]] = s^
            except:
                pass

    def _handle_ping(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound PING frame."""
        var pp = decode_ping_payload(frame)
        if not pp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid PING"))
            return
        if pp.ack:
            events.append(H2Event.ping_acknowledged(pp.opaque_data.copy()))
            return
        # Auto-ACK: send PING with ACK flag and same opaque data
        var ack_frame = Frame(8, FRAME_PING, FLAG_ACK, 0, pp.opaque_data.copy())
        self._queue_frame(ack_frame)
        events.append(H2Event.ping_received(pp.opaque_data.copy()))

    def send_ping(mut self, opaque_data: List[UInt8]) raises:
        """Send a PING frame with the given 8-byte opaque data."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        if len(opaque_data) != 8:
            raise Error("PING opaque data must be exactly 8 bytes")
        var frame = Frame(8, FRAME_PING, 0, 0, opaque_data)
        self._queue_frame(frame)

    def send_headers(mut self, stream_id: UInt32, var headers: List[Header], *, end_stream: Bool = False) raises:
        """Encode headers via HPACK, queue HEADERS (+ CONTINUATION if needed)."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        if self._state == CONN_GOAWAY and self._client_side:
            raise Error("Connection is draining")
        var sid = Int(stream_id)
        # Client creating a new stream
        if self._client_side and not self._has_stream(sid):
            if sid != Int(self._next_stream_id):
                raise Error("Stream ID must be " + String(Int(self._next_stream_id)))
            if sid % 2 == 0:
                raise Error("Client stream IDs must be odd")
            if self._active_stream_count >= Int(self._local_settings.max_concurrent_streams):
                raise Error("Exceeds MAX_CONCURRENT_STREAMS")
            self._next_stream_id = UInt32(sid + 2)
            var stream = StreamState(
                lifecycle=STREAM_OPEN,
                send_window=Int(self._remote_settings.initial_window_size),
                recv_window=Int(self._local_settings.initial_window_size),
            )
            if end_stream:
                stream.lifecycle = STREAM_HALF_CLOSED_LOCAL
            self._streams[sid] = stream^
            self._active_stream_count += 1
        elif self._has_stream(sid):
            # Existing stream: server sending response OR client/server
            # sending trailers.  Trailers MUST carry END_STREAM.
            if end_stream:
                try:
                    var stream = self._streams[sid].copy()
                    if stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                        stream.lifecycle = STREAM_CLOSED
                        self._active_stream_count -= 1
                    else:
                        stream.lifecycle = STREAM_HALF_CLOSED_LOCAL
                    self._streams[sid] = stream^
                except:
                    raise Error("Stream not found: " + String(sid))
        else:
            raise Error("Invalid send_headers: stream_id=" + String(sid))
        # HPACK encode
        var block = self._hpack_encoder.encode(headers)
        var max_size = Int(self._remote_settings.max_frame_size)
        if len(block) <= max_size:
            # Single HEADERS frame with END_HEADERS
            var flags = FLAG_END_HEADERS
            if end_stream:
                flags = flags | FLAG_END_STREAM
            var hdr_frame = Frame(len(block), FRAME_HEADERS, flags, sid, block)
            self._queue_frame(hdr_frame)
        else:
            # Split: HEADERS (first chunk) + CONTINUATION frames
            var first_chunk = List[UInt8]()
            for i in range(max_size):
                first_chunk.append(block[i])
            var flags = 0
            if end_stream:
                flags = flags | FLAG_END_STREAM
            var hdr_frame = Frame(len(first_chunk), FRAME_HEADERS, flags, sid, first_chunk)
            self._queue_frame(hdr_frame)
            var offset = max_size
            while offset < len(block):
                var end = offset + max_size
                if end > len(block):
                    end = len(block)
                var chunk = List[UInt8]()
                for i in range(offset, end):
                    chunk.append(block[i])
                var cont_flags = 0
                if end == len(block):
                    cont_flags = FLAG_END_HEADERS
                var cont_frame = Frame(len(chunk), FRAME_CONTINUATION, cont_flags, sid, chunk)
                self._queue_frame(cont_frame)
                offset = end

    def send_data(mut self, stream_id: UInt32, data: List[UInt8], *, end_stream: Bool = False) raises:
        """Send DATA frame(s). Fragments by max_frame_size. Bytes that
        exceed the connection or stream send window are queued in
        `_pending_data` and emitted when an inbound WINDOW_UPDATE
        replenishes the window. Per RFC 7540 §5.2.1 senders MUST defer
        oversized writes — never overshoot the window — so this method
        does not raise on flow control."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        var sid = Int(stream_id)
        if not self._has_stream(sid):
            raise Error("Unknown stream: " + String(sid))
        var stream: StreamState
        try:
            stream = self._streams[sid].copy()
        except:
            raise Error("Stream not found: " + String(sid))
        if stream.lifecycle != STREAM_OPEN and stream.lifecycle != STREAM_HALF_CLOSED_REMOTE:
            raise Error("Cannot send on stream in state " + String(stream.lifecycle))
        var total = len(data)

        # Empty payload bypasses flow control. With END_STREAM it's a 0-byte
        # close marker; without END_STREAM there's nothing to do. If bytes are
        # already queued for this stream, we MUST NOT emit the close ahead of
        # them — push the END_STREAM flag onto the last queued chunk instead.
        if total == 0:
            if not end_stream:
                self._streams[sid] = stream^
                return
            if sid in self._pending_data:
                var qsz: Int
                try:
                    qsz = len(self._pending_data[sid])
                except:
                    qsz = 0
                if qsz > 0:
                    try:
                        self._pending_data[sid][qsz - 1].end_stream = True
                    except:
                        pass
                    self._streams[sid] = stream^
                    return
            var frame0 = Frame(0, FRAME_DATA, FLAG_END_STREAM, sid, List[UInt8]())
            self._queue_frame(frame0)
            if stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                stream.lifecycle = STREAM_CLOSED
                self._active_stream_count -= 1
            else:
                stream.lifecycle = STREAM_HALF_CLOSED_LOCAL
            self._streams[sid] = stream^
            return

        # If this stream already has queued bytes ahead of `data`,
        # appending to the queue is the only way to preserve send order.
        if sid in self._pending_data:
            var qsize: Int
            try:
                qsize = len(self._pending_data[sid])
            except:
                qsize = 0
            if qsize > 0:
                var copy_buf = List[UInt8]()
                for i in range(total):
                    copy_buf.append(data[i])
                var pc = PendingDataChunk(copy_buf^, end_stream)
                try:
                    self._pending_data[sid].append(pc^)
                except:
                    pass
                self._streams[sid] = stream^
                return

        var available = self._send_window
        if stream.send_window < available:
            available = stream.send_window
        if available < 0:
            available = 0
        var sendable = total if total < available else available

        if sendable > 0:
            var max_size = Int(self._remote_settings.max_frame_size)
            var offset = 0
            var emit_end = end_stream and sendable == total
            while offset < sendable:
                var end = offset + max_size
                if end > sendable:
                    end = sendable
                var chunk_bytes = List[UInt8]()
                for i in range(offset, end):
                    chunk_bytes.append(data[i])
                var is_last = (end >= sendable)
                var flags = FLAG_END_STREAM if (emit_end and is_last) else 0
                var frame = Frame(len(chunk_bytes), FRAME_DATA, flags, sid, chunk_bytes)
                self._queue_frame(frame)
                offset = end
            self._send_window -= sendable
            stream.send_window -= sendable

        if sendable < total:
            var remainder = List[UInt8]()
            for i in range(sendable, total):
                remainder.append(data[i])
            var pchunk = PendingDataChunk(remainder^, end_stream)
            if sid not in self._pending_data:
                self._pending_data[sid] = List[PendingDataChunk]()
            try:
                self._pending_data[sid].append(pchunk^)
            except:
                pass

        if end_stream and sendable >= total:
            if stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                stream.lifecycle = STREAM_CLOSED
                self._active_stream_count -= 1
            else:
                stream.lifecycle = STREAM_HALF_CLOSED_LOCAL
        self._streams[sid] = stream^

    def _drain_pending_data(mut self, hint_stream_id: Int):
        """Drain queued DATA bytes whose flow-control window has just been
        replenished. `hint_stream_id == 0` means the connection-level
        window grew (or INITIAL_WINDOW_SIZE changed), so walk every
        stream with pending bytes; otherwise drain just that stream."""
        if hint_stream_id == 0:
            var sids = List[Int]()
            for key in self._pending_data.keys():
                sids.append(key)
            for i in range(len(sids)):
                self._drain_stream_pending(sids[i])
        else:
            if hint_stream_id in self._pending_data:
                self._drain_stream_pending(hint_stream_id)

    def _drain_stream_pending(mut self, sid: Int):
        """Emit as many queued DATA bytes for `sid` as the current
        connection-level and stream-level windows admit, then re-queue
        any leftover. END_STREAM rides only the final byte of the queue."""
        if not self._has_stream(sid):
            try:
                _ = self._pending_data.pop(sid)
            except:
                pass
            return
        var stream: StreamState
        try:
            stream = self._streams[sid].copy()
        except:
            return
        if stream.lifecycle != STREAM_OPEN and stream.lifecycle != STREAM_HALF_CLOSED_REMOTE:
            try:
                _ = self._pending_data.pop(sid)
            except:
                pass
            return

        var queue: List[PendingDataChunk]
        try:
            queue = self._pending_data[sid].copy()
        except:
            return
        try:
            _ = self._pending_data.pop(sid)
        except:
            pass

        var max_size = Int(self._remote_settings.max_frame_size)
        var idx = 0
        var stalled = False
        var stall_remainder = List[UInt8]()
        var stall_end_stream = False

        while idx < len(queue):
            var available = self._send_window
            if stream.send_window < available:
                available = stream.send_window
            if available <= 0:
                break

            var data_bytes = queue[idx].data.copy()
            var data_end_stream = queue[idx].end_stream
            var data_len = len(data_bytes)
            var sendable = data_len if data_len < available else available
            var emit_full = (sendable == data_len)
            var is_last_chunk = (idx == len(queue) - 1)

            if sendable > 0:
                var offset = 0
                while offset < sendable:
                    var end = offset + max_size
                    if end > sendable:
                        end = sendable
                    var frame_bytes = List[UInt8]()
                    for j in range(offset, end):
                        frame_bytes.append(data_bytes[j])
                    var is_last_part = (end >= sendable)
                    var flags = FLAG_END_STREAM if (data_end_stream and emit_full and is_last_chunk and is_last_part) else 0
                    var frame = Frame(len(frame_bytes), FRAME_DATA, flags, sid, frame_bytes)
                    self._queue_frame(frame)
                    offset = end
                self._send_window -= sendable
                stream.send_window -= sendable

            if emit_full:
                if data_end_stream and is_last_chunk:
                    if stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                        stream.lifecycle = STREAM_CLOSED
                        self._active_stream_count -= 1
                    else:
                        stream.lifecycle = STREAM_HALF_CLOSED_LOCAL
                idx += 1
            else:
                var rem = List[UInt8]()
                for j in range(sendable, data_len):
                    rem.append(data_bytes[j])
                stall_remainder = rem^
                stall_end_stream = data_end_stream
                stalled = True
                idx += 1
                break

        if stalled or idx < len(queue):
            var new_queue = List[PendingDataChunk]()
            if stalled:
                new_queue.append(PendingDataChunk(stall_remainder^, stall_end_stream))
            while idx < len(queue):
                new_queue.append(PendingDataChunk(other=queue[idx]))
                idx += 1
            self._pending_data[sid] = new_queue^
        self._streams[sid] = stream^

    def _handle_goaway(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound GOAWAY frame."""
        var gp = decode_goaway_payload(frame)
        if not gp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid GOAWAY"))
            return
        self._state = CONN_GOAWAY
        events.append(H2Event.goaway_received(
            UInt32(gp.last_stream_id), UInt32(gp.error_code), gp.debug_data.copy()
        ))

    def send_goaway(mut self, last_stream_id: UInt32, error_code: UInt32) raises:
        """Send GOAWAY frame. Connection enters draining state."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        var payload = List[UInt8]()
        var lsid = Int(last_stream_id)
        payload.append(UInt8((lsid >> 24) & 0x7F))
        payload.append(UInt8((lsid >> 16) & 0xFF))
        payload.append(UInt8((lsid >> 8) & 0xFF))
        payload.append(UInt8(lsid & 0xFF))
        var ec = Int(error_code)
        payload.append(UInt8((ec >> 24) & 0xFF))
        payload.append(UInt8((ec >> 16) & 0xFF))
        payload.append(UInt8((ec >> 8) & 0xFF))
        payload.append(UInt8(ec & 0xFF))
        var frame = Frame(len(payload), FRAME_GOAWAY, 0, 0, payload)
        self._queue_frame(frame)
        self._state = CONN_GOAWAY

    def send_rst_stream(mut self, stream_id: UInt32, error_code: UInt32) raises:
        """Send RST_STREAM frame for the given stream."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        var payload = List[UInt8]()
        var ec = Int(error_code)
        payload.append(UInt8((ec >> 24) & 0xFF))
        payload.append(UInt8((ec >> 16) & 0xFF))
        payload.append(UInt8((ec >> 8) & 0xFF))
        payload.append(UInt8(ec & 0xFF))
        var sid = Int(stream_id)
        var frame = Frame(4, FRAME_RST_STREAM, 0, sid, payload)
        self._queue_frame(frame)
        # Close the stream
        if self._has_stream(sid):
            try:
                var stream = self._streams[sid].copy()
                if stream.lifecycle == STREAM_OPEN or stream.lifecycle == STREAM_HALF_CLOSED_LOCAL or stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                    self._active_stream_count -= 1
                stream.lifecycle = STREAM_CLOSED
                self._streams[sid] = stream^
            except:
                pass

    def acknowledge_received_data(mut self, size: Int, stream_id: UInt32) raises:
        """Application consumed `size` bytes. Emits WINDOW_UPDATE when threshold met."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        # Connection-level tracking
        self._recv_window_consumed += size
        if self._recv_window_consumed > DEFAULT_CONNECTION_WINDOW // 2:
            self._send_window_update_frame(UInt32(0), UInt32(self._recv_window_consumed))
            self._recv_window += self._recv_window_consumed
            self._recv_window_consumed = 0
        # Stream-level tracking
        var sid = Int(stream_id)
        if self._has_stream(sid):
            try:
                var stream = self._streams[sid].copy()
                stream.recv_window_consumed += size
                var stream_threshold = Int(self._local_settings.initial_window_size) // 2
                if stream.recv_window_consumed > stream_threshold:
                    self._send_window_update_frame(stream_id, UInt32(stream.recv_window_consumed))
                    stream.recv_window += stream.recv_window_consumed
                    stream.recv_window_consumed = 0
                self._streams[sid] = stream^
            except:
                pass

    def send_window_update(mut self, stream_id: UInt32, increment: UInt32) raises:
        """Manually send a WINDOW_UPDATE frame."""
        if self._state == CONN_CLOSED:
            raise Error("Connection is closed")
        self._send_window_update_frame(stream_id, increment)

    def _send_window_update_frame(mut self, stream_id: UInt32, increment: UInt32):
        """Queue a WINDOW_UPDATE frame."""
        var inc = Int(increment)
        var payload = List[UInt8]()
        payload.append(UInt8((inc >> 24) & 0x7F))
        payload.append(UInt8((inc >> 16) & 0xFF))
        payload.append(UInt8((inc >> 8) & 0xFF))
        payload.append(UInt8(inc & 0xFF))
        var wu_frame = Frame(4, FRAME_WINDOW_UPDATE, 0, Int(stream_id), payload)
        self._queue_frame(wu_frame)

    def _handle_window_update(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound WINDOW_UPDATE on stream 0 or a specific stream."""
        var wp = decode_window_update_payload(frame)
        if not wp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid WINDOW_UPDATE"))
            return
        if frame.stream_id == 0:
            # Connection-level: check overflow
            if self._send_window + wp.window_increment > 2147483647:
                self._connection_error(events, H2_FLOW_CONTROL_ERROR, String("Connection window overflow"))
                return
            self._send_window += wp.window_increment
            events.append(H2Event.window_updated(UInt32(0), UInt32(wp.window_increment)))
            self._drain_pending_data(0)
        else:
            # Stream-level
            if self._has_stream(frame.stream_id):
                try:
                    var stream = self._streams[frame.stream_id].copy()
                    if stream.send_window + wp.window_increment > 2147483647:
                        events.append(H2Event.stream_reset(UInt32(frame.stream_id), UInt32(H2_FLOW_CONTROL_ERROR)))
                        return
                    stream.send_window += wp.window_increment
                    self._streams[frame.stream_id] = stream^
                    events.append(H2Event.window_updated(UInt32(frame.stream_id), UInt32(wp.window_increment)))
                    self._drain_pending_data(Int(frame.stream_id))
                except:
                    pass

    def _handle_headers(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound HEADERS: new stream, response, or trailers."""
        var stream_id = frame.stream_id
        # --- Existing stream: response headers or trailers ---
        if self._has_stream(stream_id):
            try:
                var stream = self._streams[stream_id].copy()
                if stream.data_received:
                    # Trailers — Task 8 stub
                    self._handle_trailer_headers(frame, stream, events)
                    return
                # Response headers (client receiving server response)
                var hp = decode_headers_payload(frame)
                if not hp.ok():
                    self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid HEADERS: " + hp.error))
                    return
                if frame.flags & FLAG_END_HEADERS != 0:
                    var decode_result = self._hpack_decoder.decode(hp.headers_block)
                    var decoded_headers = decode_result[0].copy()
                    var decode_error = decode_result[1]
                    if decode_error.byte_length() > 0:
                        self._connection_error(events, H2_COMPRESSION_ERROR, String("HPACK decode error: " + decode_error))
                        return
                    var end_stream = (frame.flags & FLAG_END_STREAM) != 0
                    if end_stream:
                        if stream.lifecycle == STREAM_HALF_CLOSED_LOCAL:
                            stream.lifecycle = STREAM_CLOSED
                            self._active_stream_count -= 1
                        else:
                            stream.lifecycle = STREAM_HALF_CLOSED_REMOTE
                    self._streams[stream_id] = stream^
                    events.append(H2Event.response_received(UInt32(stream_id), decoded_headers, end_stream))
                else:
                    # CONTINUATION assembly for response headers
                    for i in range(len(hp.headers_block)):
                        stream.header_block_buffer.append(hp.headers_block[i])
                    stream.expects_continuation = True
                    stream.headers_end_stream = (frame.flags & FLAG_END_STREAM) != 0
                    self._streams[stream_id] = stream^
                    self._expecting_continuation_for = UInt32(stream_id)
            except:
                self._connection_error(events, H2_PROTOCOL_ERROR, String("Stream not found"))
            return
        # --- New stream (existing code, unchanged) ---
        # Validate stream ID parity
        if not self._client_side:
            if stream_id % 2 == 0:
                self._connection_error(events, H2_PROTOCOL_ERROR, String("Even stream ID from client"))
                return
        else:
            if stream_id % 2 != 0:
                self._connection_error(events, H2_PROTOCOL_ERROR, String("Odd stream ID from server"))
                return
        # Must be monotonically increasing
        if stream_id <= Int(self._last_recv_stream_id):
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Stream ID not increasing"))
            return
        # Max concurrent streams
        if self._active_stream_count >= Int(self._local_settings.max_concurrent_streams):
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Exceeds MAX_CONCURRENT_STREAMS"))
            return
        self._last_recv_stream_id = UInt32(stream_id)
        var stream = StreamState(
            lifecycle=STREAM_OPEN,
            send_window=Int(self._remote_settings.initial_window_size),
            recv_window=Int(self._local_settings.initial_window_size),
        )
        var hp = decode_headers_payload(frame)
        if not hp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid HEADERS: " + hp.error))
            return
        if frame.flags & FLAG_END_HEADERS != 0:
            # HPACK decode the complete header block
            var decode_result = self._hpack_decoder.decode(hp.headers_block)
            var decoded_headers = decode_result[0].copy()
            var decode_error = decode_result[1]
            if decode_error.byte_length() > 0:
                self._connection_error(events, H2_COMPRESSION_ERROR, String("HPACK decode error: " + decode_error))
                return
            var end_stream = (frame.flags & FLAG_END_STREAM) != 0
            if end_stream:
                stream.lifecycle = STREAM_HALF_CLOSED_REMOTE
            self._streams[stream_id] = stream^
            self._active_stream_count += 1
            if not self._client_side:
                events.append(H2Event.request_received(UInt32(stream_id), decoded_headers, end_stream))
            else:
                events.append(H2Event.response_received(UInt32(stream_id), decoded_headers, end_stream))
        else:
            # Buffer fragment, wait for CONTINUATION
            for i in range(len(hp.headers_block)):
                stream.header_block_buffer.append(hp.headers_block[i])
            stream.expects_continuation = True
            stream.headers_end_stream = (frame.flags & FLAG_END_STREAM) != 0
            self._streams[stream_id] = stream^
            self._active_stream_count += 1
            self._expecting_continuation_for = UInt32(stream_id)

    def _handle_trailer_headers(mut self, frame: Frame, stream: StreamState, mut events: List[H2Event]):
        """Process trailer HEADERS on an existing stream with data_received=True."""
        var stream_id = frame.stream_id
        var hp = decode_headers_payload(frame.copy())
        if not hp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid trailer HEADERS: " + hp.error))
            return
        # Trailers MUST have END_STREAM (RFC 9113 §8.1)
        if (frame.flags & FLAG_END_STREAM) == 0:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Trailers must have END_STREAM"))
            return
        if frame.flags & FLAG_END_HEADERS != 0:
            var decode_result = self._hpack_decoder.decode(hp.headers_block)
            var decoded_headers = decode_result[0].copy()
            var decode_error = decode_result[1]
            if decode_error.byte_length() > 0:
                self._connection_error(events, H2_COMPRESSION_ERROR, String("HPACK decode error: " + decode_error))
                return
            var s = StreamState(other=stream)
            if s.lifecycle == STREAM_HALF_CLOSED_LOCAL:
                s.lifecycle = STREAM_CLOSED
                self._active_stream_count -= 1
            else:
                s.lifecycle = STREAM_HALF_CLOSED_REMOTE
            self._streams[stream_id] = s^
            events.append(H2Event.trailers_received(UInt32(stream_id), decoded_headers))
        else:
            # CONTINUATION assembly for trailers
            var s = StreamState(other=stream)
            for i in range(len(hp.headers_block)):
                s.header_block_buffer.append(hp.headers_block[i])
            s.expects_continuation = True
            s.headers_end_stream = True  # already validated above
            self._streams[stream_id] = s^
            self._expecting_continuation_for = UInt32(stream_id)

    def stream_state(self, stream_id: UInt32) raises -> Int:
        """Return STREAM_* lifecycle constant. Raises for unknown streams."""
        try:
            return self._streams[Int(stream_id)].lifecycle
        except:
            raise Error("Unknown stream: " + String(Int(stream_id)))

    def _has_stream(self, stream_id: Int) -> Bool:
        try:
            _ = self._streams[stream_id].copy()
            return True
        except:
            return False

    def _handle_continuation(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound CONTINUATION: append fragment, finalize if END_HEADERS."""
        var stream_id = frame.stream_id
        if Int(self._expecting_continuation_for) == 0:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Unexpected CONTINUATION"))
            return
        if stream_id != Int(self._expecting_continuation_for):
            self._connection_error(events, H2_PROTOCOL_ERROR, String("CONTINUATION on wrong stream"))
            return
        var cp = decode_continuation_payload(frame)
        if not cp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid CONTINUATION"))
            return
        # Read-modify-write for Dict value
        try:
            var stream = self._streams[stream_id].copy()
            for i in range(len(cp.headers_block)):
                stream.header_block_buffer.append(cp.headers_block[i])
            if frame.flags & FLAG_END_HEADERS != 0:
                # Assembly complete — HPACK decode
                stream.expects_continuation = False
                self._expecting_continuation_for = UInt32(0)
                var decode_result = self._hpack_decoder.decode(stream.header_block_buffer)
                var decoded_headers = decode_result[0].copy()
                var decode_error = decode_result[1]
                if decode_error.byte_length() > 0:
                    self._streams[stream_id] = stream^
                    self._connection_error(events, H2_COMPRESSION_ERROR, String("HPACK decode error: " + decode_error))
                    return
                var end_stream = stream.headers_end_stream
                if end_stream:
                    if stream.lifecycle == STREAM_HALF_CLOSED_LOCAL:
                        stream.lifecycle = STREAM_CLOSED
                        self._active_stream_count -= 1
                    else:
                        stream.lifecycle = STREAM_HALF_CLOSED_REMOTE
                stream.header_block_buffer = List[UInt8]()  # clear buffer
                if stream.data_received:
                    # Trailers
                    self._streams[stream_id] = stream^
                    events.append(H2Event.trailers_received(UInt32(stream_id), decoded_headers))
                elif not self._client_side:
                    self._streams[stream_id] = stream^
                    events.append(H2Event.request_received(UInt32(stream_id), decoded_headers, end_stream))
                else:
                    self._streams[stream_id] = stream^
                    events.append(H2Event.response_received(UInt32(stream_id), decoded_headers, end_stream))
                return  # Don't fall through to the else branch's stream write
            self._streams[stream_id] = stream^
        except:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Stream not found for CONTINUATION"))

    def _stream_error(mut self, mut events: List[H2Event], stream_id: Int, error_code: Int):
        """Send RST_STREAM and emit StreamReset event for a single stream."""
        var ec = error_code
        var payload = List[UInt8]()
        payload.append(UInt8((ec >> 24) & 0xFF))
        payload.append(UInt8((ec >> 16) & 0xFF))
        payload.append(UInt8((ec >> 8) & 0xFF))
        payload.append(UInt8(ec & 0xFF))
        var frame = Frame(4, FRAME_RST_STREAM, 0, stream_id, payload)
        self._queue_frame(frame)
        events.append(H2Event.stream_reset(UInt32(stream_id), UInt32(error_code)))
        if self._has_stream(stream_id):
            try:
                var stream = self._streams[stream_id].copy()
                if stream.lifecycle == STREAM_OPEN or stream.lifecycle == STREAM_HALF_CLOSED_LOCAL or stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                    self._active_stream_count -= 1
                stream.lifecycle = STREAM_CLOSED
                self._streams[stream_id] = stream^
            except:
                pass

    def _handle_data(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound DATA frame."""
        var stream_id = frame.stream_id
        if stream_id == 0:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("DATA on stream 0"))
            return
        if not self._has_stream(stream_id):
            self._connection_error(events, H2_PROTOCOL_ERROR, String("DATA on unknown stream"))
            return
        try:
            var stream = self._streams[stream_id].copy()
            if stream.lifecycle != STREAM_OPEN and stream.lifecycle != STREAM_HALF_CLOSED_LOCAL:
                self._stream_error(events, stream_id, H2_STREAM_CLOSED)
                return
            var dp = decode_data_payload(frame.copy())
            if not dp.ok():
                self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid DATA: " + dp.error))
                return
            # Flow controlled length = total payload including padding
            var fcl = len(frame.payload)
            # Check recv window violations (RFC 9113 §6.9.1)
            if fcl > self._recv_window:
                self._connection_error(events, H2_FLOW_CONTROL_ERROR, String("Connection recv window exceeded"))
                return
            if fcl > stream.recv_window:
                self._stream_error(events, stream_id, H2_FLOW_CONTROL_ERROR)
                return
            # Decrement recv windows
            self._recv_window -= fcl
            stream.recv_window -= fcl
            stream.data_received = True
            var end_stream = (frame.flags & FLAG_END_STREAM) != 0
            if end_stream:
                if stream.lifecycle == STREAM_HALF_CLOSED_LOCAL:
                    stream.lifecycle = STREAM_CLOSED
                    self._active_stream_count -= 1
                else:
                    stream.lifecycle = STREAM_HALF_CLOSED_REMOTE
            self._streams[stream_id] = stream^
            events.append(H2Event.data_received(UInt32(stream_id), dp.data, fcl, end_stream))
        except:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Stream error processing DATA"))

    def _handle_rst_stream(mut self, frame: Frame, mut events: List[H2Event]):
        """Process inbound RST_STREAM frame."""
        var stream_id = frame.stream_id
        if stream_id == 0:
            self._connection_error(events, H2_PROTOCOL_ERROR, String("RST_STREAM on stream 0"))
            return
        if not self._has_stream(stream_id):
            self._connection_error(events, H2_PROTOCOL_ERROR, String("RST_STREAM on idle stream"))
            return
        var rp = decode_rst_stream_payload(frame.copy())
        if not rp.ok():
            self._connection_error(events, H2_PROTOCOL_ERROR, String("Invalid RST_STREAM"))
            return
        try:
            var stream = self._streams[stream_id].copy()
            if stream.lifecycle == STREAM_OPEN or stream.lifecycle == STREAM_HALF_CLOSED_LOCAL or stream.lifecycle == STREAM_HALF_CLOSED_REMOTE:
                self._active_stream_count -= 1
            stream.lifecycle = STREAM_CLOSED
            self._streams[stream_id] = stream^
        except:
            pass
        events.append(H2Event.stream_reset(UInt32(stream_id), UInt32(rp.error_code)))
