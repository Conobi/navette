# conformance/lib/http2/connection.mojo
#
# HC-4a: HTTP/2 connection state machine (conformance).
# Sans-I/O: receive_data(bytes) -> List[H2Event], data_to_send() -> List[UInt8].
# Mirrors Python h2 API for oracle cross-validation.

from std.collections import Dict

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
)
from .hpack import HpackEncoder, HpackDecoder, HpackConfig
from lib.http1.types import Header

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
    for i in range(len(s)):
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

    def __init__(out self, *, lifecycle: Int = STREAM_IDLE, send_window: Int = DEFAULT_INITIAL_WINDOW_SIZE, recv_window: Int = DEFAULT_INITIAL_WINDOW_SIZE):
        self.lifecycle = lifecycle
        self.send_window = send_window
        self.recv_window = recv_window
        self.recv_window_consumed = 0
        self.expects_continuation = False
        self.header_block_buffer = List[UInt8]()

    def __init__(out self, *, other: Self):
        self.lifecycle = other.lifecycle
        self.send_window = other.send_window
        self.recv_window = other.recv_window
        self.recv_window_consumed = other.recv_window_consumed
        self.expects_continuation = other.expects_continuation
        self.header_block_buffer = other.header_block_buffer.copy()

    def __init__(out self, *, deinit take: Self):
        self.lifecycle = take.lifecycle
        self.send_window = take.send_window
        self.recv_window = take.recv_window
        self.recv_window_consumed = take.recv_window_consumed
        self.expects_continuation = take.expects_continuation
        self.header_block_buffer = take.header_block_buffer^


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

    def __init__(out self, *, client_side: Bool, config: H2Config = H2Config()):
        self._config = H2Config(other=config)
        self._config.client_side = client_side
        self._state = CONN_IDLE
        self._client_side = client_side
        self._local_settings = H2Settings.from_config(self._config)
        self._remote_settings = H2Settings.defaults()
        self._settings_acked = False
        self._inbuf = List[UInt8]()
        self._outbuf = List[UInt8]()
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
        for i in range(len(encoded)):
            self._outbuf.append(encoded[i])

    def _trim_inbuf(mut self, count: Int):
        """Remove first `count` bytes from the inbound buffer."""
        if count <= 0:
            return
        var new_buf = List[UInt8]()
        for i in range(count, len(self._inbuf)):
            new_buf.append(self._inbuf[i])
        self._inbuf = new_buf^

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
                self._remote_settings.initial_window_size = UInt32(s.value)
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

    # Stub handlers — replaced in later tasks
    def _handle_ping(mut self, frame: Frame, mut events: List[H2Event]):
        pass

    def _handle_goaway(mut self, frame: Frame, mut events: List[H2Event]):
        pass

    def _handle_window_update(mut self, frame: Frame, mut events: List[H2Event]):
        pass

    def _handle_headers(mut self, frame: Frame, mut events: List[H2Event]):
        pass

    def _handle_continuation(mut self, frame: Frame, mut events: List[H2Event]):
        pass
