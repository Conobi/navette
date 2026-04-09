# conformance/lib/http2/connection.mojo
#
# HC-4a: HTTP/2 connection state machine (conformance).
# Sans-I/O: receive_data(bytes) -> List[H2Event], data_to_send() -> List[UInt8].
# Mirrors Python h2 API for oracle cross-validation.

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
