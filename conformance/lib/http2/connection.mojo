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
