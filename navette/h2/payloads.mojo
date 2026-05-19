# src/h2/payloads.mojo
#
# Per-type payload structs and decoders for HTTP/2 frames (RFC 9113).
# Each decoder takes a Frame and returns a typed payload struct.

from .frame import (
    Frame,
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
    FLAG_PADDED,
    FLAG_PRIORITY,
    FLAG_ACK,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_u32(payload: List[UInt8], offset: Int) -> Int:
    """Read a 4-byte big-endian unsigned integer."""
    return (
        (Int(payload[offset]) << 24)
        | (Int(payload[offset + 1]) << 16)
        | (Int(payload[offset + 2]) << 8)
        | Int(payload[offset + 3])
    )


def _read_u31(payload: List[UInt8], offset: Int) -> Int:
    """Read a 31-bit value (mask high bit) from 4 bytes big-endian."""
    return (
        ((Int(payload[offset]) & 0x7F) << 24)
        | (Int(payload[offset + 1]) << 16)
        | (Int(payload[offset + 2]) << 8)
        | Int(payload[offset + 3])
    )


def _read_u16(payload: List[UInt8], offset: Int) -> Int:
    """Read a 2-byte big-endian unsigned integer."""
    return (Int(payload[offset]) << 8) | Int(payload[offset + 1])


def _slice_payload(payload: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    """Copy a slice of payload bytes [start, end)."""
    var result = List[UInt8]()
    for i in range(start, end):
        result.append(payload[i])
    return result^


# ---------------------------------------------------------------------------
# 1. DataPayload
# ---------------------------------------------------------------------------
struct DataPayload(Movable):
    """Decoded DATA frame payload (RFC 9113 Section 6.1)."""

    var data: List[UInt8]
    var padding_length: Int
    var error: String

    def __init__(out self):
        self.data = List[UInt8]()
        self.padding_length = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.data = take.data^
        self.padding_length = take.padding_length
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_data_payload(frame: Frame) -> DataPayload:
    """Decode a DATA frame's payload into a DataPayload."""
    var result = DataPayload()
    var length = len(frame.payload)

    if frame.frame_type != FRAME_DATA:
        result.error = "expected DATA frame, got type " + String(
            frame.frame_type
        )
        return result^

    if (frame.flags & FLAG_PADDED) != 0:
        if length < 1:
            result.error = "DATA PADDED frame too short for pad length byte"
            return result^
        var pad_len = Int(frame.payload[0])
        if pad_len > length - 1:
            result.error = "DATA padding length " + String(
                pad_len
            ) + " exceeds payload"
            return result^
        result.padding_length = pad_len
        result.data = _slice_payload(frame.payload, 1, length - pad_len)
    else:
        result.padding_length = 0
        result.data = _slice_payload(frame.payload, 0, length)

    return result^


# ---------------------------------------------------------------------------
# 2. HeadersPayload
# ---------------------------------------------------------------------------
struct HeadersPayload(Movable):
    """Decoded HEADERS frame payload (RFC 9113 Section 6.2)."""

    var headers_block: List[UInt8]
    var padding_length: Int
    var priority_present: Bool
    var exclusive: Bool
    var stream_dependency: Int
    var weight: Int
    var error: String

    def __init__(out self):
        self.headers_block = List[UInt8]()
        self.padding_length = 0
        self.priority_present = False
        self.exclusive = False
        self.stream_dependency = 0
        self.weight = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.headers_block = take.headers_block^
        self.padding_length = take.padding_length
        self.priority_present = take.priority_present
        self.exclusive = take.exclusive
        self.stream_dependency = take.stream_dependency
        self.weight = take.weight
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_headers_payload(frame: Frame) -> HeadersPayload:
    """Decode a HEADERS frame's payload into a HeadersPayload."""
    var result = HeadersPayload()
    var length = len(frame.payload)

    if frame.frame_type != FRAME_HEADERS:
        result.error = "expected HEADERS frame, got type " + String(
            frame.frame_type
        )
        return result^

    var offset = 0
    var pad_len = 0

    if (frame.flags & FLAG_PADDED) != 0:
        if length < 1:
            result.error = (
                "HEADERS PADDED frame too short for pad length byte"
            )
            return result^
        pad_len = Int(frame.payload[0])
        offset = 1
        result.padding_length = pad_len

    if (frame.flags & FLAG_PRIORITY) != 0:
        if length < offset + 5:
            result.error = "HEADERS PRIORITY frame too short for priority fields"
            return result^
        result.priority_present = True
        result.exclusive = (Int(frame.payload[offset]) >> 7) != 0
        result.stream_dependency = _read_u31(frame.payload, offset)
        result.weight = Int(frame.payload[offset + 4]) + 1
        offset += 5

    if pad_len > length - offset:
        result.error = "HEADERS padding length exceeds available payload"
        return result^

    result.headers_block = _slice_payload(
        frame.payload, offset, length - pad_len
    )
    return result^


# ---------------------------------------------------------------------------
# 3. PriorityPayload
# ---------------------------------------------------------------------------
struct PriorityPayload(Movable):
    """Decoded PRIORITY frame payload (RFC 9113 Section 6.3)."""

    var exclusive: Bool
    var stream_dependency: Int
    var weight: Int
    var error: String

    def __init__(out self):
        self.exclusive = False
        self.stream_dependency = 0
        self.weight = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.exclusive = take.exclusive
        self.stream_dependency = take.stream_dependency
        self.weight = take.weight
        self.error = take.error^

    def ok(self) -> Bool:
        return len(self.error) == 0


def decode_priority_payload(frame: Frame) -> PriorityPayload:
    """Decode a PRIORITY frame's payload into a PriorityPayload."""
    var result = PriorityPayload()

    if frame.frame_type != FRAME_PRIORITY:
        result.error = "expected PRIORITY frame, got type " + String(
            frame.frame_type
        )
        return result^

    if len(frame.payload) != 5:
        result.error = "PRIORITY frame must be 5 bytes, got " + String(
            len(frame.payload)
        )
        return result^

    result.exclusive = (Int(frame.payload[0]) >> 7) != 0
    result.stream_dependency = _read_u31(frame.payload, 0)
    result.weight = Int(frame.payload[4]) + 1
    return result^


# ---------------------------------------------------------------------------
# 4. RstStreamPayload
# ---------------------------------------------------------------------------
struct RstStreamPayload(Movable):
    """Decoded RST_STREAM frame payload (RFC 9113 Section 6.4)."""

    var error_code: Int
    var error: String

    def __init__(out self):
        self.error_code = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.error_code = take.error_code
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_rst_stream_payload(frame: Frame) -> RstStreamPayload:
    """Decode a RST_STREAM frame's payload into a RstStreamPayload."""
    var result = RstStreamPayload()

    if frame.frame_type != FRAME_RST_STREAM:
        result.error = "expected RST_STREAM frame, got type " + String(
            frame.frame_type
        )
        return result^

    if len(frame.payload) != 4:
        result.error = "RST_STREAM frame must be 4 bytes, got " + String(
            len(frame.payload)
        )
        return result^

    result.error_code = _read_u32(frame.payload, 0)
    return result^


# ---------------------------------------------------------------------------
# 5. Setting + SettingsPayload
# ---------------------------------------------------------------------------
struct Setting(Copyable, Movable):
    """A single SETTINGS parameter (id + value)."""

    var id: Int
    var value: Int

    def __init__(out self):
        self.id = 0
        self.value = 0

    def __init__(out self, id: Int, value: Int):
        self.id = id
        self.value = value

    def __init__(out self, *, other: Self):
        self.id = other.id
        self.value = other.value

    def __init__(out self, *, deinit take: Self):
        self.id = take.id
        self.value = take.value


struct SettingsPayload(Movable):
    """Decoded SETTINGS frame payload (RFC 9113 Section 6.5)."""

    var settings: List[Setting]
    var ack: Bool
    var error: String

    def __init__(out self):
        self.settings = List[Setting]()
        self.ack = False
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.settings = take.settings^
        self.ack = take.ack
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_settings_payload(frame: Frame) -> SettingsPayload:
    """Decode a SETTINGS frame's payload into a SettingsPayload."""
    var result = SettingsPayload()

    if frame.frame_type != FRAME_SETTINGS:
        result.error = "expected SETTINGS frame, got type " + String(
            frame.frame_type
        )
        return result^

    result.ack = (frame.flags & FLAG_ACK) != 0

    if result.ack:
        if len(frame.payload) != 0:
            result.error = "SETTINGS ACK must have empty payload"
        return result^

    var length = len(frame.payload)
    if length % 6 != 0:
        result.error = "SETTINGS payload length must be multiple of 6, got " + String(
            length
        )
        return result^

    var count = length // 6
    for i in range(count):
        var offset = i * 6
        var id = _read_u16(frame.payload, offset)
        var value = _read_u32(frame.payload, offset + 2)
        result.settings.append(Setting(id, value))

    return result^


# ---------------------------------------------------------------------------
# 6. PushPromisePayload
# ---------------------------------------------------------------------------
struct PushPromisePayload(Movable):
    """Decoded PUSH_PROMISE frame payload (RFC 9113 Section 6.6)."""

    var promised_stream_id: Int
    var headers_block: List[UInt8]
    var padding_length: Int
    var error: String

    def __init__(out self):
        self.promised_stream_id = 0
        self.headers_block = List[UInt8]()
        self.padding_length = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.promised_stream_id = take.promised_stream_id
        self.headers_block = take.headers_block^
        self.padding_length = take.padding_length
        self.error = take.error^

    def ok(self) -> Bool:
        return len(self.error) == 0


def decode_push_promise_payload(frame: Frame) -> PushPromisePayload:
    """Decode a PUSH_PROMISE frame's payload into a PushPromisePayload."""
    var result = PushPromisePayload()
    var length = len(frame.payload)

    if frame.frame_type != FRAME_PUSH_PROMISE:
        result.error = "expected PUSH_PROMISE frame, got type " + String(
            frame.frame_type
        )
        return result^

    var offset = 0
    var pad_len = 0

    if (frame.flags & FLAG_PADDED) != 0:
        if length < 1:
            result.error = (
                "PUSH_PROMISE PADDED frame too short for pad length byte"
            )
            return result^
        pad_len = Int(frame.payload[0])
        offset = 1
        result.padding_length = pad_len

    if length < offset + 4:
        result.error = (
            "PUSH_PROMISE frame too short for promised stream id"
        )
        return result^

    result.promised_stream_id = _read_u31(frame.payload, offset)
    offset += 4

    if pad_len > length - offset:
        result.error = "PUSH_PROMISE padding length exceeds available payload"
        return result^

    result.headers_block = _slice_payload(
        frame.payload, offset, length - pad_len
    )
    return result^


# ---------------------------------------------------------------------------
# 7. PingPayload
# ---------------------------------------------------------------------------
struct PingPayload(Movable):
    """Decoded PING frame payload (RFC 9113 Section 6.7)."""

    var opaque_data: List[UInt8]
    var ack: Bool
    var error: String

    def __init__(out self):
        self.opaque_data = List[UInt8]()
        self.ack = False
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.opaque_data = take.opaque_data^
        self.ack = take.ack
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_ping_payload(frame: Frame) -> PingPayload:
    """Decode a PING frame's payload into a PingPayload."""
    var result = PingPayload()

    if frame.frame_type != FRAME_PING:
        result.error = "expected PING frame, got type " + String(
            frame.frame_type
        )
        return result^

    if len(frame.payload) != 8:
        result.error = "PING frame must be 8 bytes, got " + String(
            len(frame.payload)
        )
        return result^

    result.ack = (frame.flags & FLAG_ACK) != 0
    result.opaque_data = _slice_payload(frame.payload, 0, 8)
    return result^


# ---------------------------------------------------------------------------
# 8. GoawayPayload
# ---------------------------------------------------------------------------
struct GoawayPayload(Movable):
    """Decoded GOAWAY frame payload (RFC 9113 Section 6.8)."""

    var last_stream_id: Int
    var error_code: Int
    var debug_data: List[UInt8]
    var error: String

    def __init__(out self):
        self.last_stream_id = 0
        self.error_code = 0
        self.debug_data = List[UInt8]()
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.last_stream_id = take.last_stream_id
        self.error_code = take.error_code
        self.debug_data = take.debug_data^
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_goaway_payload(frame: Frame) -> GoawayPayload:
    """Decode a GOAWAY frame's payload into a GoawayPayload."""
    var result = GoawayPayload()
    var length = len(frame.payload)

    if frame.frame_type != FRAME_GOAWAY:
        result.error = "expected GOAWAY frame, got type " + String(
            frame.frame_type
        )
        return result^

    if length < 8:
        result.error = "GOAWAY frame must be >= 8 bytes, got " + String(
            length
        )
        return result^

    result.last_stream_id = _read_u31(frame.payload, 0)
    result.error_code = _read_u32(frame.payload, 4)
    if length > 8:
        result.debug_data = _slice_payload(frame.payload, 8, length)

    return result^


# ---------------------------------------------------------------------------
# 9. WindowUpdatePayload
# ---------------------------------------------------------------------------
struct WindowUpdatePayload(Movable):
    """Decoded WINDOW_UPDATE frame payload (RFC 9113 Section 6.9)."""

    var window_increment: Int
    var error: String

    def __init__(out self):
        self.window_increment = 0
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.window_increment = take.window_increment
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_window_update_payload(frame: Frame) -> WindowUpdatePayload:
    """Decode a WINDOW_UPDATE frame's payload into a WindowUpdatePayload."""
    var result = WindowUpdatePayload()

    if frame.frame_type != FRAME_WINDOW_UPDATE:
        result.error = "expected WINDOW_UPDATE frame, got type " + String(
            frame.frame_type
        )
        return result^

    if len(frame.payload) != 4:
        result.error = "WINDOW_UPDATE frame must be 4 bytes, got " + String(
            len(frame.payload)
        )
        return result^

    result.window_increment = _read_u31(frame.payload, 0)
    return result^


# ---------------------------------------------------------------------------
# 10. ContinuationPayload
# ---------------------------------------------------------------------------
struct ContinuationPayload(Movable):
    """Decoded CONTINUATION frame payload (RFC 9113 Section 6.10)."""

    var headers_block: List[UInt8]
    var error: String

    def __init__(out self):
        self.headers_block = List[UInt8]()
        self.error = String("")

    def __init__(out self, *, deinit take: Self):
        self.headers_block = take.headers_block^
        self.error = take.error^

    def ok(self) -> Bool:
        return self.error.byte_length() == 0


def decode_continuation_payload(frame: Frame) -> ContinuationPayload:
    """Decode a CONTINUATION frame's payload into a ContinuationPayload."""
    var result = ContinuationPayload()

    if frame.frame_type != FRAME_CONTINUATION:
        result.error = "expected CONTINUATION frame, got type " + String(
            frame.frame_type
        )
        return result^

    result.headers_block = _slice_payload(
        frame.payload, 0, len(frame.payload)
    )
    return result^
