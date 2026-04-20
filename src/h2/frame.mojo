# src/h2/frame.mojo
#
# HTTP/2 frame codec — RFC 9113 compliant.
# Provides Frame struct, H2FrameConfig, decode_frame, encode_frame.

# ---------------------------------------------------------------------------
# Error codes (RFC 9113 Section 7)
# ---------------------------------------------------------------------------
comptime H2_NO_ERROR: Int = 0
comptime H2_PROTOCOL_ERROR: Int = 1
comptime H2_INTERNAL_ERROR: Int = 2
comptime H2_FLOW_CONTROL_ERROR: Int = 3
comptime H2_SETTINGS_TIMEOUT: Int = 4
comptime H2_STREAM_CLOSED: Int = 5
comptime H2_FRAME_SIZE_ERROR: Int = 6
comptime H2_REFUSED_STREAM: Int = 7
comptime H2_CANCEL: Int = 8
comptime H2_COMPRESSION_ERROR: Int = 9
comptime H2_CONNECT_ERROR: Int = 10
comptime H2_ENHANCE_YOUR_CALM: Int = 11
comptime H2_INADEQUATE_SECURITY: Int = 12
comptime H2_HTTP_1_1_REQUIRED: Int = 13

# ---------------------------------------------------------------------------
# Error scopes
# ---------------------------------------------------------------------------
comptime SCOPE_NONE: Int = 0
comptime SCOPE_STREAM: Int = 1
comptime SCOPE_CONNECTION: Int = 2

# ---------------------------------------------------------------------------
# Frame types (RFC 9113 Section 6)
# ---------------------------------------------------------------------------
comptime FRAME_DATA: Int = 0
comptime FRAME_HEADERS: Int = 1
comptime FRAME_PRIORITY: Int = 2
comptime FRAME_RST_STREAM: Int = 3
comptime FRAME_SETTINGS: Int = 4
comptime FRAME_PUSH_PROMISE: Int = 5
comptime FRAME_PING: Int = 6
comptime FRAME_GOAWAY: Int = 7
comptime FRAME_WINDOW_UPDATE: Int = 8
comptime FRAME_CONTINUATION: Int = 9

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
comptime FLAG_END_STREAM: Int = 0x01
comptime FLAG_ACK: Int = 0x01
comptime FLAG_END_HEADERS: Int = 0x04
comptime FLAG_PADDED: Int = 0x08
comptime FLAG_PRIORITY: Int = 0x20


# ---------------------------------------------------------------------------
# H2FrameConfig
# ---------------------------------------------------------------------------
struct H2FrameConfig(Copyable, Movable):
    """Controls frame decoding strictness and limits."""

    var allow_oversized_frame: Bool
    var allow_nonzero_padding: Bool
    var allow_settings_flood: Bool
    var max_frame_size: Int
    var max_settings_per_frame: Int
    var max_header_block_size: Int

    def __init__(
        out self,
        allow_oversized_frame: Bool = False,
        allow_nonzero_padding: Bool = False,
        allow_settings_flood: Bool = False,
        max_frame_size: Int = 16384,
        max_settings_per_frame: Int = 256,
        max_header_block_size: Int = 65536,
    ):
        self.allow_oversized_frame = allow_oversized_frame
        self.allow_nonzero_padding = allow_nonzero_padding
        self.allow_settings_flood = allow_settings_flood
        self.max_frame_size = max_frame_size
        self.max_settings_per_frame = max_settings_per_frame
        self.max_header_block_size = max_header_block_size

    def __init__(out self, *, other: Self):
        self.allow_oversized_frame = other.allow_oversized_frame
        self.allow_nonzero_padding = other.allow_nonzero_padding
        self.allow_settings_flood = other.allow_settings_flood
        self.max_frame_size = other.max_frame_size
        self.max_settings_per_frame = other.max_settings_per_frame
        self.max_header_block_size = other.max_header_block_size

    def __init__(out self, *, deinit take: Self):
        self.allow_oversized_frame = take.allow_oversized_frame
        self.allow_nonzero_padding = take.allow_nonzero_padding
        self.allow_settings_flood = take.allow_settings_flood
        self.max_frame_size = take.max_frame_size
        self.max_settings_per_frame = take.max_settings_per_frame
        self.max_header_block_size = take.max_header_block_size


def h2_strict_config() -> H2FrameConfig:
    """Strict RFC 9113 compliance — all checks enabled."""
    return H2FrameConfig()


def h2_lenient_config() -> H2FrameConfig:
    """Relaxes nonzero padding check for legacy interop."""
    return H2FrameConfig(allow_nonzero_padding=True)


def h2_permissive_config() -> H2FrameConfig:
    """Accepts nearly everything — for fuzzing / debugging."""
    return H2FrameConfig(
        allow_oversized_frame=True,
        allow_nonzero_padding=True,
        allow_settings_flood=True,
    )


# ---------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------
struct Frame(Copyable, Movable):
    """An HTTP/2 frame (header + raw payload)."""

    var length: Int
    var frame_type: Int
    var flags: Int
    var stream_id: Int
    var payload: List[UInt8]
    var error: String
    var error_code: Int
    var error_scope: Int

    def __init__(out self):
        self.length = 0
        self.frame_type = 0
        self.flags = 0
        self.stream_id = 0
        self.payload = List[UInt8]()
        self.error = String("")
        self.error_code = H2_NO_ERROR
        self.error_scope = SCOPE_NONE

    def __init__(
        out self,
        length: Int,
        frame_type: Int,
        flags: Int,
        stream_id: Int,
        payload: List[UInt8],
    ):
        self.length = length
        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id
        self.payload = payload.copy()
        self.error = String("")
        self.error_code = H2_NO_ERROR
        self.error_scope = SCOPE_NONE

    def __init__(out self, *, other: Self):
        self.length = other.length
        self.frame_type = other.frame_type
        self.flags = other.flags
        self.stream_id = other.stream_id
        self.payload = other.payload.copy()
        self.error = other.error
        self.error_code = other.error_code
        self.error_scope = other.error_scope

    def __init__(out self, *, deinit take: Self):
        self.length = take.length
        self.frame_type = take.frame_type
        self.flags = take.flags
        self.stream_id = take.stream_id
        self.payload = take.payload^
        self.error = take.error^
        self.error_code = take.error_code
        self.error_scope = take.error_scope

    def ok(self) -> Bool:
        """Returns True if the frame decoded without error."""
        return len(self.error) == 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _make_error_frame(
    length: Int,
    frame_type: Int,
    flags: Int,
    stream_id: Int,
    payload: List[UInt8],
    error: String,
    error_code: Int,
    error_scope: Int,
) -> Frame:
    """Build a Frame that carries an error."""
    var f = Frame(length, frame_type, flags, stream_id, payload)
    f.error = error
    f.error_code = error_code
    f.error_scope = error_scope
    return f^


def _requires_nonzero_stream(ft: Int) -> Bool:
    """Frame types that MUST have stream_id != 0."""
    return (
        ft == FRAME_DATA
        or ft == FRAME_HEADERS
        or ft == FRAME_PRIORITY
        or ft == FRAME_RST_STREAM
        or ft == FRAME_PUSH_PROMISE
        or ft == FRAME_CONTINUATION
    )


def _requires_zero_stream(ft: Int) -> Bool:
    """Frame types that MUST have stream_id == 0."""
    return ft == FRAME_SETTINGS or ft == FRAME_PING or ft == FRAME_GOAWAY


# ---------------------------------------------------------------------------
# decode_frame
# ---------------------------------------------------------------------------
def decode_frame(
    wire: List[UInt8],
    pos: Int = 0,
    config: H2FrameConfig = H2FrameConfig(),
) -> Tuple[Frame, Int, String]:
    """Decode one HTTP/2 frame from `wire` starting at `pos`.

    Returns (frame, bytes_consumed, error_string).
    On success error_string is empty and frame.ok() is True.
    On error the frame still contains whatever was parsed, plus error info.
    """
    var available = len(wire) - pos

    # --- Need at least 9-byte header ---
    if available < 9:
        var f = Frame()
        f.error = "incomplete frame header: need 9 bytes, have " + String(
            available
        )
        f.error_code = H2_FRAME_SIZE_ERROR
        f.error_scope = SCOPE_CONNECTION
        return (f^, 0, f.error)

    # --- Parse 9-byte header ---
    var length = (
        (Int(wire[pos]) << 16)
        | (Int(wire[pos + 1]) << 8)
        | Int(wire[pos + 2])
    )
    var frame_type = Int(wire[pos + 3])
    var flags = Int(wire[pos + 4])
    var stream_id = (
        (Int(wire[pos + 5]) << 24)
        | (Int(wire[pos + 6]) << 16)
        | (Int(wire[pos + 7]) << 8)
        | Int(wire[pos + 8])
    ) & 0x7FFFFFFF  # mask reserved bit

    # --- Check payload fits in wire ---
    if available < 9 + length:
        var f = Frame()
        f.length = length
        f.frame_type = frame_type
        f.flags = flags
        f.stream_id = stream_id
        f.error = (
            "incomplete frame payload: need "
            + String(length)
            + " bytes, have "
            + String(available - 9)
        )
        f.error_code = H2_FRAME_SIZE_ERROR
        f.error_scope = SCOPE_CONNECTION
        return (f^, 0, f.error)

    # --- Check max_frame_size ---
    if not config.allow_oversized_frame and length > config.max_frame_size:
        var payload = List[UInt8]()
        for i in range(length):
            payload.append(wire[pos + 9 + i])
        var f = _make_error_frame(
            length,
            frame_type,
            flags,
            stream_id,
            payload,
            "frame payload "
            + String(length)
            + " exceeds max_frame_size "
            + String(config.max_frame_size),
            H2_FRAME_SIZE_ERROR,
            SCOPE_CONNECTION,
        )
        return (f^, 9 + length, f.error)

    # --- Copy payload ---
    var payload = List[UInt8]()
    for i in range(length):
        payload.append(wire[pos + 9 + i])

    var consumed = 9 + length

    # --- Stream ID validation ---
    if _requires_nonzero_stream(frame_type) and stream_id == 0:
        var f = _make_error_frame(
            length,
            frame_type,
            flags,
            stream_id,
            payload,
            "frame type "
            + String(frame_type)
            + " requires stream_id != 0",
            H2_PROTOCOL_ERROR,
            SCOPE_CONNECTION,
        )
        return (f^, consumed, f.error)

    if _requires_zero_stream(frame_type) and stream_id != 0:
        var f = _make_error_frame(
            length,
            frame_type,
            flags,
            stream_id,
            payload,
            "frame type "
            + String(frame_type)
            + " requires stream_id == 0",
            H2_PROTOCOL_ERROR,
            SCOPE_CONNECTION,
        )
        return (f^, consumed, f.error)

    # --- Type-specific validation ---

    # PING: must be exactly 8 bytes (Section 6.7)
    if frame_type == FRAME_PING:
        if length != 8:
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "PING frame length must be 8, got " + String(length),
                H2_FRAME_SIZE_ERROR,
                SCOPE_CONNECTION,
            )
            return (f^, consumed, f.error)

    # RST_STREAM: must be exactly 4 bytes (Section 6.4)
    if frame_type == FRAME_RST_STREAM:
        if length != 4:
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "RST_STREAM frame length must be 4, got " + String(length),
                H2_FRAME_SIZE_ERROR,
                SCOPE_CONNECTION,
            )
            return (f^, consumed, f.error)

    # PRIORITY: must be exactly 5 bytes (Section 6.3)
    if frame_type == FRAME_PRIORITY:
        if length != 5:
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "PRIORITY frame length must be 5, got " + String(length),
                H2_FRAME_SIZE_ERROR,
                SCOPE_STREAM,
            )
            return (f^, consumed, f.error)

    # WINDOW_UPDATE: must be exactly 4 bytes (Section 6.9)
    if frame_type == FRAME_WINDOW_UPDATE:
        if length != 4:
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "WINDOW_UPDATE frame length must be 4, got " + String(length),
                H2_FRAME_SIZE_ERROR,
                SCOPE_CONNECTION,
            )
            return (f^, consumed, f.error)

    # GOAWAY: minimum 8 bytes (Section 6.8)
    if frame_type == FRAME_GOAWAY:
        if length < 8:
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "GOAWAY frame length must be >= 8, got " + String(length),
                H2_FRAME_SIZE_ERROR,
                SCOPE_CONNECTION,
            )
            return (f^, consumed, f.error)

    # SETTINGS: multiple of 6, ACK must have no payload (Section 6.5)
    if frame_type == FRAME_SETTINGS:
        if (flags & FLAG_ACK) != 0:
            if length != 0:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "SETTINGS ACK frame must have empty payload, got "
                    + String(length)
                    + " bytes",
                    H2_FRAME_SIZE_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)
        else:
            if length % 6 != 0:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "SETTINGS frame length must be multiple of 6, got "
                    + String(length),
                    H2_FRAME_SIZE_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)

            # Settings flood check
            if not config.allow_settings_flood:
                var num_entries = length // 6
                if num_entries > config.max_settings_per_frame:
                    var f = _make_error_frame(
                        length,
                        frame_type,
                        flags,
                        stream_id,
                        payload,
                        "SETTINGS flood: "
                        + String(num_entries)
                        + " entries exceeds max "
                        + String(config.max_settings_per_frame),
                        H2_PROTOCOL_ERROR,
                        SCOPE_CONNECTION,
                    )
                    return (f^, consumed, f.error)

    # Padding validation for DATA, HEADERS, PUSH_PROMISE
    if (
        frame_type == FRAME_DATA
        or frame_type == FRAME_HEADERS
        or frame_type == FRAME_PUSH_PROMISE
    ):
        if (flags & FLAG_PADDED) != 0:
            if length < 1:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "PADDED frame too short for pad length byte",
                    H2_PROTOCOL_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)

            var pad_length = Int(payload[0])

            # For HEADERS with PRIORITY, we need at least 1 (pad) + 5 (priority) + pad_length
            var min_overhead = 1  # pad length byte
            if frame_type == FRAME_HEADERS and (flags & FLAG_PRIORITY) != 0:
                min_overhead = 6  # 1 pad + 5 priority fields
            elif frame_type == FRAME_PUSH_PROMISE:
                min_overhead = 5  # 1 pad + 4 promised stream id

            if pad_length > length - min_overhead:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "padding length "
                    + String(pad_length)
                    + " exceeds available payload",
                    H2_PROTOCOL_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)

            # Check nonzero padding bytes if strict
            if not config.allow_nonzero_padding and pad_length > 0:
                var pad_start = length - pad_length
                for i in range(pad_start, length):
                    if Int(payload[i]) != 0:
                        var f = _make_error_frame(
                            length,
                            frame_type,
                            flags,
                            stream_id,
                            payload,
                            "nonzero padding byte at offset " + String(i),
                            H2_PROTOCOL_ERROR,
                            SCOPE_CONNECTION,
                        )
                        return (f^, consumed, f.error)

    # WINDOW_UPDATE: zero increment check (Section 6.9.1)
    if frame_type == FRAME_WINDOW_UPDATE and length == 4:
        var increment = (
            (Int(payload[0]) << 24)
            | (Int(payload[1]) << 16)
            | (Int(payload[2]) << 8)
            | Int(payload[3])
        ) & 0x7FFFFFFF
        if increment == 0:
            var scope = SCOPE_CONNECTION if stream_id == 0 else SCOPE_STREAM
            var f = _make_error_frame(
                length,
                frame_type,
                flags,
                stream_id,
                payload,
                "WINDOW_UPDATE increment must not be zero",
                H2_PROTOCOL_ERROR,
                scope,
            )
            return (f^, consumed, f.error)

    # PUSH_PROMISE: promised stream ID must not be 0 (Section 6.6)
    if frame_type == FRAME_PUSH_PROMISE:
        var pp_offset = 0
        if (flags & FLAG_PADDED) != 0:
            pp_offset = 1
        if length >= pp_offset + 4:
            var promised_id = (
                (Int(payload[pp_offset]) << 24)
                | (Int(payload[pp_offset + 1]) << 16)
                | (Int(payload[pp_offset + 2]) << 8)
                | Int(payload[pp_offset + 3])
            ) & 0x7FFFFFFF
            if promised_id == 0:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "PUSH_PROMISE promised_stream_id must not be 0",
                    H2_PROTOCOL_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)
            # Promised stream IDs must be even (server-initiated)
            if (promised_id & 1) != 0:
                var f = _make_error_frame(
                    length,
                    frame_type,
                    flags,
                    stream_id,
                    payload,
                    "PUSH_PROMISE promised_stream_id must be even, got "
                    + String(promised_id),
                    H2_PROTOCOL_ERROR,
                    SCOPE_CONNECTION,
                )
                return (f^, consumed, f.error)

    # --- Success ---
    var frame = Frame(length, frame_type, flags, stream_id, payload)
    return (frame^, consumed, String(""))


# ---------------------------------------------------------------------------
# encode_frame
# ---------------------------------------------------------------------------
def encode_frame(frame: Frame) -> List[UInt8]:
    """Encode a Frame into wire bytes (9-byte header + payload)."""
    var payload_len = len(frame.payload)
    var result = List[UInt8]()

    # 3-byte length (big-endian)
    result.append(UInt8((payload_len >> 16) & 0xFF))
    result.append(UInt8((payload_len >> 8) & 0xFF))
    result.append(UInt8(payload_len & 0xFF))

    # 1-byte type
    result.append(UInt8(frame.frame_type & 0xFF))

    # 1-byte flags
    result.append(UInt8(frame.flags & 0xFF))

    # 4-byte stream ID (big-endian, reserved bit = 0)
    result.append(UInt8((frame.stream_id >> 24) & 0x7F))
    result.append(UInt8((frame.stream_id >> 16) & 0xFF))
    result.append(UInt8((frame.stream_id >> 8) & 0xFF))
    result.append(UInt8(frame.stream_id & 0xFF))

    # Payload
    for i in range(payload_len):
        result.append(frame.payload[i])

    return result^
