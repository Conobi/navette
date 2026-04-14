# src/quic/error.mojo
# Transport error codes — RFC 9000 Section 20.


struct QuicTransportError(Copyable, Movable, Writable):
    var code: UInt64
    var frame_type: UInt64
    var reason: String

    def __init__(out self, code: UInt64, reason: String):
        self.code = code
        self.frame_type = UInt64(0)
        self.reason = reason

    def __init__(out self, code: UInt64, frame_type: UInt64, reason: String):
        self.code = code
        self.frame_type = frame_type
        self.reason = reason

    def __init__(out self, *, other: Self):
        self.code = other.code
        self.frame_type = other.frame_type
        self.reason = other.reason

    def __init__(out self, *, deinit take: Self):
        self.code = take.code
        self.frame_type = take.frame_type
        self.reason = take.reason^

    def write_to[W: Writer](self, mut writer: W):
        writer.write("QuicTransportError(")
        writer.write(hex(Int(self.code)))
        writer.write(")")
        if len(self.reason) > 0:
            writer.write(": ")
            writer.write(self.reason)


# RFC 9000 Section 20 — Transport Error Codes
comptime NO_ERROR: UInt64 = 0x00
comptime INTERNAL_ERROR: UInt64 = 0x01
comptime CONNECTION_REFUSED: UInt64 = 0x02
comptime FLOW_CONTROL_ERROR: UInt64 = 0x03
comptime STREAM_LIMIT_ERROR: UInt64 = 0x04
comptime STREAM_STATE_ERROR: UInt64 = 0x05
comptime FINAL_SIZE_ERROR: UInt64 = 0x06
comptime FRAME_ENCODING_ERROR: UInt64 = 0x07
comptime TRANSPORT_PARAMETER_ERROR: UInt64 = 0x08
comptime CONNECTION_ID_LIMIT_ERROR: UInt64 = 0x09
comptime PROTOCOL_VIOLATION: UInt64 = 0x0A
comptime INVALID_TOKEN: UInt64 = 0x0B
comptime APPLICATION_ERROR: UInt64 = 0x0C
comptime CRYPTO_BUFFER_EXCEEDED: UInt64 = 0x0D
comptime KEY_UPDATE_ERROR: UInt64 = 0x0E
comptime AEAD_LIMIT_REACHED: UInt64 = 0x0F
comptime NO_VIABLE_PATH: UInt64 = 0x10
comptime VERSION_NEGOTIATION_ERROR: UInt64 = 0x11


def frame_encoding_error(frame_type: UInt64, reason: String) -> QuicTransportError:
    return QuicTransportError(FRAME_ENCODING_ERROR, frame_type, reason)


def transport_parameter_error(reason: String) -> QuicTransportError:
    return QuicTransportError(TRANSPORT_PARAMETER_ERROR, reason)


def protocol_violation(reason: String) -> QuicTransportError:
    return QuicTransportError(PROTOCOL_VIOLATION, reason)
