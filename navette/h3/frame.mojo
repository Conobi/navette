from std.collections import Span
from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_encode_at, varint_decode, varint_len

# Frame type constants (RFC 9114 §7.2)
comptime H3_FRAME_DATA:     UInt64 = 0x00
comptime H3_FRAME_HEADERS:  UInt64 = 0x01
comptime H3_FRAME_SETTINGS: UInt64 = 0x04
comptime H3_FRAME_GOAWAY:   UInt64 = 0x07

# SETTINGS identifiers (RFC 9114 §7.2.4)
comptime SETTINGS_QPACK_MAX_TABLE_CAPACITY: UInt64 = 0x01
comptime SETTINGS_MAX_FIELD_SECTION_SIZE:   UInt64 = 0x06
comptime SETTINGS_QPACK_BLOCKED_STREAMS:    UInt64 = 0x07
# RFC 9297 §2.2 — H3_DATAGRAM SETTINGS identifier. Both peers MUST
# advertise this (value = 1) before either side may send H3-framed
# datagrams; absence or 0 means H3-layer datagrams are unsupported even
# if the underlying QUIC layer negotiated DATAGRAM via RFC 9221.
comptime SETTINGS_H3_DATAGRAM: UInt64 = 0x33


struct H3RawFrame(Copyable, Movable):
    var frame_type: UInt64
    var payload: List[Byte]

    def __init__(out self, frame_type: UInt64, var payload: List[Byte]):
        self.frame_type = frame_type
        self.payload = payload^

    def __init__(out self, *, copy: Self):
        self.frame_type = copy.frame_type
        self.payload = List[Byte](copy=copy.payload)

    def encode(self) raises -> List[Byte]:
        var result = List[Byte](capacity=2 + len(self.payload))
        var pos = len(result)
        result.resize(pos + varint_len(self.frame_type), Byte(0))
        _ = varint_encode_at(result, pos, self.frame_type)
        pos = len(result)
        result.resize(pos + varint_len(UInt64(len(self.payload))), Byte(0))
        _ = varint_encode_at(result, pos, UInt64(len(self.payload)))
        result.extend(Span(self.payload))
        return result^


struct DataFrame(Copyable, Movable):
    var data: List[Byte]

    def __init__(out self, var data: List[Byte]):
        self.data = data^

    def __init__(out self, *, copy: Self):
        self.data = List[Byte](copy=copy.data)

    @staticmethod
    def decode(var payload: List[Byte]) -> DataFrame:
        return DataFrame(payload^)

    def encode(self) raises -> List[Byte]:
        var result = List[Byte](capacity=2 + len(self.data))
        var pos = len(result)
        result.resize(pos + varint_len(H3_FRAME_DATA), Byte(0))
        _ = varint_encode_at(result, pos, H3_FRAME_DATA)
        pos = len(result)
        result.resize(pos + varint_len(UInt64(len(self.data))), Byte(0))
        _ = varint_encode_at(result, pos, UInt64(len(self.data)))
        result.extend(Span(self.data))
        return result^


struct HeadersFrame(Copyable, Movable):
    var encoded_fields: List[Byte]

    def __init__(out self, var encoded_fields: List[Byte]):
        self.encoded_fields = encoded_fields^

    def __init__(out self, *, copy: Self):
        self.encoded_fields = List[Byte](copy=copy.encoded_fields)

    @staticmethod
    def decode(var payload: List[Byte]) -> HeadersFrame:
        return HeadersFrame(payload^)

    def encode(self) raises -> List[Byte]:
        var result = List[Byte](capacity=2 + len(self.encoded_fields))
        var pos = len(result)
        result.resize(pos + varint_len(H3_FRAME_HEADERS), Byte(0))
        _ = varint_encode_at(result, pos, H3_FRAME_HEADERS)
        pos = len(result)
        result.resize(pos + varint_len(UInt64(len(self.encoded_fields))), Byte(0))
        _ = varint_encode_at(result, pos, UInt64(len(self.encoded_fields)))
        result.extend(Span(self.encoded_fields))
        return result^


struct SettingsPair(Copyable, Movable):
    var id: UInt64
    var value: UInt64

    def __init__(out self, id: UInt64, value: UInt64):
        self.id = id
        self.value = value

    def __init__(out self, *, copy: Self):
        self.id = copy.id
        self.value = copy.value


struct SettingsFrame(Copyable, Movable):
    var pairs: List[SettingsPair]

    def __init__(out self, var pairs: List[SettingsPair]):
        self.pairs = pairs^

    def __init__(out self, *, copy: Self):
        self.pairs = List[SettingsPair](copy=copy.pairs)

    @staticmethod
    def decode(payload: List[Byte]) raises -> SettingsFrame:
        var pairs = List[SettingsPair]()
        var r = ByteReader(Span(payload))
        while r.remaining() > 0:
            var id = varint_decode(r)
            var value = varint_decode(r)
            pairs.append(SettingsPair(id, value))
        return SettingsFrame(pairs^)

    def encode(self) raises -> List[Byte]:
        var payload = List[Byte](capacity=len(self.pairs) * 4)
        for ref pair in self.pairs:
            var pos = len(payload)
            payload.resize(pos + varint_len(pair.id), Byte(0))
            _ = varint_encode_at(payload, pos, pair.id)
            pos = len(payload)
            payload.resize(pos + varint_len(pair.value), Byte(0))
            _ = varint_encode_at(payload, pos, pair.value)
        var result = List[Byte](capacity=2 + len(payload))
        var pos = len(result)
        result.resize(pos + varint_len(H3_FRAME_SETTINGS), Byte(0))
        _ = varint_encode_at(result, pos, H3_FRAME_SETTINGS)
        pos = len(result)
        result.resize(pos + varint_len(UInt64(len(payload))), Byte(0))
        _ = varint_encode_at(result, pos, UInt64(len(payload)))
        result.extend(Span(payload))
        return result^

    def get(self, id: UInt64) -> Optional[UInt64]:
        for ref pair in self.pairs:
            if pair.id == id:
                return Optional[UInt64](pair.value)
        return Optional[UInt64](None)


def parse_h3_frame[origin: Origin](mut r: ByteReader[origin]) raises -> H3RawFrame:
    """Parse one H3 frame from the reader.

    Reads: type(varint) + length(varint) + payload(bytes).
    Raises if the stream is truncated.
    Unknown frame types are returned as-is (RFC 9114 §7.2.8).
    """
    var frame_type = varint_decode(r)
    var length = varint_decode(r)
    if UInt64(r.remaining()) < length:
        raise "H3: truncated frame payload (declared " + String(length) + " bytes, got " + String(r.remaining()) + ")"
    var n = Int(length)
    var payload = List[Byte](capacity=n)
    for _ in range(n):
        payload.append(r.read_u8())
    return H3RawFrame(frame_type, payload^)
