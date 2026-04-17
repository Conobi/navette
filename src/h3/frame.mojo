from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len

# Frame type constants (RFC 9114 §7.2)
comptime H3_FRAME_DATA:     UInt64 = 0x00
comptime H3_FRAME_HEADERS:  UInt64 = 0x01
comptime H3_FRAME_SETTINGS: UInt64 = 0x04
comptime H3_FRAME_GOAWAY:   UInt64 = 0x07

# SETTINGS identifiers (RFC 9114 §7.2.4)
comptime SETTINGS_QPACK_MAX_TABLE_CAPACITY: UInt64 = 0x01
comptime SETTINGS_MAX_FIELD_SECTION_SIZE:   UInt64 = 0x06
comptime SETTINGS_QPACK_BLOCKED_STREAMS:    UInt64 = 0x07


struct H3RawFrame(Copyable, Movable):
    var frame_type: UInt64
    var payload: List[UInt8]

    def __init__(out self, frame_type: UInt64, payload: List[UInt8]):
        self.frame_type = frame_type
        self.payload = List[UInt8](copy=payload)

    def __init__(out self, *, copy_from: Self):
        self.frame_type = copy_from.frame_type
        self.payload = List[UInt8](copy=copy_from.payload)

    def encode(self) raises -> List[UInt8]:
        var w = ByteWriter()
        varint_encode(w, self.frame_type)
        varint_encode(w, UInt64(len(self.payload)))
        for i in range(len(self.payload)):
            w.write_u8(self.payload[i])
        return w.finish()


struct DataFrame(Copyable, Movable):
    var data: List[UInt8]

    def __init__(out self, data: List[UInt8]):
        self.data = List[UInt8](copy=data)

    def __init__(out self, *, copy_from: Self):
        self.data = List[UInt8](copy=copy_from.data)

    @staticmethod
    def decode(payload: List[UInt8]) -> DataFrame:
        return DataFrame(payload)

    def encode(self) raises -> List[UInt8]:
        var raw = H3RawFrame(H3_FRAME_DATA, self.data)
        return raw.encode()


struct HeadersFrame(Copyable, Movable):
    var encoded_fields: List[UInt8]

    def __init__(out self, encoded_fields: List[UInt8]):
        self.encoded_fields = List[UInt8](copy=encoded_fields)

    def __init__(out self, *, copy_from: Self):
        self.encoded_fields = List[UInt8](copy=copy_from.encoded_fields)

    @staticmethod
    def decode(payload: List[UInt8]) -> HeadersFrame:
        return HeadersFrame(payload)

    def encode(self) raises -> List[UInt8]:
        var raw = H3RawFrame(H3_FRAME_HEADERS, self.encoded_fields)
        return raw.encode()


struct SettingsPair(Copyable, Movable):
    var id: UInt64
    var value: UInt64

    def __init__(out self, id: UInt64, value: UInt64):
        self.id = id
        self.value = value

    def __init__(out self, *, copy_from: Self):
        self.id = copy_from.id
        self.value = copy_from.value


struct SettingsFrame(Copyable, Movable):
    var pairs: List[SettingsPair]

    def __init__(out self, pairs: List[SettingsPair]):
        self.pairs = List[SettingsPair](copy=pairs)

    def __init__(out self, *, copy_from: Self):
        self.pairs = List[SettingsPair](copy=copy_from.pairs)

    @staticmethod
    def decode(payload: List[UInt8]) raises -> SettingsFrame:
        var pairs = List[SettingsPair]()
        var r = ByteReader(Span(payload))
        while r.remaining() > 0:
            var id = varint_decode(r)
            var value = varint_decode(r)
            pairs.append(SettingsPair(id, value))
        return SettingsFrame(pairs)

    def encode(self) raises -> List[UInt8]:
        var pw = ByteWriter()
        for i in range(len(self.pairs)):
            varint_encode(pw, self.pairs[i].id)
            varint_encode(pw, self.pairs[i].value)
        var payload = pw.finish()
        var raw = H3RawFrame(H3_FRAME_SETTINGS, payload)
        return raw.encode()

    def get(self, id: UInt64) -> Optional[UInt64]:
        for i in range(len(self.pairs)):
            if self.pairs[i].id == id:
                return Optional[UInt64](self.pairs[i].value)
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
    var payload = List[UInt8]()
    var n = Int(length)
    for _ in range(n):
        payload.append(r.read_u8())
    return H3RawFrame(frame_type, payload)
