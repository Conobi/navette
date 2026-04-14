# src/quic/codec.mojo
# QUIC varint codec (RFC 9000 Section 16) + binary I/O cursors.


struct ByteReader[origin: Origin]:
    var _buf: Span[UInt8, Self.origin]
    var pos: Int

    def __init__(out self, buf: Span[UInt8, Self.origin]):
        self._buf = buf
        self.pos = 0

    def remaining(self) -> Int:
        return len(self._buf) - self.pos

    def read_u8(mut self) raises -> UInt8:
        if self.pos >= len(self._buf):
            raise "ByteReader: underflow reading u8"
        var v = self._buf[self.pos]
        self.pos += 1
        return v

    def read_u16_be(mut self) raises -> UInt16:
        if self.pos + 2 > len(self._buf):
            raise "ByteReader: underflow reading u16"
        var v = (UInt16(self._buf[self.pos]) << 8) | UInt16(self._buf[self.pos + 1])
        self.pos += 2
        return v

    def read_u32_be(mut self) raises -> UInt32:
        if self.pos + 4 > len(self._buf):
            raise "ByteReader: underflow reading u32"
        var v = (
            (UInt32(self._buf[self.pos]) << 24)
            | (UInt32(self._buf[self.pos + 1]) << 16)
            | (UInt32(self._buf[self.pos + 2]) << 8)
            | UInt32(self._buf[self.pos + 3])
        )
        self.pos += 4
        return v

    def read_u64_be(mut self) raises -> UInt64:
        if self.pos + 8 > len(self._buf):
            raise "ByteReader: underflow reading u64"
        var v = UInt64(0)
        for i in range(8):
            v = (v << 8) | UInt64(self._buf[self.pos + i])
        self.pos += 8
        return v

    def read_bytes(mut self, n: Int) raises -> List[UInt8]:
        if self.pos + n > len(self._buf):
            raise "ByteReader: underflow reading " + String(n) + " bytes"
        var result = List[UInt8](capacity=n)
        for i in range(n):
            result.append(self._buf[self.pos + i])
        self.pos += n
        return result^

    def skip(mut self, n: Int) raises:
        if self.pos + n > len(self._buf):
            raise "ByteReader: underflow skipping " + String(n) + " bytes"
        self.pos += n

    def peek_u8(self) raises -> UInt8:
        if self.pos >= len(self._buf):
            raise "ByteReader: underflow peeking u8"
        return self._buf[self.pos]


struct ByteWriter:
    var buf: List[UInt8]

    def __init__(out self):
        self.buf = List[UInt8]()

    def __init__(out self, capacity: Int):
        self.buf = List[UInt8](capacity=capacity)

    def write_u8(mut self, value: UInt8):
        self.buf.append(value)

    def write_u16_be(mut self, value: UInt16):
        self.buf.append(UInt8((value >> 8) & 0xFF))
        self.buf.append(UInt8(value & 0xFF))

    def write_u32_be(mut self, value: UInt32):
        self.buf.append(UInt8((value >> 24) & 0xFF))
        self.buf.append(UInt8((value >> 16) & 0xFF))
        self.buf.append(UInt8((value >> 8) & 0xFF))
        self.buf.append(UInt8(value & 0xFF))

    def write_u64_be(mut self, value: UInt64):
        for i in range(8):
            self.buf.append(UInt8((value >> UInt64((7 - i) * 8)) & 0xFF))

    def write_bytes(mut self, data: Span[UInt8, _]):
        for i in range(len(data)):
            self.buf.append(data[i])

    def len(self) -> Int:
        return len(self.buf)

    def finish(mut self) -> List[UInt8]:
        var result = self.buf^
        self.buf = List[UInt8]()
        return result^


def varint_len(value: UInt64) -> Int:
    if value <= UInt64(63):
        return 1
    if value <= UInt64(16383):
        return 2
    if value <= UInt64(1073741823):
        return 4
    return 8


def varint_encode(mut writer: ByteWriter, value: UInt64) raises:
    if value > UInt64(4611686018427387903):
        raise "varint value exceeds max (2^62 - 1)"
    var size = varint_len(value)
    if size == 1:
        writer.write_u8(UInt8(value))
    elif size == 2:
        writer.write_u16_be(UInt16(value) | UInt16(0x4000))
    elif size == 4:
        writer.write_u32_be(UInt32(value) | UInt32(0x80000000))
    else:
        writer.write_u64_be(value | UInt64(0xC000000000000000))


def varint_decode[origin: Origin](mut reader: ByteReader[origin]) raises -> UInt64:
    var first = reader.read_u8()
    var prefix = Int(first >> 6)
    if prefix == 0:
        return UInt64(first)
    elif prefix == 1:
        if reader.remaining() < 1:
            raise "varint truncated: need 2 bytes"
        var second = reader.read_u8()
        return (UInt64(first & 0x3F) << 8) | UInt64(second)
    elif prefix == 2:
        if reader.remaining() < 3:
            raise "varint truncated: need 4 bytes"
        var b1 = reader.read_u8()
        var b2 = reader.read_u8()
        var b3 = reader.read_u8()
        return (
            (UInt64(first & 0x3F) << 24)
            | (UInt64(b1) << 16)
            | (UInt64(b2) << 8)
            | UInt64(b3)
        )
    else:
        if reader.remaining() < 7:
            raise "varint truncated: need 8 bytes"
        var v = UInt64(first & 0x3F)
        for _ in range(7):
            v = (v << 8) | UInt64(reader.read_u8())
        return v
