# src/quic/codec.mojo
# QUIC varint codec (RFC 9000 Section 16) + binary I/O cursors.


struct ByteReader[origin: Origin]:
    var _buf: Span[UInt8, Self.origin]
    var pos: Int

    def __init__(out self, buf: Span[UInt8, Self.origin]):
        self._buf = buf
        self.pos = 0

    @always_inline
    def remaining(self) -> Int:
        return len(self._buf) - self.pos

    @always_inline
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
        """Read n bytes, returning an owned copy."""
        if self.pos + n > len(self._buf):
            raise "ByteReader: underflow reading " + String(n) + " bytes"
        var result = List[UInt8](capacity=n)
        for i in range(n):
            result.append(self._buf[self.pos + i])
        self.pos += n
        return result^

    @always_inline
    def read_span(mut self, n: Int) raises -> Span[UInt8, Self.origin]:
        """Read n bytes as a zero-copy Span view into the underlying buffer."""
        if self.pos + n > len(self._buf):
            raise "ByteReader: underflow reading " + String(n) + " bytes"
        var result = self._buf[self.pos : self.pos + n]
        self.pos += n
        return result

    def skip(mut self, n: Int) raises:
        if self.pos + n > len(self._buf):
            raise "ByteReader: underflow skipping " + String(n) + " bytes"
        self.pos += n

    @always_inline
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
        """Append one byte."""
        var base = len(self.buf)
        self.buf.resize(base + 1, UInt8(0))
        _ = write_u8_at(self.buf, base, value)

    def write_u16_be(mut self, value: UInt16):
        """Append a 16-bit big-endian integer."""
        var base = len(self.buf)
        self.buf.resize(base + 2, UInt8(0))
        _ = write_u16_be_at(self.buf, base, value)

    def write_u32_be(mut self, value: UInt32):
        """Append a 32-bit big-endian integer."""
        var base = len(self.buf)
        self.buf.resize(base + 4, UInt8(0))
        _ = write_u32_be_at(self.buf, base, value)

    def write_u64_be(mut self, value: UInt64):
        """Append a 64-bit big-endian integer."""
        var base = len(self.buf)
        self.buf.resize(base + 8, UInt8(0))
        _ = write_u64_be_at(self.buf, base, value)

    def write_bytes(mut self, data: Span[UInt8, _]):
        """Append a byte span to the write buffer."""
        self.buf.extend(data)

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


def varint_encode_into(mut buf: List[UInt8], value: UInt64) raises:
    """Encode a QUIC varint directly into a byte list with overflow check.

    Same encoding as varint_encode but bypasses ByteWriter indirection.
    """
    if value > UInt64(4611686018427387903):
        raise "varint value exceeds max (2^62 - 1)"
    varint_encode_raw(buf, value)


def varint_encode_raw(mut buf: List[UInt8], value: UInt64):
    """Encode a QUIC varint and append it directly to a byte list.

    Bypasses ByteWriter to avoid intermediate allocation when writing
    frames directly into a pre-existing packet buffer.
    """
    var size = varint_len(value)
    if size == 1:
        buf.append(UInt8(value))
    elif size == 2:
        var v = UInt16(value) | UInt16(0x4000)
        buf.append(UInt8((v >> 8) & 0xFF))
        buf.append(UInt8(v & 0xFF))
    elif size == 4:
        var v = UInt32(value) | UInt32(0x80000000)
        buf.append(UInt8((v >> 24) & 0xFF))
        buf.append(UInt8((v >> 16) & 0xFF))
        buf.append(UInt8((v >> 8) & 0xFF))
        buf.append(UInt8(v & 0xFF))
    else:
        var v = value | UInt64(0xC000000000000000)
        for i in range(8):
            buf.append(UInt8((v >> UInt64((7 - i) * 8)) & 0xFF))


@always_inline
def write_u8_at(mut buf: List[UInt8], pos: Int, value: UInt8) -> Int:
    """Write one byte at `pos`. Returns 1."""
    buf[pos] = value
    return 1


@always_inline
def write_u16_be_at(mut buf: List[UInt8], pos: Int, value: UInt16) -> Int:
    """Write a 16-bit big-endian integer at `pos`. Returns 2."""
    buf[pos] = UInt8((value >> 8) & 0xFF)
    buf[pos + 1] = UInt8(value & 0xFF)
    return 2


@always_inline
def write_u24_be_at(mut buf: List[UInt8], pos: Int, value: UInt32) -> Int:
    """Write a 24-bit big-endian integer at `pos`. Returns 3."""
    buf[pos] = UInt8((value >> 16) & 0xFF)
    buf[pos + 1] = UInt8((value >> 8) & 0xFF)
    buf[pos + 2] = UInt8(value & 0xFF)
    return 3


@always_inline
def write_u32_be_at(mut buf: List[UInt8], pos: Int, value: UInt32) -> Int:
    """Write a 32-bit big-endian integer at `pos`. Returns 4."""
    buf[pos] = UInt8((value >> 24) & 0xFF)
    buf[pos + 1] = UInt8((value >> 16) & 0xFF)
    buf[pos + 2] = UInt8((value >> 8) & 0xFF)
    buf[pos + 3] = UInt8(value & 0xFF)
    return 4


@always_inline
def write_u64_be_at(mut buf: List[UInt8], pos: Int, value: UInt64) -> Int:
    """Write a 64-bit big-endian integer at `pos`. Returns 8."""
    for i in range(8):
        buf[pos + i] = UInt8((value >> UInt64((7 - i) * 8)) & 0xFF)
    return 8


@always_inline
def varint_encode_at(mut buf: List[UInt8], pos: Int, value: UInt64) -> Int:
    """Write a QUIC varint (RFC 9000 section 16) at `pos`. Returns 1, 2, 4, or 8."""
    var size = varint_len(value)
    if size == 1:
        buf[pos] = UInt8(value)
    elif size == 2:
        var v = UInt16(value) | UInt16(0x4000)
        buf[pos] = UInt8((v >> 8) & 0xFF)
        buf[pos + 1] = UInt8(v & 0xFF)
    elif size == 4:
        var v = UInt32(value) | UInt32(0x80000000)
        buf[pos] = UInt8((v >> 24) & 0xFF)
        buf[pos + 1] = UInt8((v >> 16) & 0xFF)
        buf[pos + 2] = UInt8((v >> 8) & 0xFF)
        buf[pos + 3] = UInt8(v & 0xFF)
    else:
        var v = value | UInt64(0xC000000000000000)
        for i in range(8):
            buf[pos + i] = UInt8((v >> UInt64((7 - i) * 8)) & 0xFF)
    return size


@always_inline
def hpack_encode_int_at(mut buf: List[Byte], pos: Int, value: Int, prefix_bits: Int) -> Int:
    """Write an HPACK/QPACK prefix integer (RFC 7541 S5.1) at `pos`.

    The high bits of buf[pos] are preserved; the low `prefix_bits` are OR'd in.
    Returns total bytes written. Caller must ensure buf is pre-sized.
    """
    var max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        buf[pos] = buf[pos] | Byte(value)
        return 1
    buf[pos] = buf[pos] | Byte(max_prefix)
    var remaining = value - max_prefix
    var written = 1
    while remaining >= 128:
        buf[pos + written] = Byte((remaining & 0x7F) | 0x80)
        remaining >>= 7
        written += 1
    buf[pos + written] = Byte(remaining)
    return written + 1


@always_inline
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
