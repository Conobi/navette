# conformance/lib/varint.mojo
from lib.cursor import ByteWriter, ByteReader


def varint_size(value: UInt64) -> Int:
    """Return the encoding length (1, 2, 4, or 8) for a QUIC varint."""
    if value <= UInt64(63):
        return 1
    if value <= UInt64(16383):
        return 2
    if value <= UInt64(1073741823):
        return 4
    return 8


def varint_encode(mut w: ByteWriter, value: UInt64) raises:
    """Encode a QUIC variable-length integer (RFC 9000 Section 16)."""
    if value > UInt64(4611686018427387903):
        raise "varint value exceeds max (2^62 - 1)"

    var size = varint_size(value)
    if size == 1:
        w.write_u8(UInt8(Int(value)))
    elif size == 2:
        w.write_u16_be(UInt16(Int(value)) | UInt16(0x4000))
    elif size == 4:
        w.write_u32_be(UInt32(Int(value)) | UInt32(0x80000000))
    else:
        w.write_u64_be(value | UInt64(0xC000000000000000))


def varint_decode(mut r: ByteReader) raises -> UInt64:
    """Decode a QUIC variable-length integer (RFC 9000 Section 16)."""
    if r.remaining() < 1:
        raise "varint: empty input"

    var first = r.read_u8()
    var prefix = Int(first) >> 6

    if prefix == 0:
        return UInt64(first & UInt8(0x3F))
    elif prefix == 1:
        if r.remaining() < 1:
            raise "varint: truncated 2-byte encoding"
        var second = r.read_u8()
        return (UInt64(first & UInt8(0x3F)) << 8) | UInt64(second)
    elif prefix == 2:
        if r.remaining() < 3:
            raise "varint: truncated 4-byte encoding"
        var b1 = r.read_u8()
        var b2 = r.read_u8()
        var b3 = r.read_u8()
        return (
            (UInt64(first & UInt8(0x3F)) << 24)
            | (UInt64(b1) << 16)
            | (UInt64(b2) << 8)
            | UInt64(b3)
        )
    else:
        if r.remaining() < 7:
            raise "varint: truncated 8-byte encoding"
        var result = UInt64(first & UInt8(0x3F))
        for _ in range(7):
            result = (result << 8) | UInt64(r.read_u8())
        return result
