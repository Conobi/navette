from navette.quic.codec import (
    write_u8_at, write_u16_be_at, write_u24_be_at,
    write_u32_be_at, write_u64_be_at, varint_encode_at, varint_len,
    hpack_encode_int_at,
)


def _zeroed(n: Int) -> List[Byte]:
    """Return an n-byte list initialised to zero."""
    var buf = List[Byte]()
    buf.resize(n, Byte(0))
    return buf^


def test_write_u8_at() raises:
    var buf = _zeroed(3)
    var n = write_u8_at(buf, 1, UInt8(0xAB))
    if n != 1: raise "write_u8_at should return 1"
    if buf[0] != UInt8(0): raise "should not touch buf[0]"
    if buf[1] != UInt8(0xAB): raise "buf[1] should be 0xAB"
    if buf[2] != UInt8(0): raise "should not touch buf[2]"
    print("  write_u8_at: PASS")


def test_write_u16_be_at() raises:
    var buf = _zeroed(4)
    var n = write_u16_be_at(buf, 1, UInt16(0x1234))
    if n != 2: raise "write_u16_be_at should return 2"
    if buf[1] != UInt8(0x12): raise "high byte mismatch"
    if buf[2] != UInt8(0x34): raise "low byte mismatch"
    print("  write_u16_be_at: PASS")


def test_write_u24_be_at() raises:
    var buf = _zeroed(4)
    var n = write_u24_be_at(buf, 0, UInt32(0x010203))
    if n != 3: raise "write_u24_be_at should return 3"
    if buf[0] != UInt8(0x01) or buf[1] != UInt8(0x02) or buf[2] != UInt8(0x03):
        raise "u24 mismatch"
    print("  write_u24_be_at: PASS")


def test_write_u32_be_at() raises:
    var buf = _zeroed(5)
    var n = write_u32_be_at(buf, 1, UInt32(0xDEADBEEF))
    if n != 4: raise "write_u32_be_at should return 4"
    if buf[1] != UInt8(0xDE): raise "byte 0 mismatch"
    if buf[2] != UInt8(0xAD): raise "byte 1 mismatch"
    if buf[3] != UInt8(0xBE): raise "byte 2 mismatch"
    if buf[4] != UInt8(0xEF): raise "byte 3 mismatch"
    print("  write_u32_be_at: PASS")


def test_write_u64_be_at() raises:
    var buf = _zeroed(8)
    var n = write_u64_be_at(buf, 0, UInt64(0x0102030405060708))
    if n != 8: raise "write_u64_be_at should return 8"
    for i in range(8):
        if buf[i] != UInt8(i + 1):
            raise "u64 byte " + String(i) + " mismatch"
    print("  write_u64_be_at: PASS")


def test_varint_encode_at_1byte() raises:
    var buf = _zeroed(2)
    var n = varint_encode_at(buf, 0, UInt64(37))
    if n != 1: raise "varint 37 should be 1 byte"
    if buf[0] != UInt8(37): raise "varint 37 value mismatch"
    print("  varint_encode_at_1byte: PASS")


def test_varint_encode_at_2byte() raises:
    var buf = _zeroed(2)
    var n = varint_encode_at(buf, 0, UInt64(15293))
    if n != 2: raise "varint 15293 should be 2 bytes"
    if buf[0] != UInt8(0x7B) or buf[1] != UInt8(0xBD):
        raise "varint 15293 encoding mismatch (RFC 9000 A.1)"
    print("  varint_encode_at_2byte: PASS")


def test_varint_encode_at_4byte() raises:
    var buf = _zeroed(4)
    var n = varint_encode_at(buf, 0, UInt64(494878333))
    if n != 4: raise "varint 494878333 should be 4 bytes"
    if buf[0] != UInt8(0x9D) or buf[1] != UInt8(0x7F) or buf[2] != UInt8(0x3E) or buf[3] != UInt8(0x7D):
        raise "varint 494878333 encoding mismatch (RFC 9000 A.1)"
    print("  varint_encode_at_4byte: PASS")


def test_varint_encode_at_8byte() raises:
    var buf = _zeroed(8)
    var n = varint_encode_at(buf, 0, UInt64(151288809941952652))
    if n != 8: raise "varint 151288809941952652 should be 8 bytes"
    if buf[0] != UInt8(0xC2) or buf[1] != UInt8(0x19) or buf[7] != UInt8(0x8C):
        raise "varint 151288809941952652 encoding mismatch (RFC 9000 A.1)"
    print("  varint_encode_at_8byte: PASS")


def test_varint_encode_at_with_offset() raises:
    var buf = _zeroed(4)
    buf[0] = UInt8(0xFF)
    buf[3] = UInt8(0xFF)
    var n = varint_encode_at(buf, 1, UInt64(100))
    if n != 2: raise "varint 100 should be 2 bytes"
    if buf[0] != UInt8(0xFF): raise "should not touch byte before pos"
    if buf[3] != UInt8(0xFF): raise "should not touch byte after written region"
    print("  varint_encode_at_with_offset: PASS")


def test_varint_roundtrip_via_at() raises:
    from navette.quic.codec import ByteReader, varint_decode
    var values = List[UInt64]()
    values.append(UInt64(0))
    values.append(UInt64(63))
    values.append(UInt64(64))
    values.append(UInt64(16383))
    values.append(UInt64(16384))
    values.append(UInt64(1073741823))
    values.append(UInt64(1073741824))
    values.append(UInt64(4611686018427387903))
    for i in range(len(values)):
        var v = values[i]
        var size = varint_len(v)
        var buf = List[Byte]()
        buf.resize(size, Byte(0))
        var n = varint_encode_at(buf, 0, v)
        if n != size:
            raise "varint_encode_at returned " + String(n) + " for " + String(v) + ", expected " + String(size)
        var r = ByteReader(Span(buf))
        var decoded = varint_decode(r)
        if decoded != v:
            raise "roundtrip failed for " + String(v) + ": got " + String(decoded)
    print("  varint_roundtrip_via_at: PASS (8 values)")


def test_hpack_encode_int_at_small() raises:
    """Value fits in prefix -- single byte, OR'd into existing high bits."""
    var buf = _zeroed(2)
    buf[0] = UInt8(0x80)
    var n = hpack_encode_int_at(buf, 0, 10, 7)
    if n != 1: raise "small value should be 1 byte"
    if buf[0] != UInt8(0x8A): raise "should OR 10 into low 7 bits of 0x80 = 0x8A, got " + String(Int(buf[0]))
    print("  hpack_encode_int_at_small: PASS")


def test_hpack_encode_int_at_multibyte() raises:
    """Value exceeds prefix -- continuation bytes (RFC 7541 S5.1: 1337 with 5-bit prefix)."""
    var buf = _zeroed(4)
    var n = hpack_encode_int_at(buf, 0, 1337, 5)
    if n != 3: raise "1337 with 5-bit prefix should be 3 bytes, got " + String(n)
    if buf[0] != UInt8(0x1F): raise "first byte mismatch"
    if buf[1] != UInt8(0x9A): raise "second byte mismatch"
    if buf[2] != UInt8(0x0A): raise "third byte mismatch"
    print("  hpack_encode_int_at_multibyte: PASS")


def test_hpack_encode_int_at_preserves_opcode() raises:
    """High bits of buf[pos] are preserved -- only low prefix_bits are written."""
    var buf = _zeroed(4)
    buf[0] = UInt8(0x40)
    _ = hpack_encode_int_at(buf, 0, 1337, 6)
    if (buf[0] & UInt8(0xC0)) != UInt8(0x40):
        raise "high bits should be preserved"
    print("  hpack_encode_int_at_preserves_opcode: PASS")


def main() raises:
    print("test_encoding_primitives:")
    test_write_u8_at()
    test_write_u16_be_at()
    test_write_u24_be_at()
    test_write_u32_be_at()
    test_write_u64_be_at()
    test_varint_encode_at_1byte()
    test_varint_encode_at_2byte()
    test_varint_encode_at_4byte()
    test_varint_encode_at_8byte()
    test_varint_encode_at_with_offset()
    test_varint_roundtrip_via_at()
    test_hpack_encode_int_at_small()
    test_hpack_encode_int_at_multibyte()
    test_hpack_encode_int_at_preserves_opcode()
    print("All test_encoding_primitives tests passed.")
