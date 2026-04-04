# conformance/tests/test_cursor.mojo
from lib.cursor import ByteWriter, ByteReader
from lib.test_util import assert_true, assert_equal


def test_write_read_u8() raises:
    var w = ByteWriter(capacity=16)
    w.write_u8(0x42)
    w.write_u8(0xFF)
    assert_equal(w.position, 2, "position should be 2")

    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u8()), 0x42, "first byte")
    assert_equal(Int(r.read_u8()), 0xFF, "second byte")
    assert_equal(r.remaining(), 0, "nothing left")


def test_write_read_u16_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u16_be(0x1234)
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u16_be()), 0x1234, "u16 round-trip")


def test_write_read_u32_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u32_be(0xDEADBEEF)
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u32_be()), 0xDEADBEEF, "u32 round-trip")


def test_write_read_u64_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u64_be(0x0102030405060708)
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u64_be()), 0x0102030405060708, "u64 round-trip")


def test_write_bytes() raises:
    var w = ByteWriter(capacity=16)
    var data = List[UInt8]()
    data.append(0xAA)
    data.append(0xBB)
    data.append(0xCC)
    w.write_bytes(data)
    assert_equal(w.position, 3, "wrote 3 bytes")
    var r = ByteReader(w.finish())
    var out = r.read_bytes(3)
    assert_equal(len(out), 3, "read 3 bytes")
    assert_equal(Int(out[0]), 0xAA, "byte 0")
    assert_equal(Int(out[1]), 0xBB, "byte 1")
    assert_equal(Int(out[2]), 0xCC, "byte 2")


def test_reader_underflow_u8() raises:
    var data = List[UInt8]()
    data.append(0x01)
    var r = ByteReader(data)
    _ = r.read_u8()
    var raised = False
    try:
        _ = r.read_u8()
    except:
        raised = True
    assert_true(raised, "u8 underflow should raise")


def test_reader_underflow_u16() raises:
    var data = List[UInt8]()
    data.append(0x01)
    var r = ByteReader(data)
    var raised = False
    try:
        _ = r.read_u16_be()
    except:
        raised = True
    assert_true(raised, "u16 underflow should raise (1 byte available, need 2)")


def test_reader_underflow_u32() raises:
    var data = List[UInt8]()
    data.append(0x01)
    data.append(0x02)
    var r = ByteReader(data)
    var raised = False
    try:
        _ = r.read_u32_be()
    except:
        raised = True
    assert_true(raised, "u32 underflow should raise (2 bytes available, need 4)")


def test_reader_underflow_u64() raises:
    var data = List[UInt8]()
    for i in range(7):
        data.append(UInt8(i))
    var r = ByteReader(data)
    var raised = False
    try:
        _ = r.read_u64_be()
    except:
        raised = True
    assert_true(raised, "u64 underflow should raise (7 bytes available, need 8)")


def test_reader_underflow_bytes() raises:
    var data = List[UInt8]()
    data.append(0x01)
    var r = ByteReader(data)
    var raised = False
    try:
        _ = r.read_bytes(5)
    except:
        raised = True
    assert_true(raised, "read_bytes underflow should raise (1 available, need 5)")


def test_u64_high_bit_set() raises:
    """Test u64 with high bits set — catches Int(UInt64) truncation bugs."""
    # 0xFFFFFFFFFFFFFFFF — all bits set
    var w1 = ByteWriter(capacity=8)
    w1.write_u64_be(0xFFFFFFFFFFFFFFFF)
    var b1 = w1.finish()
    assert_equal(len(b1), 8, "u64_max should be 8 bytes")
    for i in range(8):
        assert_equal(Int(b1[i]), 0xFF, "u64_max byte " + String(i))

    # 0xC000000000000000 — bits 62-63 set (used by 8-byte varint prefix)
    var w2 = ByteWriter(capacity=8)
    w2.write_u64_be(0xC000000000000000)
    var b2 = w2.finish()
    assert_equal(Int(b2[0]), 0xC0, "varint_prefix byte 0")
    for i in range(1, 8):
        assert_equal(Int(b2[i]), 0x00, "varint_prefix byte " + String(i))

    # 0x8000000000000000 — bit 63 only
    var w3 = ByteWriter(capacity=8)
    w3.write_u64_be(0x8000000000000000)
    var b3 = w3.finish()
    assert_equal(Int(b3[0]), 0x80, "bit63 byte 0")
    for i in range(1, 8):
        assert_equal(Int(b3[i]), 0x00, "bit63 byte " + String(i))

    # Round-trip all three
    var r1 = ByteReader(w1.finish())
    assert_true(r1.read_u64_be() == 0xFFFFFFFFFFFFFFFF, "u64_max round-trip")

    var r2 = ByteReader(w2.finish())
    assert_true(r2.read_u64_be() == 0xC000000000000000, "varint_prefix round-trip")

    var r3 = ByteReader(w3.finish())
    assert_true(r3.read_u64_be() == 0x8000000000000000, "bit63 round-trip")


def test_u16_boundary() raises:
    var w = ByteWriter(capacity=4)
    w.write_u16_be(0x0000)
    w.write_u16_be(0xFFFF)
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u16_be()), 0x0000, "u16 zero")
    assert_equal(Int(r.read_u16_be()), 0xFFFF, "u16 max")


def test_u32_boundary() raises:
    var w = ByteWriter(capacity=8)
    w.write_u32_be(0x00000000)
    w.write_u32_be(0xFFFFFFFF)
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u32_be()), 0x00000000, "u32 zero")
    assert_equal(Int(r.read_u32_be()), 0xFFFFFFFF, "u32 max")


def test_interleaved_types() raises:
    """Write/read multiple types interleaved to test position tracking."""
    var w = ByteWriter(capacity=32)
    w.write_u8(0xAA)
    w.write_u32_be(0x12345678)
    w.write_u16_be(0xBEEF)
    w.write_u8(0x01)
    w.write_u64_be(0xDEADCAFEBABEF00D)
    assert_equal(w.position, 1 + 4 + 2 + 1 + 8, "total position after interleaved writes")

    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u8()), 0xAA, "interleaved u8")
    assert_equal(Int(r.read_u32_be()), 0x12345678, "interleaved u32")
    assert_equal(Int(r.read_u16_be()), 0xBEEF, "interleaved u16")
    assert_equal(Int(r.read_u8()), 0x01, "interleaved u8 #2")
    assert_equal(r.remaining(), 8, "8 bytes remaining before u64")
    assert_true(r.read_u64_be() == 0xDEADCAFEBABEF00D, "interleaved u64")
    assert_equal(r.remaining(), 0, "nothing left after interleaved")


def test_empty_write_bytes() raises:
    var w = ByteWriter(capacity=4)
    w.write_u8(0xFF)
    w.write_bytes(List[UInt8]())
    assert_equal(w.position, 1, "position unchanged after empty write_bytes")
    var r = ByteReader(w.finish())
    assert_equal(Int(r.read_u8()), 0xFF, "byte survives empty write_bytes")
    assert_equal(r.remaining(), 0, "nothing else")


def main() raises:
    # Verify assertions are working (guard against silent no-op)
    var _sentinel_ok = False
    try:
        assert_true(False, "sentinel")
    except:
        _sentinel_ok = True
    assert_true(_sentinel_ok, "assertions are not firing — test infrastructure is broken")

    test_write_read_u8()
    test_write_read_u16_be()
    test_write_read_u32_be()
    test_write_read_u64_be()
    test_write_bytes()
    test_reader_underflow_u8()
    test_reader_underflow_u16()
    test_reader_underflow_u32()
    test_reader_underflow_u64()
    test_reader_underflow_bytes()
    test_u64_high_bit_set()
    test_u16_boundary()
    test_u32_boundary()
    test_interleaved_types()
    test_empty_write_bytes()
    print("test_cursor: all 15 tests passed")
