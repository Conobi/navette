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


def test_reader_underflow() raises:
    var data = List[UInt8]()
    data.append(0x01)
    var r = ByteReader(data)
    _ = r.read_u8()  # consume the one byte
    var raised = False
    try:
        _ = r.read_u8()
    except:
        raised = True
    assert_true(raised, "should raise on underflow")


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
    test_reader_underflow()
    print("test_cursor: all passed")
