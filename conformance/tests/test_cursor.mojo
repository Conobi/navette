# conformance/tests/test_cursor.mojo
from lib.cursor import ByteWriter, ByteReader


def test_write_read_u8() raises:
    var w = ByteWriter(capacity=16)
    w.write_u8(0x42)
    w.write_u8(0xFF)
    debug_assert(w.position == 2, "position should be 2")

    var r = ByteReader(w.finish())
    debug_assert(r.read_u8() == 0x42, "first byte")
    debug_assert(r.read_u8() == 0xFF, "second byte")
    debug_assert(r.remaining() == 0, "nothing left")


def test_write_read_u16_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u16_be(0x1234)
    var r = ByteReader(w.finish())
    debug_assert(r.read_u16_be() == 0x1234, "u16 round-trip")


def test_write_read_u32_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u32_be(0xDEADBEEF)
    var r = ByteReader(w.finish())
    debug_assert(r.read_u32_be() == 0xDEADBEEF, "u32 round-trip")


def test_write_read_u64_be() raises:
    var w = ByteWriter(capacity=16)
    w.write_u64_be(0x0102030405060708)
    var r = ByteReader(w.finish())
    debug_assert(r.read_u64_be() == 0x0102030405060708, "u64 round-trip")


def test_write_bytes() raises:
    var w = ByteWriter(capacity=16)
    var data = List[UInt8]()
    data.append(0xAA)
    data.append(0xBB)
    data.append(0xCC)
    w.write_bytes(data)
    debug_assert(w.position == 3, "wrote 3 bytes")
    var r = ByteReader(w.finish())
    var out = r.read_bytes(3)
    debug_assert(len(out) == 3, "read 3 bytes")
    debug_assert(out[0] == 0xAA, "byte 0")
    debug_assert(out[1] == 0xBB, "byte 1")
    debug_assert(out[2] == 0xCC, "byte 2")


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
    debug_assert(raised, "should raise on underflow")


def main() raises:
    test_write_read_u8()
    test_write_read_u16_be()
    test_write_read_u32_be()
    test_write_read_u64_be()
    test_write_bytes()
    test_reader_underflow()
    print("test_cursor: all passed")
