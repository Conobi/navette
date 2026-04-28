from src.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from bench.h3_server import _is_long_header_initial


def test_varint_roundtrip() raises:
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
        var w = ByteWriter()
        varint_encode(w, v)
        var encoded = w.finish()
        var expected_len = varint_len(v)
        if len(encoded) != expected_len:
            raise "varint_len mismatch for " + String(v) + ": got " + String(len(encoded)) + " expected " + String(expected_len)
        var r = ByteReader(Span(encoded))
        var decoded = varint_decode(r)
        if decoded != v:
            raise "varint roundtrip failed for " + String(v) + ": got " + String(decoded)
        if r.remaining() != 0:
            raise "varint did not consume all bytes for " + String(v)
    print("  varint_roundtrip: PASS (" + String(len(values)) + " values)")


def test_varint_lengths() raises:
    if varint_len(UInt64(0)) != 1: raise "varint_len(0) != 1"
    if varint_len(UInt64(63)) != 1: raise "varint_len(63) != 1"
    if varint_len(UInt64(64)) != 2: raise "varint_len(64) != 2"
    if varint_len(UInt64(16383)) != 2: raise "varint_len(16383) != 2"
    if varint_len(UInt64(16384)) != 4: raise "varint_len(16384) != 4"
    if varint_len(UInt64(1073741823)) != 4: raise "varint_len(1073741823) != 4"
    if varint_len(UInt64(1073741824)) != 8: raise "varint_len(1073741824) != 8"
    print("  varint_lengths: PASS")


def test_varint_overflow() raises:
    var w = ByteWriter()
    var caught = False
    try:
        varint_encode(w, UInt64(4611686018427387904))
    except:
        caught = True
    if not caught:
        raise "varint_encode should raise for value >= 2^62"
    print("  varint_overflow: PASS")


def test_varint_truncation() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x40))
    var r = ByteReader(Span(data))
    var caught = False
    try:
        _ = varint_decode(r)
    except:
        caught = True
    if not caught:
        raise "varint_decode should raise on truncated 2-byte varint"
    print("  varint_truncation: PASS")


def test_byte_reader_writer_roundtrip() raises:
    var w = ByteWriter()
    w.write_u8(UInt8(0xAB))
    w.write_u16_be(UInt16(0x1234))
    w.write_u32_be(UInt32(0xDEADBEEF))
    w.write_u64_be(UInt64(0x0102030405060708))
    var data = w.finish()
    var r = ByteReader(Span(data))
    if r.read_u8() != UInt8(0xAB): raise "u8 mismatch"
    if r.read_u16_be() != UInt16(0x1234): raise "u16 mismatch"
    if r.read_u32_be() != UInt32(0xDEADBEEF): raise "u32 mismatch"
    if r.read_u64_be() != UInt64(0x0102030405060708): raise "u64 mismatch"
    if r.remaining() != 0: raise "reader should be exhausted"
    print("  byte_reader_writer_roundtrip: PASS")


def test_byte_reader_underflow() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x01))
    var r = ByteReader(Span(data))
    _ = r.read_u8()
    var caught = False
    try:
        _ = r.read_u8()
    except:
        caught = True
    if not caught:
        raise "ByteReader should raise on underflow"
    print("  byte_reader_underflow: PASS")


def test_byte_writer_bytes() raises:
    var w = ByteWriter()
    var src = List[UInt8]()
    src.append(UInt8(1))
    src.append(UInt8(2))
    src.append(UInt8(3))
    w.write_bytes(Span(src))
    var out = w.finish()
    if len(out) != 3 or out[0] != UInt8(1) or out[1] != UInt8(2) or out[2] != UInt8(3):
        raise "write_bytes mismatch"
    print("  byte_writer_bytes: PASS")


def test_is_long_header_initial_5_cases() raises:
    # Helper: build a 1-byte payload from a single hex value.
    fn one_byte(b: UInt8) -> List[UInt8]:
        var out = List[UInt8]()
        out.append(b)
        return out^

    # Initial: 1100_0000 (long bit + type 00).
    var initial = one_byte(UInt8(0xC0))
    if not _is_long_header_initial(Span(initial)):
        raise "expected Initial to be long-header-Initial"
    # 0-RTT: 1101_0000.
    var zerort = one_byte(UInt8(0xD0))
    if _is_long_header_initial(Span(zerort)):
        raise "expected 0-RTT to be NOT long-header-Initial"
    # Handshake: 1110_0000.
    var hs = one_byte(UInt8(0xE0))
    if _is_long_header_initial(Span(hs)):
        raise "expected Handshake to be NOT long-header-Initial"
    # Retry: 1111_0000.
    var retry = one_byte(UInt8(0xF0))
    if _is_long_header_initial(Span(retry)):
        raise "expected Retry to be NOT long-header-Initial"
    # Short-header: 0100_0000 (high bit clear).
    var shrt = one_byte(UInt8(0x40))
    if _is_long_header_initial(Span(shrt)):
        raise "expected short-header to be NOT long-header-Initial"
    # Empty payload: defensive case.
    var empty = List[UInt8]()
    if _is_long_header_initial(Span(empty)):
        raise "expected empty payload to be NOT long-header-Initial"
    print("PASS: test_is_long_header_initial_5_cases")


def main() raises:
    print("test_quic_codec:")
    test_varint_roundtrip()
    test_varint_lengths()
    test_varint_overflow()
    test_varint_truncation()
    test_byte_reader_writer_roundtrip()
    test_byte_reader_underflow()
    test_byte_writer_bytes()
    test_is_long_header_initial_5_cases()
    print("All test_quic_codec tests passed.")
