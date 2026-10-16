from navette.quic.codec import ByteReader, ByteWriter, varint_encode, varint_decode, varint_len
from navette.quic.packet import is_long_header_initial, is_long_header_zero_rtt


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
    var data = List[Byte]()
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
    var data = List[Byte]()
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


def _bytes(*values: Int) -> List[Byte]:
    var out = List[Byte]()
    for v in values:
        out.append(UInt8(v))
    return out^


def _read_u8_raises[o: Origin](mut r: ByteReader[o]) -> Bool:
    try:
        _ = r.read_u8()
    except:
        return True
    return False


def _peek_u8_raises[o: Origin](r: ByteReader[o]) -> Bool:
    try:
        _ = r.peek_u8()
    except:
        return True
    return False


def _varint_raises[o: Origin](mut r: ByteReader[o]) -> Bool:
    try:
        _ = varint_decode(r)
    except:
        return True
    return False


def test_byte_reader_empty_span_raises() raises:
    var data = List[Byte]()
    var r = ByteReader(Span(data))
    if not _read_u8_raises(r): raise "read_u8 on empty span should raise"
    if not _peek_u8_raises(r): raise "peek_u8 on empty span should raise"
    if r.pos != 0: raise "failed read on empty span moved pos"
    print("  byte_reader_empty_span_raises: PASS")


def test_byte_reader_exact_end() raises:
    var data = _bytes(0x11, 0x22, 0x33)
    var r = ByteReader(Span(data))
    if r.peek_u8() != UInt8(0x11): raise "peek_u8 at 0 mismatch"
    if r.read_u8() != UInt8(0x11): raise "read_u8 at 0 mismatch"
    if r.read_u8() != UInt8(0x22): raise "read_u8 at 1 mismatch"
    if r.peek_u8() != UInt8(0x33): raise "peek_u8 at last byte mismatch"
    if r.read_u8() != UInt8(0x33): raise "read_u8 at last byte mismatch"
    if not _read_u8_raises(r): raise "read_u8 past end should raise"
    if not _peek_u8_raises(r): raise "peek_u8 at end should raise"
    if r.pos != 3: raise "failed reads at end moved pos to " + String(r.pos)
    print("  byte_reader_exact_end: PASS")


def test_byte_reader_sub_span_bound() raises:
    # The parent holds bytes past the view; a wrong guard would leak them.
    var parent = _bytes(0xA0, 0xA1, 0xEE, 0xEF)
    var r = ByteReader(Span(parent)[0:2])
    if r.read_u8() != UInt8(0xA0): raise "sub-span read 0 mismatch"
    if r.read_u8() != UInt8(0xA1): raise "sub-span read 1 mismatch"
    if not _peek_u8_raises(r): raise "peek_u8 at sub-span end read the parent's byte"
    if not _read_u8_raises(r): raise "read_u8 at sub-span end read the parent's byte"
    if r.pos != 2: raise "failed sub-span reads moved pos to " + String(r.pos)
    print("  byte_reader_sub_span_bound: PASS")


def test_byte_reader_negative_pos_raises() raises:
    # pos is public; a negative value must not index before the view.
    var parent = _bytes(0x55, 0x66, 0x77)
    var r = ByteReader(Span(parent)[1:3])
    r.pos = -1
    if not _read_u8_raises(r): raise "read_u8 at negative pos should raise"
    if not _peek_u8_raises(r): raise "peek_u8 at negative pos should raise"
    if r.pos != -1: raise "failed reads at negative pos moved pos"
    print("  byte_reader_negative_pos_raises: PASS")


def test_varint_truncated_each_prefix() raises:
    # Full encodings of 2-, 4- and 8-byte varints, each cut by one byte.
    var encodings = List[List[Byte]]()
    encodings.append(_bytes(0x40, 0x25))
    encodings.append(_bytes(0x80, 0x01, 0x02, 0x03))
    encodings.append(_bytes(0xC0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07))
    for i in range(len(encodings)):
        var full = encodings[i].copy()
        var n = len(full)
        var cut = List[Byte](full[0 : n - 1])
        var r = ByteReader(Span(cut))
        if not _varint_raises(r):
            raise "varint_decode should raise on " + String(n) + "-byte varint missing its last byte"
        # Same truncation as a view whose parent still holds the missing byte.
        var rs = ByteReader(Span(full)[0 : n - 1])
        if not _varint_raises(rs):
            raise "varint_decode read past a " + String(n) + "-byte sub-span into its parent"
        # The untruncated encoding ends exactly at the span end and decodes.
        var rf = ByteReader(Span(full))
        _ = varint_decode(rf)
        if rf.remaining() != 0:
            raise "varint_decode left bytes on an exact " + String(n) + "-byte span"
    print("  varint_truncated_each_prefix: PASS")


def test_varint_ends_at_sub_span_end() raises:
    # 2-byte varint 0x4025 = 37 filling a view, followed by parent bytes.
    var parent = _bytes(0x40, 0x25, 0xFF, 0xFF)
    var r = ByteReader(Span(parent)[0:2])
    if varint_decode(r) != UInt64(0x25): raise "varint at sub-span end mismatch"
    if r.remaining() != 0: raise "varint at sub-span end left bytes"
    if not _varint_raises(r): raise "varint_decode past sub-span end should raise"
    print("  varint_ends_at_sub_span_end: PASS")


def test_byte_writer_bytes() raises:
    var w = ByteWriter()
    var src = List[Byte]()
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
    def one_byte(b: UInt8) -> List[Byte]:
        var out = List[Byte]()
        out.append(b)
        return out^

    # Initial: 1100_0000 (long bit + type 00).
    var initial = one_byte(UInt8(0xC0))
    if not is_long_header_initial(Span(initial)):
        raise "expected Initial to be long-header-Initial"
    # 0-RTT: 1101_0000.
    var zerort = one_byte(UInt8(0xD0))
    if is_long_header_initial(Span(zerort)):
        raise "expected 0-RTT to be NOT long-header-Initial"
    # Handshake: 1110_0000.
    var hs = one_byte(UInt8(0xE0))
    if is_long_header_initial(Span(hs)):
        raise "expected Handshake to be NOT long-header-Initial"
    # Retry: 1111_0000.
    var retry = one_byte(UInt8(0xF0))
    if is_long_header_initial(Span(retry)):
        raise "expected Retry to be NOT long-header-Initial"
    # Short-header: 0100_0000 (high bit clear).
    var shrt = one_byte(UInt8(0x40))
    if is_long_header_initial(Span(shrt)):
        raise "expected short-header to be NOT long-header-Initial"
    # Empty payload: defensive case.
    var empty = List[Byte]()
    if is_long_header_initial(Span(empty)):
        raise "expected empty payload to be NOT long-header-Initial"
    print("PASS: test_is_long_header_initial_5_cases")


def test_is_long_header_zero_rtt_5_cases() raises:
    """RFC 9000 §17.2 / §17.2.3 — long-header 0-RTT first-byte detection.

    Mirrors `test_is_long_header_initial_5_cases`: enumerates the four
    long-header packet types plus the short-header form, asserting the
    helper fires iff the first byte's top bit is set AND bits 5-4 == 0b01.
    """
    def one_byte(b: UInt8) -> List[Byte]:
        var out = List[Byte]()
        out.append(b)
        return out^

    # Initial: 1100_0000 — long bit + type 0b00.
    var initial = one_byte(UInt8(0xC0))
    if is_long_header_zero_rtt(Span(initial)):
        raise "expected Initial to be NOT long-header-0RTT"
    # 0-RTT: 1101_0000 — long bit + type 0b01.
    var zerort = one_byte(UInt8(0xD0))
    if not is_long_header_zero_rtt(Span(zerort)):
        raise "expected 0-RTT to be long-header-0RTT"
    # Handshake: 1110_0000.
    var hs = one_byte(UInt8(0xE0))
    if is_long_header_zero_rtt(Span(hs)):
        raise "expected Handshake to be NOT long-header-0RTT"
    # Retry: 1111_0000.
    var retry = one_byte(UInt8(0xF0))
    if is_long_header_zero_rtt(Span(retry)):
        raise "expected Retry to be NOT long-header-0RTT"
    # Short header: 0100_0000 (high bit clear) — never 0-RTT.
    var shrt = one_byte(UInt8(0x40))
    if is_long_header_zero_rtt(Span(shrt)):
        raise "expected short-header to be NOT long-header-0RTT"
    # Empty payload: defensive — must be False.
    var empty = List[Byte]()
    if is_long_header_zero_rtt(Span(empty)):
        raise "expected empty payload to be NOT long-header-0RTT"
    # 0-RTT with reserved bits set (lower nibble varies): 1101_1111.
    # The helper inspects only the form bit (0x80) and the type field
    # (0x30); reserved bits MUST NOT alter classification.
    var zerort_rsv = one_byte(UInt8(0xDF))
    if not is_long_header_zero_rtt(Span(zerort_rsv)):
        raise "expected 0-RTT with set reserved bits to still classify as 0-RTT"
    print("PASS: test_is_long_header_zero_rtt_5_cases")


def main() raises:
    print("test_quic_codec:")
    test_varint_roundtrip()
    test_varint_lengths()
    test_varint_overflow()
    test_varint_truncation()
    test_byte_reader_writer_roundtrip()
    test_byte_reader_underflow()
    test_byte_reader_empty_span_raises()
    test_byte_reader_exact_end()
    test_byte_reader_sub_span_bound()
    test_byte_reader_negative_pos_raises()
    test_varint_truncated_each_prefix()
    test_varint_ends_at_sub_span_end()
    test_byte_writer_bytes()
    test_is_long_header_initial_5_cases()
    test_is_long_header_zero_rtt_5_cases()
    print("All test_quic_codec tests passed.")
