# tests/h3/test_h3_qpack_int_bounds.mojo
#
# Hostile QPACK prefix-integer inputs (RFC 9204 Section 4.1.1): values
# are capped at 62 bits, overlong / wrapping encodings and reads past the
# buffer must raise, and a decoded length can never reach an allocation
# unchecked.

from navette.h3.qpack import qpack_decode_int, QpackDecoder
from tests._test_util import assert_true, assert_equal_int

comptime _MAX62: UInt64 = (UInt64(1) << 62) - 1


def _encode_int(first: UInt8, prefix_bits: Int, value: UInt64) -> List[Byte]:
    """RFC 7541 Section 5.1 encoder; `first` carries the non-prefix flag bits."""
    var out = List[Byte]()
    var max_first = UInt64((1 << prefix_bits) - 1)
    if value < max_first:
        out.append(first | UInt8(value))
        return out^
    out.append(first | UInt8(max_first))
    var rest = value - max_first
    while rest >= 128:
        out.append(UInt8((rest & 0x7F) | 0x80))
        rest >>= 7
    out.append(UInt8(rest))
    return out^


def _int_raises(data: List[Byte], offset: Int, prefix_bits: UInt8) -> Bool:
    try:
        _ = qpack_decode_int(data, offset, prefix_bits)
    except:
        return True
    return False


def _decode_raises(data: List[Byte]) -> Bool:
    try:
        var dec = QpackDecoder()
        _ = dec.decode(data)
    except:
        return True
    return False


def test_too_many_continuation_bytes() raises:
    # 0xFF then 11 zero-valued continuation bytes: overlong, value 255.
    var data: List[Byte] = [0xFF]
    for _ in range(11):
        data.append(0x80)
    data.append(0x00)
    assert_true(_int_raises(data, 0, 8), "11+ continuation bytes must raise")
    var long: List[Byte] = [0xFF]
    for _ in range(40):
        long.append(0x80)
    long.append(0x00)
    assert_true(_int_raises(long, 0, 8), "40 continuation bytes must raise")
    print("  test_too_many_continuation_bytes: PASS")


def test_wrapping_value_raises() raises:
    # 255 + (2^63 - 1) + 2^63 wraps UInt64 to 254 without a bound.
    var data: List[Byte] = [0xFF]
    for _ in range(9):
        data.append(0xFF)
    data.append(0x01)
    assert_true(_int_raises(data, 0, 8), "value past 2^64 must raise")
    print("  test_wrapping_value_raises: PASS")


def test_62_bit_boundary() raises:
    var ok = _encode_int(0, 8, _MAX62)
    var r = qpack_decode_int(ok, 0, 8)
    assert_true(r[0] == _MAX62, "2^62-1 decodes")
    assert_equal_int(r[1], len(ok), "offset past the integer")
    var over = _encode_int(0, 8, _MAX62 + 1)
    assert_true(_int_raises(over, 0, 8), "2^62 must raise")
    var over7 = _encode_int(0, 7, UInt64(1) << 63)
    assert_true(_int_raises(over7, 0, 7), "2^63 must raise")
    print("  test_62_bit_boundary: PASS")


def test_truncated_and_empty() raises:
    var empty = List[Byte]()
    assert_true(_int_raises(empty, 0, 8), "empty data must raise")
    var one: List[Byte] = [0x05]
    assert_true(_int_raises(one, 1, 8), "offset == len must raise")
    assert_true(_int_raises(one, 7, 8), "offset past len must raise")
    var cut: List[Byte] = [0xFF, 0x80]
    assert_true(_int_raises(cut, 0, 8), "missing final byte must raise")
    print("  test_truncated_and_empty: PASS")


def test_decoder_huge_value_length() raises:
    # Literal with static name ref (idx 1 = :path) and a value length of
    # 2^62-1: must raise before any allocation sized by it.
    var data: List[Byte] = [0x00, 0x00, 0x51]
    data.extend(_encode_int(0, 7, _MAX62))
    data.append(0x41)
    assert_true(_decode_raises(data), "2^62-1 value length must raise")
    # Length that would be negative as Int (> 2^63).
    var neg: List[Byte] = [0x00, 0x00, 0x51, 0x7F]
    for _ in range(8):
        neg.append(0xFF)
    neg.append(0x7F)
    assert_true(_decode_raises(neg), "value length > 2^63 must raise")
    print("  test_decoder_huge_value_length: PASS")


def test_decoder_huge_name_length() raises:
    # Literal without name ref, 3-bit name-length prefix, length > 2^63.
    var neg: List[Byte] = [0x00, 0x00, 0x27]
    for _ in range(8):
        neg.append(0xFF)
    neg.append(0x7F)
    assert_true(_decode_raises(neg), "name length > 2^63 must raise")
    var big: List[Byte] = [0x00, 0x00]
    big.extend(_encode_int(0x20, 3, _MAX62))
    assert_true(_decode_raises(big), "2^62-1 name length must raise")
    print("  test_decoder_huge_name_length: PASS")


def test_decoder_huge_index() raises:
    var data: List[Byte] = [0x00, 0x00]
    data.extend(_encode_int(0xC0, 6, _MAX62))
    assert_true(_decode_raises(data), "huge static index must raise")
    print("  test_decoder_huge_index: PASS")


def main() raises:
    print("test_h3_qpack_int_bounds:")
    test_too_many_continuation_bytes()
    test_wrapping_value_raises()
    test_62_bit_boundary()
    test_decoder_huge_value_length()
    test_decoder_huge_name_length()
    test_decoder_huge_index()
    test_truncated_and_empty()
    print("All test_h3_qpack_int_bounds tests passed.")
