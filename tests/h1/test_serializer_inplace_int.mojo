# tests/h1/test_serializer_inplace_int.mojo
#
# params-int-render (§7): _append_decimal / _append_hex_lower emit ASCII
# decimal / lowercase-hex in place (MSD first, no leading zeros, "0" for 0),
# differential vs reference renderers over a boundary set + >=1000 randoms.
# Covers edges inplace-int-zero / -single-digit / -multi-digit / -max.

from std.random import random_ui64, seed
from navette.h1.serializer import _append_decimal, _append_hex_lower
from tests._test_util import assert_equal_str


def _buf_to_str(data: List[UInt8]) -> String:
    var s = String()
    for i in range(len(data)):
        s += chr(Int(data[i]))
    return s^


def _ref_decimal(value: Int) -> String:
    if value == 0:
        return String("0")
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        digits.append(UInt8(v % 10 + 48))
        v //= 10
    var result = String()
    var i = len(digits) - 1
    while i >= 0:
        result += chr(Int(digits[i]))
        i -= 1
    return result^


def _check_decimal(value: Int) raises:
    var buf = List[UInt8]()
    _append_decimal(buf, value)
    assert_equal_str(_buf_to_str(buf), _ref_decimal(value), "decimal " + String(value))


def test_append_decimal_property() raises:
    # Boundary set: inplace-int-zero / -single / -multi / -max.
    for v in [0, 1, 9, 10, 99, 100, 999, 9223372036854775807]:
        _check_decimal(v)
    # Bytes before `start` are untouched (append into a non-empty buffer).
    var pre = List[UInt8]()
    pre.append(UInt8(65))  # 'A'
    _append_decimal(pre, 4096)
    assert_equal_str(_buf_to_str(pre), String("A4096"), "decimal prefix preserved")
    # >= 1000 randomized values in [0, Int.MAX].
    seed(0xC0FFEE)
    for _ in range(1000):
        _check_decimal(Int(random_ui64(0, UInt64(9223372036854775807))))


def _ref_hex(value: Int) -> String:
    if value == 0:
        return String("0")
    var hex_chars = String("0123456789abcdef")
    var hb = hex_chars.as_bytes()
    var digits = List[UInt8]()
    var v = value
    while v > 0:
        digits.append(hb[v & 0xF])
        v >>= 4
    var result = String()
    var i = len(digits) - 1
    while i >= 0:
        result += chr(Int(digits[i]))
        i -= 1
    return result^


def _check_hex(value: Int) raises:
    var buf = List[UInt8]()
    _append_hex_lower(buf, value)
    assert_equal_str(_buf_to_str(buf), _ref_hex(value), "hex " + String(value))


def test_append_hex_property() raises:
    for v in [0, 1, 9, 10, 99, 100, 999, 9223372036854775807]:
        _check_hex(v)
    seed(0xBEEF)
    for _ in range(1000):
        _check_hex(Int(random_ui64(0, UInt64(9223372036854775807))))


def main() raises:
    test_append_decimal_property()
    test_append_hex_property()
    print("test_serializer_inplace_int: decimal+hex property PASS")
