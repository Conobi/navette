# tests/h1/test_parser_bytes_to_string.mojo
#
# params-fuzz-non-ascii (§7) + bytes-to-string-empty/-single/-non-ascii (§5):
# _bytes_to_string is byte-identical to the per-byte chr() reference for ALL
# inputs (ASCII via the fast path, 0x80-0xFF via the chr() fallback), so an
# invalid-UTF-8 String is never constructed. Also asserts the parser rejects
# the same requests as before the optimization.

from std.memory import Span
from std.random import random_ui64, seed
from navette.h1.parser import _bytes_to_string
from navette.h1.connection import H1Connection
from navette.h1 import ParseConfig
from tests._test_util import assert_true, assert_equal_int


def _ref_chr(data: List[UInt8], start: Int, end: Int) -> String:
    var result = String()
    var i = start
    while i < end:
        result += chr(Int(data[i]))
        i += 1
    return result^


def _str_to_bytes(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var r = List[UInt8]()
    for i in range(len(b)):
        r.append(b[i])
    return r^


def _assert_str_bytes_eq(got: String, exp: String, msg: String) raises:
    var gb = got.as_bytes()
    var eb = exp.as_bytes()
    if len(gb) != len(eb):
        print("BTS DIVERGENCE [" + msg + "] byte_length " + String(len(gb)) + " vs " + String(len(eb)))
        raise "bytes_to_string divergence: " + msg
    for i in range(len(gb)):
        if gb[i] != eb[i]:
            print("BTS DIVERGENCE [" + msg + "] byte " + String(i))
            raise "bytes_to_string divergence: " + msg


def _check_range(data: List[UInt8], start: Int, end: Int, msg: String) raises:
    var got = _bytes_to_string(data, start, end)
    var exp = _ref_chr(data, start, end)
    _assert_str_bytes_eq(got, exp, msg)


def test_bytes_to_string_full_byte_corpus() raises:
    # Every single byte 0x00..0xFF as a one-byte range (bytes-to-string-single),
    # incl. the boundary 0x7F (ASCII, fast path) and 0x80 (first non-ASCII,
    # fallback). A high byte expands to 2 UTF-8 bytes via chr(); fast-path bulk
    # copy would emit 1 raw byte, so equality to the chr() reference proves the
    # fallback was taken (unsafe_from_utf8 never sees >= 0x80).
    var d = List[UInt8]()
    for b in range(256):
        d.append(UInt8(b))
    for b in range(256):
        _check_range(d, b, b + 1, "single-0x" + String(b))
    # Whole-range ASCII (fast path) and mixed (fallback).
    _check_range(d, 0x20, 0x7F, "ascii-range")
    _check_range(d, 0x70, 0x90, "mixed-range")
    # bytes-to-string-empty: start == end and start > end.
    assert_equal_int(_bytes_to_string(d, 5, 5).byte_length(), 0, "empty start==end")
    assert_equal_int(_bytes_to_string(d, 9, 4).byte_length(), 0, "empty start>end")


def test_bytes_to_string_random_high_byte_injection() raises:
    # >= 500 randomized header-value-like buffers with 1-8 high bytes at random
    # offsets; assert byte-identity to chr() and (implicitly) no UB under
    # ASSERT=all.
    seed(0xA5A5)
    for _ in range(500):
        var n = Int(random_ui64(8, 64))
        var d = List[UInt8]()
        for _2 in range(n):
            d.append(UInt8(random_ui64(0x20, 0x7E)))  # printable ASCII base
        var inj_count = Int(random_ui64(1, 8))
        for _3 in range(inj_count):
            var off = Int(random_ui64(0, UInt64(n - 1)))
            d[off] = UInt8(random_ui64(0x80, 0xFF))   # inject a high byte
        _check_range(d, 0, len(d), "rand-inject")


def test_parser_rejection_unchanged() raises:
    # Point (4): a non-ASCII byte in the request target is still rejected (the
    # _bytes_to_string change does not touch target validation); a high byte in
    # a header value is still accepted and decoded via the fallback.
    var conn = H1Connection(ParseConfig())
    # 0x80 in the target -> parse error (PHASE_ERROR -> next_request None).
    var bad = _str_to_bytes("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
    bad[5] = UInt8(0x80)  # corrupt the target byte after "GET /"
    conn.receive_data(Span(bad))
    var r = conn.next_request()
    assert_true(not r.__bool__(), "non-ascii target must be rejected")

    # 0x80 in a header value -> accepted (obs-text permitted today).
    var conn2 = H1Connection(ParseConfig())
    var ok = _str_to_bytes("GET / HTTP/1.1\r\nHost: x\r\nX-V: ab\r\n\r\n")
    ok[len(ok) - 5] = UInt8(0x80)  # corrupt the 'b' in the X-V value
    conn2.receive_data(Span(ok))
    var r2 = conn2.next_request()
    assert_true(r2.__bool__(), "high-byte header value must be accepted")


def main() raises:
    test_bytes_to_string_full_byte_corpus()
    test_bytes_to_string_random_high_byte_injection()
    test_parser_rejection_unchanged()
    print("test_parser_bytes_to_string: all tests passed")
