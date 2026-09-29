"""Secure random fill: real getrandom draws, plus failure paths through injected fakes."""


from navette.util.secure_random import _GetrandomFn, fill_random, _fill_random_with
from tests._test_util import assert_true

comptime _EINTR = 4
comptime _EAGAIN = 11
comptime _ENOSYS = 38


def _all(buf: InlineArray[UInt8, 64], v: UInt8) -> Bool:
    for i in range(64):
        if buf[i] != v:
            return False
    return True


def _short_reads(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    """Writes at most 3 bytes per call, like a getrandom interrupted mid-copy."""
    var k = min(n, 3)
    for i in range(k):
        p[unsafe_offset=i] = 0xAB
    return k


def _eintr_then_fill(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    """First call on a zeroed buffer reports EINTR (marking byte 0); the next fills."""
    if p[unsafe_offset=0] == 0:
        p[unsafe_offset=0] = 1
        return -_EINTR
    for i in range(n):
        p[unsafe_offset=i] = 0xAB
    return n


def _enosys(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    return -_ENOSYS


def _eagain(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    return -_EAGAIN


def _zero_bytes(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    return 0


def _over_report(p: Pointer[UInt8, MutAnyOrigin], n: Int) -> Int:
    """Fills the request but claims more bytes than it was asked for."""
    for i in range(n):
        p[unsafe_offset=i] = 0xAB
    return n + 5


def test_real_draws_fill_and_differ() raises:
    var a = InlineArray[UInt8, 64](fill=UInt8(0))
    var b = InlineArray[UInt8, 64](fill=UInt8(0))
    fill_random(Span(a))
    fill_random(Span(b))
    assert_true(not _all(a, 0), "a draw is not all zero")
    var same = True
    for i in range(64):
        if a[i] != b[i]:
            same = False
    assert_true(not same, "two draws differ")
    print("PASS: test_real_draws_fill_and_differ")


def test_short_reads_fill_every_byte() raises:
    var buf = InlineArray[UInt8, 64](fill=UInt8(0))
    _fill_random_with[_short_reads](Span(buf))
    assert_true(_all(buf, 0xAB), "short reads are retried until every byte is filled")
    print("PASS: test_short_reads_fill_every_byte")


def test_eintr_is_retried() raises:
    var buf = InlineArray[UInt8, 64](fill=UInt8(0))
    _fill_random_with[_eintr_then_fill](Span(buf))
    assert_true(_all(buf, 0xAB), "EINTR is retried")
    print("PASS: test_eintr_is_retried")


def _expect_raise[f: _GetrandomFn](name: String) raises:
    var buf = InlineArray[UInt8, 64](fill=UInt8(0))
    var raised = False
    try:
        _fill_random_with[f](Span(buf))
    except:
        raised = True
    assert_true(raised, name + " raises instead of leaving the buffer unfilled")


def test_failures_raise() raises:
    _expect_raise[_enosys]("ENOSYS")
    _expect_raise[_eagain]("EAGAIN")
    _expect_raise[_zero_bytes]("a zero-byte read")
    _expect_raise[_over_report]("a source reporting more bytes than requested")
    print("PASS: test_failures_raise")


def main() raises:
    test_real_draws_fill_and_differ()
    test_short_reads_fill_every_byte()
    test_eintr_is_retried()
    test_failures_raise()
