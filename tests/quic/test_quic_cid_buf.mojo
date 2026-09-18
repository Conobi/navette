# tests/quic/test_quic_cid_buf.mojo

from std.testing import assert_equal, assert_true, assert_false
from navette.quic.cid_buf import CidBuf


def _bytes(n: Int, start: UInt8 = UInt8(0)) -> List[Byte]:
    """Build an n-byte List[Byte] counting up from `start`."""
    var out = List[Byte](capacity=n)
    for i in range(n):
        out.append(start + UInt8(i))
    return out^


def test_empty_has_zero_len() raises:
    var buf = CidBuf.empty()
    assert_equal(len(buf), 0)
    print("PASS: test_empty_has_zero_len")


def test_from_span_round_trips() raises:
    var src = _bytes(8)
    var buf = CidBuf.from_span(Span(src))
    assert_equal(len(buf), 8)
    var view = buf.as_span()
    assert_equal(len(view), 8)
    for i in range(8):
        assert_equal(Int(view[i]), i)
    print("PASS: test_from_span_round_trips")


def test_from_span_max_length() raises:
    """20 bytes is the RFC 9000 max and must not abort."""
    var src = _bytes(20)
    var buf = CidBuf.from_span(Span(src))
    assert_equal(len(buf), 20)
    var view = buf.as_span()
    for i in range(20):
        assert_equal(Int(view[i]), i)
    print("PASS: test_from_span_max_length")


def test_from_span_empty() raises:
    var src = List[Byte]()
    var buf = CidBuf.from_span(Span(src))
    assert_equal(len(buf), 0)
    print("PASS: test_from_span_empty")


def test_equality_same_content() raises:
    var a = CidBuf.from_span(Span(_bytes(8)))
    var b = CidBuf.from_span(Span(_bytes(8)))
    assert_true(a == b, "same content should be equal")
    assert_false(a != b, "same content should not be unequal")
    print("PASS: test_equality_same_content")


def test_equality_different_content() raises:
    var a = CidBuf.from_span(Span(_bytes(8, start=UInt8(0))))
    var b = CidBuf.from_span(Span(_bytes(8, start=UInt8(1))))
    assert_false(a == b, "different content should not be equal")
    assert_true(a != b, "different content should be unequal")
    print("PASS: test_equality_different_content")


def test_equality_different_length() raises:
    var a = CidBuf.from_span(Span(_bytes(8)))
    var b = CidBuf.from_span(Span(_bytes(4)))
    assert_false(a == b, "different lengths should not be equal")
    assert_true(a != b, "different lengths should be unequal")
    print("PASS: test_equality_different_length")


def test_as_span_reflects_active_bytes_only() raises:
    """A CID shorter than the 20-byte backing array exposes only its
    active prefix, not the zero-filled tail."""
    var buf = CidBuf.from_span(Span(_bytes(4, start=UInt8(0x10))))
    var view = buf.as_span()
    assert_equal(len(view), 4)
    assert_equal(Int(view[0]), 0x10)
    assert_equal(Int(view[3]), 0x13)
    print("PASS: test_as_span_reflects_active_bytes_only")


def test_copy_is_independent_of_original() raises:
    var original = CidBuf.from_span(Span(_bytes(8)))
    var copy = CidBuf(copy=original)
    original.data[0] = UInt8(0xFF)
    assert_equal(Int(copy.data[0]), 0, "copy must not observe original's mutation")
    assert_true(original != copy, "mutated original diverges from the copy")
    print("PASS: test_copy_is_independent_of_original")


def main() raises:
    print("test_quic_cid_buf:")
    test_empty_has_zero_len()
    test_from_span_round_trips()
    test_from_span_max_length()
    test_from_span_empty()
    test_equality_same_content()
    test_equality_different_content()
    test_equality_different_length()
    test_as_span_reflects_active_bytes_only()
    test_copy_is_independent_of_original()
    print("All test_quic_cid_buf tests passed.")
