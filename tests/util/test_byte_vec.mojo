from std.collections import Span
from tests._test_util import assert_true, assert_equal_int
from navette.util.byte_vec import ByteVec, OwnedBuf


def test_empty() raises:
    var v = ByteVec[20]()
    assert_equal_int(len(v), 0, "empty ByteVec length")
    assert_equal_int(v.remaining_capacity(), 20, "empty ByteVec capacity")


def test_append_and_len() raises:
    var v = ByteVec[8]()
    v.append(Byte(0x0A))
    v.append(Byte(0x0B))
    assert_equal_int(len(v), 2, "append increases length")
    assert_equal_int(Int(v[0]), Int(Byte(0x0A)), "first appended byte")
    assert_equal_int(Int(v[1]), Int(Byte(0x0B)), "second appended byte")


def test_extend_from_span() raises:
    var src = List[Byte](capacity=4)
    src.append(Byte(1))
    src.append(Byte(2))
    src.append(Byte(3))
    src.append(Byte(4))
    var v = ByteVec[10]()
    v.extend(Span(src))
    assert_equal_int(len(v), 4, "extend adds all bytes")
    assert_equal_int(Int(v[0]), 1, "first extended byte")
    assert_equal_int(Int(v[3]), 4, "last extended byte")


def test_as_span() raises:
    var v = ByteVec[8]()
    v.append(Byte(42))
    v.append(Byte(99))
    var sp = v.as_span()
    assert_equal_int(len(sp), 2, "span length matches buffer length")
    assert_equal_int(Int(sp[0]), 42, "span first byte")
    assert_equal_int(Int(sp[1]), 99, "span second byte")


def test_clear() raises:
    var v = ByteVec[8]()
    v.append(Byte(1))
    v.append(Byte(2))
    v.clear()
    assert_equal_int(len(v), 0, "clear empties buffer")
    assert_equal_int(v.remaining_capacity(), 8, "clear restores capacity")


def test_overflow_raises() raises:
    var v = ByteVec[2]()
    v.append(Byte(1))
    v.append(Byte(2))
    var raised = False
    try:
        v.append(Byte(3))
    except:
        raised = True
    assert_true(raised, "ByteVec should raise on overflow")


def test_extend_overflow_raises() raises:
    var src = List[Byte](capacity=5)
    src.append(Byte(1))
    src.append(Byte(2))
    src.append(Byte(3))
    src.append(Byte(4))
    src.append(Byte(5))
    var v = ByteVec[3]()
    var raised = False
    try:
        v.extend(Span(src))
    except:
        raised = True
    assert_true(raised, "ByteVec.extend should raise on overflow")


def test_copy() raises:
    var v = ByteVec[8]()
    v.append(Byte(10))
    v.append(Byte(20))
    var v2 = v.copy()
    v2.clear()
    assert_equal_int(len(v), 2, "original unchanged after copy-then-clear")
    assert_equal_int(len(v2), 0, "copy is cleared")


def test_setitem() raises:
    var v = ByteVec[4]()
    v.append(Byte(0))
    v.append(Byte(0))
    v[1] = Byte(42)
    assert_equal_int(Int(v[1]), 42, "setitem modifies byte")


def test_owned_buf_empty() raises:
    var b = OwnedBuf[1200]()
    assert_equal_int(len(b), 0, "empty OwnedBuf length")
    assert_equal_int(b.remaining_capacity(), 1200, "empty OwnedBuf capacity")


def test_owned_buf_append_and_read() raises:
    var b = OwnedBuf[64]()
    for i in range(64):
        b.append(Byte(i % 256))
    assert_equal_int(len(b), 64, "OwnedBuf append all 64 bytes")
    assert_equal_int(Int(b[0]), 0, "OwnedBuf first byte")
    assert_equal_int(Int(b[63]), 63, "OwnedBuf last byte")


def test_owned_buf_extend() raises:
    var src = List[Byte](capacity=3)
    src.append(Byte(10))
    src.append(Byte(20))
    src.append(Byte(30))
    var b = OwnedBuf[128]()
    b.extend(Span(src))
    assert_equal_int(len(b), 3, "OwnedBuf extend adds bytes")
    assert_equal_int(Int(b[2]), 30, "OwnedBuf extended byte value")


def test_owned_buf_as_span() raises:
    var b = OwnedBuf[32]()
    b.append(Byte(0xAA))
    b.append(Byte(0xBB))
    var sp = b.as_span()
    assert_equal_int(len(sp), 2, "OwnedBuf span length")
    assert_equal_int(Int(sp[0]), 0xAA, "OwnedBuf span first byte")


def test_owned_buf_clear_and_reuse() raises:
    var b = OwnedBuf[100]()
    for i in range(50):
        b.append(Byte(i % 256))
    assert_equal_int(len(b), 50, "OwnedBuf after append loop")
    b.clear()
    assert_equal_int(len(b), 0, "OwnedBuf after clear")
    assert_equal_int(b.remaining_capacity(), 100, "OwnedBuf capacity after clear")
    b.append(Byte(0xFF))
    assert_equal_int(Int(b[0]), 0xFF, "OwnedBuf reused after clear")


def test_owned_buf_overflow_raises() raises:
    var b = OwnedBuf[3]()
    b.append(Byte(1))
    b.append(Byte(2))
    b.append(Byte(3))
    var raised = False
    try:
        b.append(Byte(4))
    except:
        raised = True
    assert_true(raised, "OwnedBuf should raise on overflow")


def test_owned_buf_mtu_size() raises:
    """Verify OwnedBuf works at MTU-sized capacity (1200 bytes)."""
    var b = OwnedBuf[1200]()
    for i in range(1200):
        b.append(Byte(i % 256))
    assert_equal_int(len(b), 1200, "OwnedBuf MTU-size length")
    var sp = b.as_span()
    assert_equal_int(len(sp), 1200, "OwnedBuf MTU-size span length")
    assert_equal_int(Int(sp[0]), 0, "OwnedBuf MTU-size first byte")
    assert_equal_int(Int(sp[1199]), 1199 % 256, "OwnedBuf MTU-size last byte")


def test_unsafe_ptr_reads_storage() raises:
    """unsafe_ptr must type-check (origin tied to self) and see written bytes."""
    var v = ByteVec[4]()
    v.append(7)
    v.append(9)
    var p = v.unsafe_ptr()
    assert_equal_int(Int(p[0]), 7, "ByteVec ptr[0]")
    assert_equal_int(Int(p[1]), 9, "ByteVec ptr[1]")
    var ob = OwnedBuf[4]()
    ob.append(3)
    var q = ob.unsafe_ptr()
    assert_equal_int(Int(q[0]), 3, "OwnedBuf ptr[0]")
    _ = v._len
    _ = ob._len


def main() raises:
    test_empty()
    test_append_and_len()
    test_extend_from_span()
    test_as_span()
    test_clear()
    test_overflow_raises()
    test_extend_overflow_raises()
    test_copy()
    test_setitem()
    test_owned_buf_empty()
    test_owned_buf_append_and_read()
    test_owned_buf_extend()
    test_owned_buf_as_span()
    test_owned_buf_clear_and_reuse()
    test_owned_buf_overflow_raises()
    test_owned_buf_mtu_size()
    test_unsafe_ptr_reads_storage()
    print("test_byte_vec: all 17 tests passed")
