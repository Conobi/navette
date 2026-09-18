from std.collections import Span
from tests._test_util import assert_true, assert_equal_int
from navette.util.byte_vec import ByteVec


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
    print("test_byte_vec: all 9 tests passed")
