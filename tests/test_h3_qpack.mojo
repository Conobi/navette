# tests/test_h3_qpack.mojo
# QPACK static table tests — RFC 9204 Appendix A
# Task 2: static table only (Huffman, encoder, decoder in T3-T5)

from src.h3.qpack import (
    QpackStaticEntry,
    QpackHeaderField,
    QPACK_STATIC_TABLE_SIZE,
    qpack_static_get,
    qpack_static_find,
    qpack_static_find_name,
)
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_static_get_method_get() raises:
    # RFC 9204 Appendix A: index 17 = (:method, GET)
    var entry = qpack_static_get(17)
    assert_true(entry.name == ":method", "name should be :method")
    assert_true(entry.value == "GET", "value should be GET")
    print("  test_static_get_method_get: PASS")


def test_static_get_out_of_range_raises() raises:
    var raised = False
    try:
        _ = qpack_static_get(QPACK_STATIC_TABLE_SIZE)
    except:
        raised = True
    assert_true(raised, "should raise on out-of-range index")
    print("  test_static_get_out_of_range_raises: PASS")


def test_static_find_exact_match() raises:
    # (:method, GET) should find index 17
    var result = qpack_static_find(":method", "GET")
    assert_true(result.__bool__(), "should find :method GET")
    assert_equal_int(result.value(), 17, "index of :method GET should be 17")
    print("  test_static_find_exact_match: PASS")


def test_static_find_no_match() raises:
    # Unknown header
    var result = qpack_static_find("x-custom", "value")
    assert_false(result.__bool__(), "x-custom should not be found")
    print("  test_static_find_no_match: PASS")


def test_static_find_name_only() raises:
    # :method exists; first :method entry is index 15 (CONNECT)
    var result = qpack_static_find_name(":method")
    assert_true(result.__bool__(), "should find :method by name")
    # First :method entry is index 15 (CONNECT) per RFC 9204 Appendix A
    assert_equal_int(result.value(), 15, "first :method index should be 15")
    print("  test_static_find_name_only: PASS")


def test_static_find_name_no_match() raises:
    var result = qpack_static_find_name("x-unknown-header")
    assert_false(result.__bool__(), "x-unknown-header should not be found")
    print("  test_static_find_name_no_match: PASS")


def main() raises:
    print("=== test_h3_qpack ===")
    test_static_get_method_get()
    test_static_get_out_of_range_raises()
    test_static_find_exact_match()
    test_static_find_no_match()
    test_static_find_name_only()
    test_static_find_name_no_match()
    print("All tests passed.")
