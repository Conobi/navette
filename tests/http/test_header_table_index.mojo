# tests/http/test_header_table_index.mojo
#
# Unit tests for StaticTableIndex O(1) header lookup.

from navette.http.header_table_index import StaticTableIndex
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_exact_match() raises:
    """Exact name+value match returns the correct index."""
    var entries = List[Tuple[String, String]]()
    entries.append((String(""), String("")))
    entries.append((String(":method"), String("GET")))
    entries.append((String(":method"), String("POST")))
    entries.append((String(":path"), String("/")))
    var idx = StaticTableIndex(entries, start_index=1)
    var result = idx.find(":method", "GET")
    assert_equal_int(result[0], 1, "exact match :method GET should be index 1")
    assert_true(result[1], "should be exact match")
    print("  test_exact_match: PASS")


def test_name_only_match() raises:
    """Name match without value returns first index, exact=False."""
    var entries = List[Tuple[String, String]]()
    entries.append((String(""), String("")))
    entries.append((String(":method"), String("GET")))
    entries.append((String(":method"), String("POST")))
    entries.append((String(":path"), String("/")))
    var idx = StaticTableIndex(entries, start_index=1)
    var result = idx.find(":method", "DELETE")
    assert_equal_int(result[0], 1, "name-only :method should return first index 1")
    assert_false(result[1], "should NOT be exact match")
    print("  test_name_only_match: PASS")


def test_no_match() raises:
    """Unknown header returns (-1, False)."""
    var entries = List[Tuple[String, String]]()
    entries.append((String(""), String("")))
    entries.append((String(":method"), String("GET")))
    var idx = StaticTableIndex(entries, start_index=1)
    var result = idx.find("x-custom", "value")
    assert_equal_int(result[0], -1, "unknown header should return -1")
    assert_false(result[1], "should NOT be exact match")
    print("  test_no_match: PASS")


def test_zero_based_start_index() raises:
    """Indexes from the first entry when start_index=0."""
    var entries = List[Tuple[String, String]]()
    entries.append((String(":authority"), String("")))
    entries.append((String(":path"), String("/")))
    var idx = StaticTableIndex(entries, start_index=0)
    var result = idx.find(":authority", "")
    assert_equal_int(result[0], 0, "0-based: :authority should be index 0")
    assert_true(result[1], "should be exact match")
    print("  test_zero_based_start_index: PASS")


def test_first_name_wins() raises:
    """Name-only match returns the first index for that name."""
    var entries = List[Tuple[String, String]]()
    entries.append((String(""), String("")))
    entries.append((String(":status"), String("200")))
    entries.append((String(":status"), String("304")))
    entries.append((String(":status"), String("404")))
    var idx = StaticTableIndex(entries, start_index=1)
    var result = idx.find(":status", "500")
    assert_equal_int(result[0], 1, "name-only should return FIRST :status index")
    assert_false(result[1], "should NOT be exact match")
    print("  test_first_name_wins: PASS")


def main() raises:
    print("test_header_table_index")
    test_exact_match()
    test_name_only_match()
    test_no_match()
    test_zero_based_start_index()
    test_first_name_wins()
    print("  All passed.")
