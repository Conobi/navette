# tests/h2/test_hpack_dynamic_index.mojo
#
# Unit tests for the Dict-indexed HPACK DynamicTable.

from navette.h2.hpack_table import DynamicTable


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise Error("assertion failed: " + msg)


def assert_equal_int(a: Int, b: Int, msg: String) raises:
    if a != b:
        print(
            "ASSERTION FAILED ["
            + msg
            + "]: got "
            + String(a)
            + " expected "
            + String(b)
        )
        raise Error("assertion failed: " + msg)


def test_insert_and_find_exact() raises:
    """Insert one entry, find exact match at wire index 0."""
    var dt = DynamicTable(4096)
    dt.insert("content-type", "text/html")

    var result = dt.find("content-type", "text/html")
    assert_equal_int(result[0], 0, "exact match wire index")
    assert_true(result[1], "exact match flag")
    print("  PASS: test_insert_and_find_exact")


def test_insert_and_find_name_only() raises:
    """Same name different value yields name-only match."""
    var dt = DynamicTable(4096)
    dt.insert("content-type", "text/html")

    var result = dt.find("content-type", "application/json")
    assert_equal_int(result[0], 0, "name-only match wire index")
    assert_true(not result[1], "name-only match flag is False")
    print("  PASS: test_insert_and_find_name_only")


def test_wire_index_shifts_on_insert() raises:
    """Two inserts -- newer entry at 0, older shifts to 1."""
    var dt = DynamicTable(4096)
    dt.insert("x-first", "aaa")
    dt.insert("x-second", "bbb")

    # Newer entry is at wire index 0
    var r1 = dt.find("x-second", "bbb")
    assert_equal_int(r1[0], 0, "x-second at wire index 0")
    assert_true(r1[1], "x-second exact match")

    # Older entry shifted to wire index 1
    var r2 = dt.find("x-first", "aaa")
    assert_equal_int(r2[0], 1, "x-first at wire index 1")
    assert_true(r2[1], "x-first exact match")
    print("  PASS: test_wire_index_shifts_on_insert")


def test_eviction_preserves_invariant() raises:
    """Tiny table (80 bytes) -- second insert evicts first."""
    # Entry size = name_len + value_len + 32 (RFC 7541 S4.1)
    # "x-a" (3) + "val" (3) + 32 = 38 bytes
    # "x-b" (3) + "val" (3) + 32 = 38 bytes
    # Table of 80 can hold both (76 bytes), but 70 can only hold one.
    var dt = DynamicTable(70)
    dt.insert("x-a", "val")
    dt.insert("x-b", "val")

    # x-a should be evicted
    var r1 = dt.find("x-a", "val")
    assert_equal_int(r1[0], -1, "x-a evicted")
    assert_true(not r1[1], "x-a not found")

    # x-b should be present at wire index 0
    var r2 = dt.find("x-b", "val")
    assert_equal_int(r2[0], 0, "x-b at wire index 0")
    assert_true(r2[1], "x-b exact match")
    print("  PASS: test_eviction_preserves_invariant")


def test_eviction_doesnt_remove_newer_same_name() raises:
    """Same name inserted twice -- evict oldest, newer survives."""
    # "x-hdr" (5) + "old" (3) + 32 = 40 bytes
    # "x-hdr" (5) + "new" (3) + 32 = 40 bytes
    # Table of 70 can hold only one entry of 40 bytes.
    var dt = DynamicTable(70)
    dt.insert("x-hdr", "old")
    dt.insert("x-hdr", "new")

    # Newer entry survives
    var r1 = dt.find("x-hdr", "new")
    assert_equal_int(r1[0], 0, "newer x-hdr at wire index 0")
    assert_true(r1[1], "newer x-hdr exact match")

    # Old entry is gone -- name-only match should still point to newer
    var r2 = dt.find("x-hdr", "old")
    assert_equal_int(r2[0], 0, "name-only match points to newer")
    assert_true(not r2[1], "old value not exact match")
    print("  PASS: test_eviction_doesnt_remove_newer_same_name")


def test_set_max_size_zero_clears_indices() raises:
    """Calling set_max_size(0) clears everything."""
    var dt = DynamicTable(4096)
    dt.insert("content-type", "text/html")
    dt.insert("x-custom", "value")

    dt.set_max_size(0)

    var r1 = dt.find("content-type", "text/html")
    assert_equal_int(r1[0], -1, "content-type gone after clear")
    assert_true(not r1[1], "content-type not found")

    var r2 = dt.find("x-custom", "value")
    assert_equal_int(r2[0], -1, "x-custom gone after clear")
    assert_true(not r2[1], "x-custom not found")

    assert_equal_int(dt.size(), 0, "table empty")
    print("  PASS: test_set_max_size_zero_clears_indices")


def test_not_found() raises:
    """Unknown name returns (-1, False)."""
    var dt = DynamicTable(4096)
    dt.insert("content-type", "text/html")

    var result = dt.find("x-unknown", "whatever")
    assert_equal_int(result[0], -1, "unknown name index")
    assert_true(not result[1], "unknown name not found")
    print("  PASS: test_not_found")


def main() raises:
    test_insert_and_find_exact()
    test_insert_and_find_name_only()
    test_wire_index_shifts_on_insert()
    test_eviction_preserves_invariant()
    test_eviction_doesnt_remove_newer_same_name()
    test_set_max_size_zero_clears_indices()
    test_not_found()
    print("test_hpack_dynamic_index: all 7 tests passed")
