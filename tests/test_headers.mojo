# tests/test_headers.mojo
#
# Unit tests for Headers type.
from src.http import Headers


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_equal_int(got: Int, expected: Int, msg: String) raises:
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got " + String(got) + " expected " + String(expected))
        raise "assertion failed: " + msg


def assert_equal_str(got: String, expected: String, msg: String) raises:
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got '" + got + "' expected '" + expected + "'")
        raise "assertion failed: " + msg


def test_empty_headers() raises:
    """New Headers is empty."""
    var h = Headers()
    assert_equal_int(len(h), 0, "empty len")


def test_add_and_get() raises:
    """Add() stores and get() retrieves a header."""
    var h = Headers()
    h.add("Content-Type", "text/html")
    assert_equal_int(len(h), 1, "len after add")
    assert_equal_str(h.get("content-type"), "text/html", "get by lowercase")


def test_lowercase_on_insert() raises:
    """Names are lowercased on insert. Retrieval is case-insensitive."""
    var h = Headers()
    h.add("Content-Type", "text/html")
    h.add("X-Custom-Header", "value1")

    # Name stored as lowercase.
    var name = h.name_at(0)
    assert_equal_str(name, "content-type", "stored lowercase")

    # get() is case-insensitive (name already lowercase internally).
    assert_equal_str(h.get("Content-Type"), "text/html", "get mixed case")
    assert_equal_str(h.get("content-type"), "text/html", "get lower")
    assert_equal_str(h.get("CONTENT-TYPE"), "text/html", "get upper")


def test_value_preserved() raises:
    """Header values are NOT lowercased, preserved exactly."""
    var h = Headers()
    h.add("Accept", "Text/HTML")
    assert_equal_str(h.get("accept"), "Text/HTML", "value preserved")


def test_multiple_values() raises:
    """Multiple headers with the same name are all stored (ordered)."""
    var h = Headers()
    h.add("Set-Cookie", "a=1")
    h.add("Set-Cookie", "b=2")
    assert_equal_int(len(h), 2, "len 2")

    var vals = h.get_all("set-cookie")
    assert_equal_int(len(vals), 2, "get_all len")
    assert_equal_str(vals[0], "a=1", "first value")
    assert_equal_str(vals[1], "b=2", "second value")


def test_get_missing() raises:
    """Get() returns empty string for missing header."""
    var h = Headers()
    assert_equal_str(h.get("x-missing"), "", "missing returns empty")


def test_get_all_missing() raises:
    """Get_all() returns empty list for missing header."""
    var h = Headers()
    var vals = h.get_all("x-missing")
    assert_equal_int(len(vals), 0, "missing returns empty list")


def test_has() raises:
    """Has() checks presence of a header (case-insensitive)."""
    var h = Headers()
    h.add("Host", "example.com")
    assert_true(h.has("host"), "has host")
    assert_true(h.has("Host"), "has Host")
    assert_true(h.has("HOST"), "has HOST")
    assert_true(not h.has("x-missing"), "not has missing")


def test_remove() raises:
    """Remove() deletes all headers with the given name."""
    var h = Headers()
    h.add("Set-Cookie", "a=1")
    h.add("Host", "example.com")
    h.add("Set-Cookie", "b=2")
    assert_equal_int(len(h), 3, "len before remove")

    h.remove("set-cookie")
    assert_equal_int(len(h), 1, "len after remove")
    assert_equal_str(h.get("host"), "example.com", "host still there")
    assert_true(not h.has("set-cookie"), "set-cookie gone")


def test_insertion_order() raises:
    """Headers maintain insertion order."""
    var h = Headers()
    h.add("Host", "example.com")
    h.add("Accept", "text/html")
    h.add("Content-Length", "42")

    assert_equal_str(h.name_at(0), "host", "first name")
    assert_equal_str(h.name_at(1), "accept", "second name")
    assert_equal_str(h.name_at(2), "content-length", "third name")

    assert_equal_str(h.value_at(0), "example.com", "first value")
    assert_equal_str(h.value_at(1), "text/html", "second value")
    assert_equal_str(h.value_at(2), "42", "third value")


def test_set_replaces() raises:
    """Set() replaces all values for a header name with a single value."""
    var h = Headers()
    h.add("Accept", "text/html")
    h.add("Accept", "application/json")
    assert_equal_int(len(h), 2, "len 2 before set")

    h.set("Accept", "text/plain")
    assert_equal_int(len(h), 1, "len 1 after set")
    assert_equal_str(h.get("accept"), "text/plain", "set value")


def test_copy() raises:
    """Headers is copyable."""
    var h = Headers()
    h.add("Host", "example.com")
    var h2 = Headers(other=h)
    assert_equal_int(len(h2), 1, "copy len")
    assert_equal_str(h2.get("host"), "example.com", "copy value")

    # Mutating the copy does not affect the original.
    h2.add("Accept", "text/html")
    assert_equal_int(len(h), 1, "original unchanged")
    assert_equal_int(len(h2), 2, "copy changed")


def main() raises:
    test_empty_headers()
    test_add_and_get()
    test_lowercase_on_insert()
    test_value_preserved()
    test_multiple_values()
    test_get_missing()
    test_get_all_missing()
    test_has()
    test_remove()
    test_insertion_order()
    test_set_replaces()
    test_copy()
    print("test_headers: all 12 tests passed")
