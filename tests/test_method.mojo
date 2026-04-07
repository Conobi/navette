# tests/test_method.mojo
#
# Unit tests for Method type.
from src.http import Method


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise "assertion failed: " + msg


def assert_equal(got: String, expected: String, msg: String) raises:
    if got != expected:
        print("ASSERTION FAILED [" + msg + "]: got '" + got + "' expected '" + expected + "'")
        raise "assertion failed: " + msg


def test_standard_methods() raises:
    """Each standard method has the correct string representation."""
    assert_equal(String(Method.get()), "GET", "GET")
    assert_equal(String(Method.post()), "POST", "POST")
    assert_equal(String(Method.put()), "PUT", "PUT")
    assert_equal(String(Method.delete()), "DELETE", "DELETE")
    assert_equal(String(Method.head()), "HEAD", "HEAD")
    assert_equal(String(Method.options()), "OPTIONS", "OPTIONS")
    assert_equal(String(Method.patch()), "PATCH", "PATCH")
    assert_equal(String(Method.connect()), "CONNECT", "CONNECT")
    assert_equal(String(Method.trace()), "TRACE", "TRACE")


def test_custom_method() raises:
    """Custom method preserves the string exactly (case-sensitive)."""
    var m = Method.custom("PURGE")
    assert_equal(String(m), "PURGE", "custom PURGE")

    var m2 = Method.custom("WebDAV-PROPFIND")
    assert_equal(String(m2), "WebDAV-PROPFIND", "custom WebDAV")


def test_equality_same_standard() raises:
    """Two instances of the same standard method are equal."""
    assert_true(Method.get() == Method.get(), "GET == GET")
    assert_true(Method.post() == Method.post(), "POST == POST")


def test_equality_different_standard() raises:
    """Different standard methods are not equal."""
    assert_true(Method.get() != Method.post(), "GET != POST")
    assert_true(Method.head() != Method.options(), "HEAD != OPTIONS")


def test_equality_custom() raises:
    """Custom methods compare by string value."""
    assert_true(Method.custom("PURGE") == Method.custom("PURGE"), "PURGE == PURGE")
    assert_true(Method.custom("PURGE") != Method.custom("BAN"), "PURGE != BAN")


def test_equality_standard_vs_custom() raises:
    """The custom() factory canonicalizes known method names to standard tags.

    Method.custom("GET") returns the same internal representation as
    Method.get(), so they compare equal. This avoids subtle bugs when
    code receives a method name as a string and constructs a Method.
    """
    assert_true(Method.get() == Method.custom("GET"), "GET == custom(GET)")
    assert_true(Method.custom("POST") == Method.post(), "custom(POST) == POST")


def test_case_sensitivity() raises:
    """Methods are case-sensitive per RFC 9110."""
    assert_true(Method.custom("get") != Method.get(), "get != GET (case)")
    assert_true(Method.custom("Get") != Method.get(), "Get != GET (case)")


def test_is_helpers() raises:
    """Predicate helpers for common methods."""
    assert_true(Method.get().is_get(), "GET.is_get()")
    assert_true(Method.head().is_head(), "HEAD.is_head()")
    assert_true(Method.connect().is_connect(), "CONNECT.is_connect()")
    assert_true(not Method.post().is_get(), "POST is not GET")
    assert_true(not Method.get().is_head(), "GET is not HEAD")


def test_copy() raises:
    """Method is copyable."""
    var m = Method.get()
    var m2 = Method(other=m)
    assert_true(m == m2, "copy equal")
    assert_equal(String(m2), "GET", "copy str")


def main() raises:
    test_standard_methods()
    test_custom_method()
    test_equality_same_standard()
    test_equality_different_standard()
    test_equality_custom()
    test_equality_standard_vs_custom()
    test_case_sensitivity()
    test_is_helpers()
    test_copy()
    print("test_method: all 9 tests passed")
