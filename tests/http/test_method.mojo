# tests/test_method.mojo
#
# Unit tests for Method type.
from navette.http import Method
from tests._test_util import assert_true, assert_equal_str


def test_standard_methods() raises:
    """Each standard method has the correct string representation."""
    assert_equal_str(String(Method.get()), "GET", "GET")
    assert_equal_str(String(Method.post()), "POST", "POST")
    assert_equal_str(String(Method.put()), "PUT", "PUT")
    assert_equal_str(String(Method.delete()), "DELETE", "DELETE")
    assert_equal_str(String(Method.head()), "HEAD", "HEAD")
    assert_equal_str(String(Method.options()), "OPTIONS", "OPTIONS")
    assert_equal_str(String(Method.patch()), "PATCH", "PATCH")
    assert_equal_str(String(Method.connect()), "CONNECT", "CONNECT")
    assert_equal_str(String(Method.trace()), "TRACE", "TRACE")
    assert_equal_str(String(Method.query()), "QUERY", "QUERY")


def test_custom_method() raises:
    """Custom method preserves the string exactly (case-sensitive)."""
    var m = Method.custom("PURGE")
    assert_equal_str(String(m), "PURGE", "custom PURGE")

    var m2 = Method.custom("WebDAV-PROPFIND")
    assert_equal_str(String(m2), "WebDAV-PROPFIND", "custom WebDAV")


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
    assert_true(Method.query() == Method.custom("QUERY"), "QUERY == custom(QUERY)")


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
    assert_true(Method.query().is_query(), "QUERY.is_query()")
    assert_true(not Method.query().is_get(), "QUERY is not GET")


def test_is_safe() raises:
    """Verify is_safe() returns true for GET, HEAD, OPTIONS, TRACE, QUERY only."""
    assert_true(Method.get().is_safe(), "GET is safe")
    assert_true(Method.head().is_safe(), "HEAD is safe")
    assert_true(Method.options().is_safe(), "OPTIONS is safe")
    assert_true(Method.trace().is_safe(), "TRACE is safe")
    assert_true(Method.query().is_safe(), "QUERY is safe")
    assert_true(not Method.post().is_safe(), "POST is not safe")
    assert_true(not Method.put().is_safe(), "PUT is not safe")
    assert_true(not Method.delete().is_safe(), "DELETE is not safe")
    assert_true(not Method.patch().is_safe(), "PATCH is not safe")
    assert_true(not Method.connect().is_safe(), "CONNECT is not safe")
    assert_true(not Method.custom("PURGE").is_safe(), "custom PURGE is not safe")


def test_is_idempotent() raises:
    """Verify is_idempotent() returns true for all safe methods + PUT + DELETE."""
    assert_true(Method.get().is_idempotent(), "GET is idempotent")
    assert_true(Method.head().is_idempotent(), "HEAD is idempotent")
    assert_true(Method.options().is_idempotent(), "OPTIONS is idempotent")
    assert_true(Method.trace().is_idempotent(), "TRACE is idempotent")
    assert_true(Method.query().is_idempotent(), "QUERY is idempotent")
    assert_true(Method.put().is_idempotent(), "PUT is idempotent")
    assert_true(Method.delete().is_idempotent(), "DELETE is idempotent")
    assert_true(not Method.post().is_idempotent(), "POST is not idempotent")
    assert_true(not Method.patch().is_idempotent(), "PATCH is not idempotent")
    assert_true(not Method.connect().is_idempotent(), "CONNECT is not idempotent")
    assert_true(not Method.custom("PURGE").is_idempotent(), "custom PURGE is not idempotent")


def test_copy() raises:
    """Method is copyable."""
    var m = Method.get()
    var m2 = Method(other=m)
    assert_true(m == m2, "copy equal")
    assert_equal_str(String(m2), "GET", "copy str")


def main() raises:
    test_standard_methods()
    test_custom_method()
    test_equality_same_standard()
    test_equality_different_standard()
    test_equality_custom()
    test_equality_standard_vs_custom()
    test_case_sensitivity()
    test_is_helpers()
    test_is_safe()
    test_is_idempotent()
    test_copy()
    print("test_method: all 11 tests passed")
