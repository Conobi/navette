# tests/test_status.mojo
#
# Unit tests for StatusCode type.
from navette.http import StatusCode
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


def test_construction() raises:
    """StatusCode wraps a UInt16 correctly."""
    var s = StatusCode(200)
    assert_equal_int(Int(s.code()), 200, "code 200")

    var s2 = StatusCode(404)
    assert_equal_int(Int(s2.code()), 404, "code 404")


def test_category_informational() raises:
    """The 1xx codes are informational."""
    assert_true(StatusCode(100).is_informational(), "100 informational")
    assert_true(StatusCode(199).is_informational(), "199 informational")
    assert_true(not StatusCode(200).is_informational(), "200 not informational")


def test_category_success() raises:
    """The 2xx codes are success."""
    assert_true(StatusCode(200).is_success(), "200 success")
    assert_true(StatusCode(299).is_success(), "299 success")
    assert_true(not StatusCode(300).is_success(), "300 not success")


def test_category_redirect() raises:
    """The 3xx codes are redirect."""
    assert_true(StatusCode(301).is_redirect(), "301 redirect")
    assert_true(StatusCode(399).is_redirect(), "399 redirect")
    assert_true(not StatusCode(400).is_redirect(), "400 not redirect")


def test_category_client_error() raises:
    """The 4xx codes are client error."""
    assert_true(StatusCode(400).is_client_error(), "400 client error")
    assert_true(StatusCode(499).is_client_error(), "499 client error")
    assert_true(not StatusCode(500).is_client_error(), "500 not client error")


def test_category_server_error() raises:
    """The 5xx codes are server error."""
    assert_true(StatusCode(500).is_server_error(), "500 server error")
    assert_true(StatusCode(599).is_server_error(), "599 server error")
    assert_true(not StatusCode(200).is_server_error(), "200 not server error")


def test_equality() raises:
    """StatusCode equality is by numeric value."""
    assert_true(StatusCode(200) == StatusCode(200), "200 == 200")
    assert_true(StatusCode(200) != StatusCode(404), "200 != 404")


def test_common_codes() raises:
    """Named constructors for common codes."""
    assert_equal_int(Int(StatusCode.ok().code()), 200, "ok = 200")
    assert_equal_int(Int(StatusCode.not_found().code()), 404, "not_found = 404")
    assert_equal_int(Int(StatusCode.bad_request().code()), 400, "bad_request = 400")
    assert_equal_int(
        Int(StatusCode.internal_server_error().code()),
        500,
        "internal_server_error = 500",
    )
    assert_equal_int(Int(StatusCode.bad_gateway().code()), 502, "bad_gateway = 502")
    assert_equal_int(
        Int(StatusCode.gateway_timeout().code()), 504, "gateway_timeout = 504"
    )


def test_str() raises:
    """String representation is the numeric code."""
    assert_equal_str(String(StatusCode(200)), "200", "str 200")
    assert_equal_str(String(StatusCode(404)), "404", "str 404")


def test_copy() raises:
    """StatusCode is copyable."""
    var s = StatusCode(200)
    var s2 = StatusCode(other=s)
    assert_true(s == s2, "copy equal")


def main() raises:
    test_construction()
    test_category_informational()
    test_category_success()
    test_category_redirect()
    test_category_client_error()
    test_category_server_error()
    test_equality()
    test_common_codes()
    test_str()
    test_copy()
    print("test_status: all 10 tests passed")
