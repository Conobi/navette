# tests/test_h2_pseudo_headers.mojo
#
# Unit tests for H2 pseudo-header translation functions.

from lib.http1.types import Header
from navette.http.method import Method
from navette.http.version import Version
from navette.http.headers import Headers
from navette.http.request import Request, RequestBody
from navette.http.status import StatusCode
from navette.h2.pseudo_headers import (
    request_from_h2_headers,
    request_to_h2_headers,
    response_from_h2_headers,
    response_to_h2_headers,
    headers_from_h2,
    headers_to_h2,
)


def assert_true(cond: Bool, msg: String) raises:
    if not cond:
        print("ASSERTION FAILED: " + msg)
        raise Error("assertion failed: " + msg)


def assert_equal(a: String, b: String, msg: String) raises:
    if a != b:
        print("ASSERTION FAILED [" + msg + "]: got '" + a + "' expected '" + b + "'")
        raise Error("assertion failed: " + msg)


def assert_equal_int(a: Int, b: Int, msg: String) raises:
    if a != b:
        print("ASSERTION FAILED [" + msg + "]: got " + String(a) + " expected " + String(b))
        raise Error("assertion failed: " + msg)


# ---------- request_from_h2_headers ----------


def test_request_from_h2_basic_get() raises:
    """GET with :method, :path, :scheme, :authority + accept header."""
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "GET"))
    hdrs.append(Header(":path", "/index.html"))
    hdrs.append(Header(":scheme", "https"))
    hdrs.append(Header(":authority", "example.com"))
    hdrs.append(Header("accept", "text/html"))

    var req = request_from_h2_headers(UInt32(1), hdrs)
    assert_true(req.method.is_get(), "method is GET")
    assert_equal(req.target, "/index.html", "target")
    assert_true(req.version.is_http_2(), "version is HTTP/2")
    assert_equal(req.headers.get("host"), "example.com", "host from :authority")
    assert_equal(req.headers.get("x-h2-scheme"), "https", "x-h2-scheme from :scheme")
    assert_equal(req.headers.get("accept"), "text/html", "accept preserved")
    print("  PASS: test_request_from_h2_basic_get")


def test_request_from_h2_missing_method() raises:
    """Headers without :method should raise."""
    var hdrs = List[Header]()
    hdrs.append(Header(":path", "/"))
    hdrs.append(Header(":scheme", "https"))

    var raised = False
    try:
        var req = request_from_h2_headers(UInt32(1), hdrs)
    except:
        raised = True
    assert_true(raised, "missing :method should raise")
    print("  PASS: test_request_from_h2_missing_method")


def test_request_from_h2_pseudo_after_regular() raises:
    """:path pseudo-header appearing after a regular header should raise."""
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "GET"))
    hdrs.append(Header("accept", "text/html"))
    hdrs.append(Header(":path", "/"))

    var raised = False
    try:
        var req = request_from_h2_headers(UInt32(1), hdrs)
    except:
        raised = True
    assert_true(raised, "pseudo after regular should raise")
    print("  PASS: test_request_from_h2_pseudo_after_regular")


def test_request_from_h2_duplicate_method() raises:
    """Two :method headers should raise."""
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "GET"))
    hdrs.append(Header(":method", "POST"))
    hdrs.append(Header(":path", "/"))

    var raised = False
    try:
        var req = request_from_h2_headers(UInt32(1), hdrs)
    except:
        raised = True
    assert_true(raised, "duplicate :method should raise")
    print("  PASS: test_request_from_h2_duplicate_method")


def test_request_from_h2_connect_no_path() raises:
    """CONNECT with :authority but no :path should succeed."""
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "CONNECT"))
    hdrs.append(Header(":authority", "proxy.example.com:443"))

    var req = request_from_h2_headers(UInt32(1), hdrs)
    assert_true(req.method.is_connect(), "method is CONNECT")
    assert_equal(req.headers.get("host"), "proxy.example.com:443", "host from :authority")
    print("  PASS: test_request_from_h2_connect_no_path")


def test_request_from_h2_authority_preserves_existing_host() raises:
    """When both :authority and host are present, host is preserved."""
    var hdrs = List[Header]()
    hdrs.append(Header(":method", "GET"))
    hdrs.append(Header(":path", "/"))
    hdrs.append(Header(":scheme", "https"))
    hdrs.append(Header(":authority", "authority.example.com"))
    hdrs.append(Header("host", "host.example.com"))

    var req = request_from_h2_headers(UInt32(1), hdrs)
    assert_equal(req.headers.get("host"), "host.example.com", "existing host preserved")
    print("  PASS: test_request_from_h2_authority_preserves_existing_host")


# ---------- request_to_h2_headers ----------


def test_request_to_h2_basic_get() raises:
    """Build a GET Request with host header and verify pseudo-header order."""
    var headers = Headers()
    headers.add("host", "example.com")
    headers.add("accept", "text/html")

    var req = Request(
        method=Method.get(),
        target="/index.html",
        version=Version.http_2(),
        headers=headers^,
        body=RequestBody.empty(),
    )

    var result = request_to_h2_headers(req)

    # Pseudo-headers in correct order: :method, :path, :scheme, :authority
    assert_equal(result[0].name, ":method", "first is :method")
    assert_equal(result[0].value, "GET", ":method value")
    assert_equal(result[1].name, ":path", "second is :path")
    assert_equal(result[1].value, "/index.html", ":path value")
    assert_equal(result[2].name, ":scheme", "third is :scheme")
    assert_equal(result[2].value, "https", ":scheme default value")
    assert_equal(result[3].name, ":authority", "fourth is :authority")
    assert_equal(result[3].value, "example.com", ":authority value")

    # Regular headers: host and x-h2-scheme should not appear
    for i in range(4, len(result)):
        assert_true(result[i].name != "host", "host not in regular headers")
        assert_true(result[i].name != "x-h2-scheme", "x-h2-scheme not in regular headers")

    # accept should be present in regular headers
    assert_equal(result[4].name, "accept", "accept in regular headers")
    assert_equal(result[4].value, "text/html", "accept value")
    print("  PASS: test_request_to_h2_basic_get")


def test_request_to_h2_preserves_scheme() raises:
    """Request with x-h2-scheme=http produces :scheme http."""
    var headers = Headers()
    headers.add("host", "example.com")
    headers.add("x-h2-scheme", "http")

    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_2(),
        headers=headers^,
        body=RequestBody.empty(),
    )

    var result = request_to_h2_headers(req)
    assert_equal(result[2].name, ":scheme", "third is :scheme")
    assert_equal(result[2].value, "http", ":scheme is http not https")
    print("  PASS: test_request_to_h2_preserves_scheme")


# ---------- response_from_h2_headers ----------


def test_response_from_h2_200() raises:
    """:status 200 + content-type."""
    var hdrs = List[Header]()
    hdrs.append(Header(":status", "200"))
    hdrs.append(Header("content-type", "text/html"))

    var resp = response_from_h2_headers(hdrs)
    assert_true(resp.status == StatusCode.ok(), "status is 200")
    assert_true(resp.version.is_http_2(), "version is HTTP/2")
    assert_equal(resp.headers.get("content-type"), "text/html", "content-type preserved")
    print("  PASS: test_response_from_h2_200")


def test_response_from_h2_missing_status() raises:
    """No :status should raise."""
    var hdrs = List[Header]()
    hdrs.append(Header("content-type", "text/html"))

    var raised = False
    try:
        var resp = response_from_h2_headers(hdrs)
    except:
        raised = True
    assert_true(raised, "missing :status should raise")
    print("  PASS: test_response_from_h2_missing_status")


# ---------- response_to_h2_headers ----------


def test_response_to_h2() raises:
    """StatusCode.ok() + headers produces :status '200' first."""
    var headers = Headers()
    headers.add("content-type", "application/json")
    headers.add("x-custom", "value")

    var result = response_to_h2_headers(StatusCode.ok(), headers)
    assert_equal(result[0].name, ":status", "first is :status")
    assert_equal(result[0].value, "200", ":status value")
    assert_equal(result[1].name, "content-type", "content-type after :status")
    assert_equal(result[1].value, "application/json", "content-type value")
    assert_equal(result[2].name, "x-custom", "x-custom after content-type")
    assert_equal(result[2].value, "value", "x-custom value")
    print("  PASS: test_response_to_h2")


# ---------- headers roundtrip ----------


def test_headers_roundtrip() raises:
    """Verify headers_to_h2 then headers_from_h2 preserves all entries."""
    var headers = Headers()
    headers.add("content-type", "text/html")
    headers.add("accept", "application/json")
    headers.add("x-custom", "foo")

    var h2 = headers_to_h2(headers)
    var back = headers_from_h2(h2)

    assert_equal_int(len(back), 3, "roundtrip count")
    assert_equal(back.get("content-type"), "text/html", "roundtrip content-type")
    assert_equal(back.get("accept"), "application/json", "roundtrip accept")
    assert_equal(back.get("x-custom"), "foo", "roundtrip x-custom")
    print("  PASS: test_headers_roundtrip")


# ---------- request roundtrip ----------


def test_request_roundtrip() raises:
    """Verify request_to_h2_headers then request_from_h2_headers preserves fields."""
    var headers = Headers()
    headers.add("host", "example.com")
    headers.add("accept", "text/html")

    var req = Request(
        method=Method.get(),
        target="/page",
        version=Version.http_2(),
        headers=headers^,
        body=RequestBody.empty(),
    )

    var h2 = request_to_h2_headers(req)
    var back = request_from_h2_headers(UInt32(1), h2)

    assert_true(back.method.is_get(), "roundtrip method")
    assert_equal(back.target, "/page", "roundtrip target")
    assert_equal(back.headers.get("host"), "example.com", "roundtrip host")
    assert_equal(back.headers.get("accept"), "text/html", "roundtrip accept")
    print("  PASS: test_request_roundtrip")


# ---------- main ----------


def main() raises:
    test_request_from_h2_basic_get()
    test_request_from_h2_missing_method()
    test_request_from_h2_pseudo_after_regular()
    test_request_from_h2_duplicate_method()
    test_request_from_h2_connect_no_path()
    test_request_from_h2_authority_preserves_existing_host()
    test_request_to_h2_basic_get()
    test_request_to_h2_preserves_scheme()
    test_response_from_h2_200()
    test_response_from_h2_missing_status()
    test_response_to_h2()
    test_headers_roundtrip()
    test_request_roundtrip()
    print("test_h2_pseudo_headers: all 13 tests passed")
