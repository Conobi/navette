# tests/test_request_response.mojo
#
# Unit tests for Request and Response types.
from src.http import Method, StatusCode, Version, Headers, BodyFrame, Request, Response
from src.http.request import RequestBody
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


def test_request_construction() raises:
    """Request can be constructed with all fields."""
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    hdrs.add("Accept", "text/html")

    var data = List[UInt8]()
    data.append(0x41)

    var req = Request(
        method=Method.get(),
        target="/index.html",
        version=Version.http_1_1(),
        headers=hdrs^,
        body=RequestBody.buffered(data^),
    )

    assert_true(req.method.is_get(), "method is GET")
    assert_equal_str(req.target, "/index.html", "target")
    assert_true(req.version.is_http_1_1(), "version 1.1")
    assert_equal_int(len(req.headers), 2, "headers count")
    assert_equal_str(req.headers.get("host"), "example.com", "host header")
    assert_true(req.body.is_buffered(), "body is buffered")
    assert_equal_int(len(req.body.bytes()), 1, "body bytes")


def test_request_defaults() raises:
    """Request with minimal fields."""
    var req = Request(
        method=Method.get(),
        target="/",
    )
    assert_true(req.method.is_get(), "default method")
    assert_equal_str(req.target, "/", "default target")
    assert_true(req.version.is_http_1_1(), "default version 1.1")
    assert_equal_int(len(req.headers), 0, "default no headers")
    assert_true(req.body.is_empty(), "default empty body")


def test_request_move() raises:
    """Request is movable."""
    var req = Request(
        method=Method.post(),
        target="/submit",
    )
    var req2 = req^
    assert_true(req2.method.is_post(), "moved method")
    assert_equal_str(req2.target, "/submit", "moved target")


def test_response_construction() raises:
    """Response can be constructed with all fields."""
    var hdrs = Headers()
    hdrs.add("Content-Type", "text/html")

    var body = List[BodyFrame]()
    var data = List[UInt8]()
    data.append(0x3C)  # <
    body.append(BodyFrame.data(data^))

    var resp = Response(
        status=StatusCode.ok(),
        reason="OK",
        version=Version.http_1_1(),
        headers=hdrs^,
        body=body^,
    )

    assert_true(resp.status.is_success(), "status is success")
    assert_equal_int(Int(resp.status.code()), 200, "status 200")
    assert_equal_str(resp.reason, "OK", "reason")
    assert_true(resp.version.is_http_1_1(), "version 1.1")
    assert_equal_int(len(resp.headers), 1, "headers count")
    assert_equal_int(len(resp.body), 1, "body frames")


def test_response_defaults() raises:
    """Response with minimal fields."""
    var resp = Response(
        status=StatusCode.ok(),
    )
    assert_equal_int(Int(resp.status.code()), 200, "default status")
    assert_equal_str(resp.reason, "", "default empty reason")
    assert_true(resp.version.is_http_1_1(), "default version 1.1")
    assert_equal_int(len(resp.headers), 0, "default no headers")
    assert_equal_int(len(resp.body), 0, "default no body")


def test_response_move() raises:
    """Response is movable."""
    var resp = Response(
        status=StatusCode.not_found(),
        reason="Not Found",
    )
    var resp2 = resp^
    assert_equal_int(Int(resp2.status.code()), 404, "moved status")
    assert_equal_str(resp2.reason, "Not Found", "moved reason")


def test_informational_response() raises:
    """100 Continue response."""
    var resp = Response(
        status=StatusCode(100),
        reason="Continue",
    )
    assert_true(resp.status.is_informational(), "100 is informational")


def test_request_with_post_body() raises:
    """POST request with body data."""
    var body_bytes = List[UInt8]()
    # "name=value"
    var payload = String("name=value")
    var payload_bytes = payload.as_bytes()
    for i in range(len(payload_bytes)):
        body_bytes.append(payload_bytes[i])

    var payload_len = len(body_bytes)

    var hdrs = Headers()
    hdrs.add("Content-Type", "application/x-www-form-urlencoded")
    hdrs.add("Content-Length", String(payload_len))

    var req = Request(
        method=Method.post(),
        target="/submit",
        headers=hdrs^,
        body=RequestBody.buffered(body_bytes^),
    )

    assert_true(req.method.is_post(), "POST method")
    assert_true(req.body.is_buffered(), "body is buffered")
    assert_equal_int(len(req.body.bytes()), 10, "body length")


def test_response_with_trailers() raises:
    """Response body with trailers."""
    var body = List[BodyFrame]()

    var chunk = List[UInt8]()
    chunk.append(0x41)
    body.append(BodyFrame.data(chunk^))

    var trailers = Headers()
    trailers.add("Checksum", "sha256=abc123")
    body.append(BodyFrame.trailers(trailers^))

    var resp = Response(
        status=StatusCode.ok(),
        reason="OK",
        body=body^,
    )

    assert_equal_int(len(resp.body), 2, "two body frames")
    assert_true(resp.body[0].is_data(), "first is data")
    assert_true(resp.body[1].is_trailers(), "second is trailers")
    assert_true(resp.body[1].trailers().has("checksum"), "trailer present")


def main() raises:
    test_request_construction()
    test_request_defaults()
    test_request_move()
    test_response_construction()
    test_response_defaults()
    test_response_move()
    test_informational_response()
    test_request_with_post_body()
    test_response_with_trailers()
    print("test_request_response: all 9 tests passed")
