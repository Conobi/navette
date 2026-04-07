# tests/test_serializer.mojo
#
# Unit tests for the HTTP/1.1 serializer (src/h1/serializer.mojo).

from src.http import Method, StatusCode, Version, Headers, BodyFrame, Request, Response
from src.h1.serializer import (
    serialize_request,
    serialize_response,
    serialize_informational,
)
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a byte list to a string for assertion messages."""
    var result = String()
    for i in range(len(data)):
        result += chr(Int(data[i]))
    return result^


def _assert_bytes_eq(data: List[UInt8], expected: String, msg: String) raises:
    """Assert that a byte buffer equals an expected string byte-for-byte."""
    var expected_bytes = expected.as_bytes()
    if len(data) != len(expected_bytes):
        print(
            "ASSERTION FAILED ["
            + msg
            + "]: length got="
            + String(len(data))
            + " expected="
            + String(len(expected_bytes))
            + "\n  got: "
            + _bytes_to_string(data)
            + "\n  exp: "
            + expected
        )
        raise "assertion failed: " + msg
    for i in range(len(data)):
        if data[i] != expected_bytes[i]:
            print(
                "ASSERTION FAILED ["
                + msg
                + "]: byte mismatch at "
                + String(i)
                + " got="
                + String(Int(data[i]))
                + " expected="
                + String(Int(expected_bytes[i]))
                + "\n  got: "
                + _bytes_to_string(data)
                + "\n  exp: "
                + expected
            )
            raise "assertion failed: " + msg


def test_serialize_get_request() raises:
    """GET / HTTP/1.1 with Host header, no body."""
    var headers = Headers()
    headers.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_1_1(),
        headers=headers^,
    )
    var wire = serialize_request(req)
    _assert_bytes_eq(
        wire,
        "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n",
        "test_serialize_get_request",
    )


def test_serialize_post_request_with_body() raises:
    """POST with Content-Length body. Serializer inserts content-length."""
    var body_data = List[UInt8]()
    var msg = String("Hello, World!")
    var msg_bytes = msg.as_bytes()
    for i in range(len(msg_bytes)):
        body_data.append(msg_bytes[i])
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_data^))
    var req = Request(
        method=Method.post(),
        target="/submit",
        version=Version.http_1_1(),
        headers=Headers(),
        body=body^,
    )
    var wire = serialize_request(req)
    _assert_bytes_eq(
        wire,
        "POST /submit HTTP/1.1\r\ncontent-length: 13\r\n\r\nHello, World!",
        "test_serialize_post_request_with_body",
    )


def test_serialize_200_response() raises:
    """200 OK with body and a user header."""
    var headers = Headers()
    headers.add("Content-Type", "text/plain")
    var body_data = List[UInt8]()
    var msg = String("OK")
    var msg_bytes = msg.as_bytes()
    for i in range(len(msg_bytes)):
        body_data.append(msg_bytes[i])
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_data^))
    var resp = Response(
        status=StatusCode(200),
        reason="OK",
        version=Version.http_1_1(),
        headers=headers^,
        body=body^,
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nOK",
        "test_serialize_200_response",
    )


def test_serialize_empty_reason() raises:
    """Empty reason still emits the SP after the status code per RFC 9112."""
    var resp = Response(
        status=StatusCode(200),
        reason="",
        version=Version.http_1_1(),
        headers=Headers(),
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 200 \r\n\r\n",
        "test_serialize_empty_reason",
    )


def test_serialize_chunked_body_with_trailers() raises:
    """Body with trailers uses chunked transfer encoding."""
    var body_data = List[UInt8]()
    var msg = String("Hello")
    var msg_bytes = msg.as_bytes()
    for i in range(len(msg_bytes)):
        body_data.append(msg_bytes[i])
    var trailer_headers = Headers()
    trailer_headers.add("Checksum", "abc123")
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_data^))
    body.append(BodyFrame.trailers(trailer_headers^))
    var resp = Response(
        status=StatusCode(200),
        reason="OK",
        version=Version.http_1_1(),
        headers=Headers(),
        body=body^,
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\nchecksum: abc123\r\n\r\n",
        "test_serialize_chunked_body_with_trailers",
    )


def test_serialize_1xx_no_body() raises:
    """1xx informational responses MUST NOT include body or framing headers."""
    var headers = Headers()
    headers.add("Link", "</style.css>; rel=preload")
    var wire = serialize_informational(StatusCode(103), headers)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 103 \r\nlink: </style.css>; rel=preload\r\n\r\n",
        "test_serialize_1xx_no_body",
    )


def test_serialize_204_no_content_length() raises:
    """204 MUST NOT include Content-Length and MUST NOT include body."""
    var resp = Response(
        status=StatusCode(204),
        reason="No Content",
        version=Version.http_1_1(),
        headers=Headers(),
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 204 No Content\r\n\r\n",
        "test_serialize_204_no_content_length",
    )


def test_serialize_304_allows_content_length() raises:
    """304 MAY include user-provided Content-Length but MUST NOT include body."""
    var headers = Headers()
    headers.add("Content-Length", "1234")
    var resp = Response(
        status=StatusCode(304),
        reason="Not Modified",
        version=Version.http_1_1(),
        headers=headers^,
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 304 Not Modified\r\ncontent-length: 1234\r\n\r\n",
        "test_serialize_304_allows_content_length",
    )


def test_serialize_http10_request() raises:
    """HTTP/1.0 version is preserved on the request line."""
    var headers = Headers()
    headers.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_1_0(),
        headers=headers^,
    )
    var wire = serialize_request(req)
    _assert_bytes_eq(
        wire,
        "GET / HTTP/1.0\r\nhost: example.com\r\n\r\n",
        "test_serialize_http10_request",
    )


def test_serialize_multiple_headers_same_name() raises:
    """Repeated headers (e.g. Set-Cookie) are emitted as separate lines."""
    var headers = Headers()
    headers.add("Set-Cookie", "a=1")
    headers.add("Set-Cookie", "b=2")
    var resp = Response(
        status=StatusCode(200),
        reason="OK",
        version=Version.http_1_1(),
        headers=headers^,
    )
    var wire = serialize_response(resp)
    _assert_bytes_eq(
        wire,
        "HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n\r\n",
        "test_serialize_multiple_headers_same_name",
    )


def main() raises:
    test_serialize_get_request()
    test_serialize_post_request_with_body()
    test_serialize_200_response()
    test_serialize_empty_reason()
    test_serialize_chunked_body_with_trailers()
    test_serialize_1xx_no_body()
    test_serialize_204_no_content_length()
    test_serialize_304_allows_content_length()
    test_serialize_http10_request()
    test_serialize_multiple_headers_same_name()
    print("test_serializer: all 10 tests passed")
