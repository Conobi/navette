# tests/test_h1_connection.mojo
#
# Unit tests for the H1Connection state machine (src/h1/connection.mojo).

from std.collections.optional import Optional
from std.memory import Span

from navette.http import (
    Method,
    StatusCode,
    Version,
    Headers,
    BodyFrame,
    Request,
    Response,
)
from navette.h1 import ParseConfig, ParserStrictness
from navette.h1.connection import H1Connection
from navette.http.request import RequestBody
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


# --- Helpers ---


def _str_to_bytes(s: String) -> List[UInt8]:
    """Copy a string into a fresh List[UInt8]."""
    var b = s.as_bytes()
    var result = List[UInt8]()
    for i in range(len(b)):
        result.append(b[i])
    return result^


def _bytes_to_string(data: List[UInt8]) -> String:
    """Convert a byte list back into a string for assertion messages."""
    var result = String()
    for i in range(len(data)):
        result += chr(Int(data[i]))
    return result^


def _str_contains(haystack: String, needle: String) -> Bool:
    """Substring search (case-sensitive)."""
    var hb = haystack.as_bytes()
    var nb = needle.as_bytes()
    var hl = len(hb)
    var nl = len(nb)
    if nl == 0:
        return True
    if nl > hl:
        return False
    for i in range(hl - nl + 1):
        var ok = True
        for j in range(nl):
            if hb[i + j] != nb[j]:
                ok = False
                break
        if ok:
            return True
    return False


# --- Tests ---


def test_basic_request_response_cycle() raises:
    """Feed a GET request, parse it, send a response, drain wire bytes."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected a request")
    var req = req_opt.take()
    assert_true(req.method.is_get(), "expected GET")
    assert_equal_str(req.target, "/", "request target")

    # Build a response with a small body.
    var headers = Headers()
    headers.add("Content-Type", "text/plain")
    var body_data = _str_to_bytes("OK")
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_data^))
    var resp = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=headers^,
        body=body^,
    )
    conn.send_response(resp^)
    assert_true(conn.wants_write(), "expected wants_write after send_response")

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 200 OK"),
        "response wire must contain status line, got: " + out_str,
    )
    assert_true(
        _str_contains(out_str, "content-length: 2\r\n\r\nOK"),
        "response wire must end with body 'OK', got: " + out_str,
    )
    # After draining, no more bytes pending.
    assert_true(not conn.wants_write(), "wants_write should be false after drain")
    print("PASS: test_basic_request_response_cycle")


def test_incremental_feeding() raises:
    """Feed partial data, get None, feed rest, get Request."""
    var conn = H1Connection(ParseConfig())

    var part1 = _str_to_bytes("GET / HTTP/1.1\r\n")
    conn.receive_data(Span(part1))
    var req1 = conn.next_request()
    assert_true(not req1.__bool__(), "should not have a request yet")

    var part2 = _str_to_bytes("Host: example.com\r\n\r\n")
    conn.receive_data(Span(part2))
    var req2 = conn.next_request()
    assert_true(req2.__bool__(), "expected a request after full data")

    print("PASS: test_incremental_feeding")


def test_keep_alive_two_requests() raises:
    """Two requests on same connection (HTTP/1.1 keep-alive default)."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
        + String("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    conn.receive_data(Span(wire))

    var req1_opt = conn.next_request()
    assert_true(req1_opt.__bool__(), "expected first request")
    var req1 = req1_opt.take()
    assert_equal_str(req1.target, "/a", "first request target")
    assert_true(not conn.should_close(), "must not close on keep-alive")

    var resp1 = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=Headers(),
        body=List[BodyFrame](),
    )
    conn.send_response(resp1^)
    _ = conn.drain()

    var req2_opt = conn.next_request()
    assert_true(req2_opt.__bool__(), "expected second request")
    var req2 = req2_opt.take()
    assert_equal_str(req2.target, "/b", "second request target")
    assert_true(not conn.should_close(), "should not close after 2nd req on keep-alive")

    print("PASS: test_keep_alive_two_requests")


def test_connection_close() raises:
    """Connection: close header transitions to MUST_CLOSE."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var req = conn.next_request()
    assert_true(req.__bool__(), "expected a request")
    assert_true(conn.should_close(), "should close after Connection: close")
    assert_true(not conn.is_keep_alive(), "is_keep_alive should be false")

    print("PASS: test_connection_close")


def test_http10_close_by_default() raises:
    """HTTP/1.0 defaults to close."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
    conn.receive_data(Span(wire))

    var req = conn.next_request()
    assert_true(req.__bool__(), "expected a request")
    assert_true(conn.should_close(), "HTTP/1.0 should close by default")

    print("PASS: test_http10_close_by_default")


def test_http10_keep_alive_header() raises:
    """HTTP/1.0 with explicit Connection: keep-alive remains open."""
    var conn = H1Connection(ParseConfig())
    var wire = _str_to_bytes(
        "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
    )
    conn.receive_data(Span(wire))
    var req = conn.next_request()
    assert_true(req.__bool__(), "expected a request")
    assert_true(not conn.should_close(), "HTTP/1.0 keep-alive should not close")
    print("PASS: test_http10_keep_alive_header")


def test_content_length_body() raises:
    """Request with Content-Length body."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHello"
    )
    conn.receive_data(Span(wire))

    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected a request")
    var req = req_opt.take()
    assert_true(req.body.is_buffered(), "expected buffered body")
    assert_equal_int(len(req.body.bytes()), 5, "body length")
    print("PASS: test_content_length_body")


def test_chunked_body() raises:
    """Request with chunked Transfer-Encoding."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "POST /data HTTP/1.1\r\nHost: example.com\r\n"
        + String("Transfer-Encoding: chunked\r\n\r\n")
        + String("5\r\nHello\r\n0\r\n\r\n")
    )
    conn.receive_data(Span(wire))

    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected a request")
    var req = req_opt.take()
    assert_true(req.body.is_buffered(), "expected buffered body")
    assert_equal_int(len(req.body.bytes()), 5, "decoded chunk length")
    print("PASS: test_chunked_body")


def test_response_parsing() raises:
    """Parse a response with next_response."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    )
    conn.receive_data(Span(wire))

    var resp_opt = conn.next_response(Method.get())
    assert_true(resp_opt.__bool__(), "expected a response")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 200, "status code")
    print("PASS: test_response_parsing")


def test_head_response_no_body() raises:
    """HEAD response has no body even with Content-Length."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var resp_opt = conn.next_response(Method.head())
    assert_true(resp_opt.__bool__(), "expected a response")
    var resp = resp_opt.take()
    assert_equal_int(len(resp.body), 0, "HEAD response should have no body")
    print("PASS: test_head_response_no_body")


def test_1xx_informational() raises:
    """1xx responses returned one at a time, then final response."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 100 Continue\r\n\r\n"
        + String("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    )
    conn.receive_data(Span(wire))

    var resp1_opt = conn.next_response(Method.get())
    assert_true(resp1_opt.__bool__(), "expected 100 response")
    var resp1 = resp1_opt.take()
    assert_equal_int(Int(resp1.status.code()), 100, "status 100")
    assert_true(not conn.should_close(), "1xx must not close connection")

    var resp2_opt = conn.next_response(Method.get())
    assert_true(resp2_opt.__bool__(), "expected 200 response")
    var resp2 = resp2_opt.take()
    assert_equal_int(Int(resp2.status.code()), 200, "status 200")
    print("PASS: test_1xx_informational")


def test_send_informational() raises:
    """Send a 1xx informational response and verify the wire bytes."""
    var conn = H1Connection(ParseConfig())

    var headers = Headers()
    headers.add("Link", "</style.css>; rel=preload")
    conn.send_informational(StatusCode(103), headers^)

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 103 "),
        "expected 103 status line, got: " + out_str,
    )
    print("PASS: test_send_informational")


def test_send_request() raises:
    """Append serialized request bytes to the outbound buffer."""
    var conn = H1Connection(ParseConfig())
    var headers = Headers()
    headers.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target=String("/"),
        version=Version.http_1_1(),
        headers=headers^,
        body=RequestBody.empty(),
    )
    conn.send_request(req^)
    var out_str = _bytes_to_string(conn.drain())
    assert_true(
        _str_contains(out_str, "GET / HTTP/1.1"),
        "expected request line, got: " + out_str,
    )
    print("PASS: test_send_request")


def test_head_response_body_suppression() raises:
    """Server-side: response to HEAD request must omit body bytes on the wire."""
    var conn = H1Connection(ParseConfig())

    # Receive a HEAD request so the connection knows the in-flight method.
    var wire = _str_to_bytes(
        "HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    conn.receive_data(Span(wire))
    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected HEAD request")
    var req = req_opt.take()
    assert_true(req.method.is_head(), "expected HEAD method")

    # Build a normal response with a body. The connection must drop the body
    # bytes after serialization, while keeping the Content-Length header.
    var headers = Headers()
    headers.add("Content-Type", "text/html")
    var body_data = _str_to_bytes("<html>HELLO</html>")
    var body = List[BodyFrame]()
    body.append(BodyFrame.data(body_data^))
    var resp = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=headers^,
        body=body^,
    )
    conn.send_response(resp^)

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 200 OK"),
        "missing status line: " + out_str,
    )
    assert_true(
        _str_contains(out_str, "content-length: 18"),
        "expected content-length header to remain, got: " + out_str,
    )
    assert_true(
        not _str_contains(out_str, "HELLO"),
        "HEAD response must not contain body bytes, got: " + out_str,
    )
    # The wire must end with the header terminator, no trailing body.
    var wire_bytes = out_str.as_bytes()
    var n = len(wire_bytes)
    assert_true(n >= 4, "wire too short")
    assert_true(
        wire_bytes[n - 4] == UInt8(0x0D)
        and wire_bytes[n - 3] == UInt8(0x0A)
        and wire_bytes[n - 2] == UInt8(0x0D)
        and wire_bytes[n - 1] == UInt8(0x0A),
        "wire must end with CRLF CRLF, got: " + out_str,
    )
    print("PASS: test_head_response_body_suppression")


def test_malformed_request_error() raises:
    """Malformed request transitions the connection into an error/close state."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes("INVALID\r\n\r\n")
    conn.receive_data(Span(wire))

    var req = conn.next_request()
    assert_true(not req.__bool__(), "should not return a request on parse error")
    assert_true(conn.should_close(), "should close on parse error")
    print("PASS: test_malformed_request_error")


def test_wants_read_write() raises:
    """Verify wants_read / wants_write transitions across send_response/drain."""
    var conn = H1Connection(ParseConfig())

    assert_true(conn.wants_read(), "fresh connection should want_read")
    assert_true(not conn.wants_write(), "fresh connection should not want_write")
    assert_true(not conn.should_close(), "fresh connection should not close")
    assert_true(conn.is_keep_alive(), "HTTP/1.1 default keep-alive")

    var headers = Headers()
    var resp = Response(
        status=StatusCode(204),
        reason=String("No Content"),
        version=Version.http_1_1(),
        headers=headers^,
        body=List[BodyFrame](),
    )
    conn.send_response(resp^)
    assert_true(conn.wants_write(), "wants_write after send_response")
    _ = conn.drain()
    assert_true(not conn.wants_write(), "no wants_write after drain")
    print("PASS: test_wants_read_write")


def test_receive_data_bound() raises:
    """A peer streaming garbage that never forms a complete message must be
    bounded by the configured cap, not allowed to grow without limit."""
    var conn = H1Connection(ParseConfig())

    # Build a chunk just under max_headers_total so the first feed succeeds.
    var first = List[UInt8]()
    var first_len = 60000
    for _ in range(first_len):
        first.append(UInt8(ord("A")))
    conn.receive_data(Span(first))
    var req_opt = conn.next_request()
    assert_true(not req_opt.__bool__(), "garbage must not parse as a request")

    # Now flood with bytes well past max_body_size + max_headers_total.
    # Default config: max_body_size=10MiB + max_headers_total=64KiB.
    # Feeding ~12 MiB in one shot must raise.
    var huge = List[UInt8]()
    var huge_len = 12 * 1024 * 1024
    for _ in range(huge_len):
        huge.append(UInt8(ord("B")))

    var raised = False
    try:
        conn.receive_data(Span(huge))
    except e:
        raised = True
    assert_true(raised, "receive_data must raise when cap is exceeded")
    print("PASS: test_receive_data_bound")


def test_connect_upgrade() raises:
    """A 2xx response to a CONNECT request flips the connection to UPGRADED."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected a CONNECT request")
    var req = req_opt.take()
    assert_true(req.method.is_connect(), "expected CONNECT method")

    var resp = Response(
        status=StatusCode(200),
        reason=String("Connection Established"),
        version=Version.http_1_1(),
        headers=Headers(),
        body=List[BodyFrame](),
    )
    conn.send_response(resp^)

    # On the server side a successful CONNECT means the HTTP layer is done:
    # subsequent bytes are tunneled. We model that as should_close() == True
    # since UPGRADED implies "no more HTTP framing on this connection".
    assert_true(
        conn.should_close() or not conn.wants_read(),
        "after CONNECT 2xx the connection must not want more HTTP reads",
    )
    print("PASS: test_connect_upgrade")


def test_101_switching_protocols() raises:
    """A client receiving 101 transitions into the UPGRADED phase."""
    var conn = H1Connection(ParseConfig())

    var headers = Headers()
    headers.add("Host", "example.com")
    headers.add("Upgrade", "websocket")
    headers.add("Connection", "Upgrade")
    var req = Request(
        method=Method.get(),
        target=String("/chat"),
        version=Version.http_1_1(),
        headers=headers^,
        body=RequestBody.empty(),
    )
    conn.send_request(req^)
    _ = conn.drain()

    var wire = _str_to_bytes(
        "HTTP/1.1 101 Switching Protocols\r\n"
        + String("Upgrade: websocket\r\n")
        + String("Connection: Upgrade\r\n\r\n")
    )
    conn.receive_data(Span(wire))

    var resp_opt = conn.next_response(Method.get())
    assert_true(resp_opt.__bool__(), "expected 101 response")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 101, "status 101")
    assert_true(
        conn.should_close(),
        "should_close() must be True after upgrade (no more HTTP framing)",
    )
    print("PASS: test_101_switching_protocols")


def test_head_response_chunked_suppression() raises:
    """HEAD response with chunked body must drop chunk frames after headers."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "HEAD /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    conn.receive_data(Span(wire))
    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected HEAD request")
    var req = req_opt.take()
    assert_true(req.method.is_head(), "expected HEAD")

    var headers = Headers()
    headers.add("Transfer-Encoding", "chunked")

    var body = List[BodyFrame]()
    var chunk = _str_to_bytes("Hello, world")
    body.append(BodyFrame.data(chunk^))
    body.append(BodyFrame.trailers(Headers()))

    var resp = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=headers^,
        body=body^,
    )
    conn.send_response(resp^)

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 200 OK"),
        "missing status line: " + out_str,
    )
    assert_true(
        not _str_contains(out_str, "Hello, world"),
        "HEAD response must not contain body bytes, got: " + out_str,
    )
    var wire_bytes = out_str.as_bytes()
    var n = len(wire_bytes)
    assert_true(n >= 4, "wire too short")
    assert_true(
        wire_bytes[n - 4] == UInt8(0x0D)
        and wire_bytes[n - 3] == UInt8(0x0A)
        and wire_bytes[n - 2] == UInt8(0x0D)
        and wire_bytes[n - 1] == UInt8(0x0A),
        "wire must end with CRLF CRLF, got: " + out_str,
    )
    print("PASS: test_head_response_chunked_suppression")


def test_head_response_empty_body() raises:
    """HEAD response with Content-Length: 0 and empty body — wire stays clean."""
    var conn = H1Connection(ParseConfig())

    var wire = _str_to_bytes(
        "HEAD /empty HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    conn.receive_data(Span(wire))
    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected HEAD request")
    var req = req_opt.take()
    assert_true(req.method.is_head(), "expected HEAD")

    var headers = Headers()
    headers.add("Content-Length", "0")
    var resp = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=headers^,
        body=List[BodyFrame](),
    )
    conn.send_response(resp^)

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 200 OK"),
        "missing status line: " + out_str,
    )
    assert_true(
        _str_contains(out_str, "content-length: 0"),
        "expected Content-Length: 0, got: " + out_str,
    )
    var wire_bytes = out_str.as_bytes()
    var n = len(wire_bytes)
    assert_true(n >= 4, "wire too short")
    assert_true(
        wire_bytes[n - 4] == UInt8(0x0D)
        and wire_bytes[n - 3] == UInt8(0x0A)
        and wire_bytes[n - 2] == UInt8(0x0D)
        and wire_bytes[n - 1] == UInt8(0x0A),
        "wire must end with CRLF CRLF, got: " + out_str,
    )
    print("PASS: test_head_response_empty_body")


def main() raises:
    test_basic_request_response_cycle()
    test_incremental_feeding()
    test_keep_alive_two_requests()
    test_connection_close()
    test_http10_close_by_default()
    test_http10_keep_alive_header()
    test_content_length_body()
    test_chunked_body()
    test_response_parsing()
    test_head_response_no_body()
    test_1xx_informational()
    test_send_informational()
    test_send_request()
    test_head_response_body_suppression()
    test_malformed_request_error()
    test_wants_read_write()
    test_receive_data_bound()
    test_connect_upgrade()
    test_101_switching_protocols()
    test_head_response_chunked_suppression()
    test_head_response_empty_body()
    print("\nAll H1Connection tests passed!")
