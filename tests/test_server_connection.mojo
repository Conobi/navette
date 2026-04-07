# tests/test_server_connection.mojo
#
# Unit tests for ServerConnection (src/h1/server.mojo).

from std.collections.optional import Optional
from std.memory import Span

from src.http import (
    Method,
    StatusCode,
    Version,
    Headers,
    BodyFrame,
    Request,
    Response,
)
from src.h1 import ParseConfig
from src.h1.server import ServerConnection
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


# --- Helpers ---


def _str_to_bytes(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var result = List[UInt8]()
    for i in range(len(b)):
        result.append(b[i])
    return result^


def _bytes_to_string(data: List[UInt8]) -> String:
    var result = String()
    for i in range(len(data)):
        result += chr(Int(data[i]))
    return result^


def _str_contains(haystack: String, needle: String) -> Bool:
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


def test_server_basic_flow() raises:
    """ServerConnection: receive a GET request, send a 200 response, drain bytes."""
    var conn = ServerConnection(ParseConfig())

    var wire = _str_to_bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    conn.receive_data(Span(wire))

    var req_opt = conn.next_request()
    assert_true(req_opt.__bool__(), "expected a request")
    var req = req_opt.take()
    assert_true(req.method.is_get(), "expected GET")
    assert_equal_str(req.target, "/", "request target")

    var resp = Response(
        status=StatusCode(200),
        reason=String("OK"),
        version=Version.http_1_1(),
        headers=Headers(),
        body=List[BodyFrame](),
    )
    conn.send_response(resp^)
    assert_true(conn.wants_write(), "expected wants_write after send_response")

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(
        _str_contains(out_str, "HTTP/1.1 200 OK"),
        "missing status line",
    )
    assert_true(not conn.wants_write(), "wants_write should be false after drain")
    print("PASS: test_server_basic_flow")


def test_server_keep_alive_two_requests() raises:
    """ServerConnection: two requests on the same persistent connection."""
    var conn = ServerConnection(ParseConfig())

    var wire = _str_to_bytes(
        "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
        + String("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    conn.receive_data(Span(wire))

    var r1_opt = conn.next_request()
    assert_true(r1_opt.__bool__(), "expected first request")
    var r1 = r1_opt.take()
    assert_equal_str(r1.target, "/a", "first request target")
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

    var r2_opt = conn.next_request()
    assert_true(r2_opt.__bool__(), "expected second request")
    var r2 = r2_opt.take()
    assert_equal_str(r2.target, "/b", "second request target")
    assert_true(conn.is_keep_alive(), "still keep-alive")

    print("PASS: test_server_keep_alive_two_requests")


def test_server_send_informational() raises:
    """ServerConnection: send 103 Early Hints."""
    var conn = ServerConnection(ParseConfig())
    var headers = Headers()
    headers.add("Link", "</style.css>; rel=preload")
    conn.send_informational(StatusCode(103), headers^)

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(_str_contains(out_str, "103"), "missing 103 status")
    assert_true(_str_contains(out_str, "link"), "missing Link header")
    print("PASS: test_server_send_informational")


def test_server_must_close_after_connection_close() raises:
    """ServerConnection: Connection: close in request transitions to MUST_CLOSE."""
    var conn = ServerConnection(ParseConfig())

    var wire = _str_to_bytes(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var req = conn.next_request()
    assert_true(req.__bool__(), "expected a request")
    assert_true(conn.should_close(), "should close after Connection: close")
    assert_true(not conn.is_keep_alive(), "is_keep_alive should be false")
    print("PASS: test_server_must_close_after_connection_close")


def test_server_state_transitions() raises:
    """ServerConnection: wants_read / wants_write transitions."""
    var conn = ServerConnection(ParseConfig())

    assert_true(conn.wants_read(), "fresh server should want_read")
    assert_true(not conn.wants_write(), "fresh server should not want_write")
    assert_true(not conn.should_close(), "fresh server should not be closed")
    assert_true(conn.is_keep_alive(), "HTTP/1.1 default keep-alive")

    var wire = _str_to_bytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    conn.receive_data(Span(wire))
    var req = conn.next_request()
    assert_true(req.__bool__(), "expected a request")

    var resp = Response(
        status=StatusCode(204),
        reason=String("No Content"),
        version=Version.http_1_1(),
        headers=Headers(),
        body=List[BodyFrame](),
    )
    conn.send_response(resp^)
    assert_true(conn.wants_write(), "should want_write after send_response")

    _ = conn.drain()
    assert_true(not conn.wants_write(), "wants_write should be false after drain")
    print("PASS: test_server_state_transitions")


def main() raises:
    test_server_basic_flow()
    test_server_keep_alive_two_requests()
    test_server_send_informational()
    test_server_must_close_after_connection_close()
    test_server_state_transitions()
    print("\nAll ServerConnection tests passed!")
