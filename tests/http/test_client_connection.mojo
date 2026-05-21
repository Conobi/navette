# tests/test_client_connection.mojo
#
# Unit tests for ClientConnection (src/h1/client.mojo).

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
from navette.h1 import ParseConfig
from navette.h1.client import ClientConnection
from navette.http.request import RequestBody
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


def test_client_basic_flow() raises:
    """ClientConnection: send GET request, drain wire, receive 200 response."""
    var conn = ClientConnection(ParseConfig())

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
    assert_true(conn.wants_write(), "expected wants_write after send_request")

    var out = conn.drain()
    var out_str = _bytes_to_string(out)
    assert_true(_str_contains(out_str, "GET / HTTP/1.1"), "missing request line")
    assert_true(not conn.wants_write(), "wants_write should be false after drain")

    var wire = _str_to_bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    conn.receive_data(Span(wire))

    var resp_opt = conn.next_response(Method.get())
    assert_true(resp_opt.__bool__(), "expected a response")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 200, "status code")
    print("PASS: test_client_basic_flow")


def test_client_keep_alive_two_responses() raises:
    """ClientConnection: parse two pipelined responses."""
    var conn = ClientConnection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        + String("HTTP/1.1 204 No Content\r\n\r\n")
    )
    conn.receive_data(Span(wire))

    var r1_opt = conn.next_response(Method.get())
    assert_true(r1_opt.__bool__(), "expected first response")
    var r1 = r1_opt.take()
    assert_equal_int(Int(r1.status.code()), 200, "first status")
    assert_true(not conn.should_close(), "must not close on keep-alive")

    var r2_opt = conn.next_response(Method.get())
    assert_true(r2_opt.__bool__(), "expected second response")
    var r2 = r2_opt.take()
    assert_equal_int(Int(r2.status.code()), 204, "second status")
    print("PASS: test_client_keep_alive_two_responses")


def test_client_head_response_no_body() raises:
    """ClientConnection: HEAD response framing — no body even with Content-Length."""
    var conn = ClientConnection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var resp_opt = conn.next_response(Method.head())
    assert_true(resp_opt.__bool__(), "expected a response")
    var resp = resp_opt.take()
    assert_equal_int(Int(resp.status.code()), 200, "HEAD response status")
    print("PASS: test_client_head_response_no_body")


def test_client_must_close_after_connection_close() raises:
    """ClientConnection: Connection: close response transitions to MUST_CLOSE."""
    var conn = ClientConnection(ParseConfig())

    var wire = _str_to_bytes(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    conn.receive_data(Span(wire))

    var resp = conn.next_response(Method.get())
    assert_true(resp.__bool__(), "expected a response")
    assert_true(conn.should_close(), "should close after Connection: close")
    assert_true(not conn.is_keep_alive(), "is_keep_alive should be false")
    print("PASS: test_client_must_close_after_connection_close")


def test_client_state_transitions() raises:
    """ClientConnection: wants_read / wants_write transitions."""
    var conn = ClientConnection(ParseConfig())

    assert_true(conn.wants_read(), "fresh client should want_read")
    assert_true(not conn.wants_write(), "fresh client should not want_write")
    assert_true(not conn.should_close(), "fresh client should not be closed")
    assert_true(conn.is_keep_alive(), "HTTP/1.1 default keep-alive")

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
    assert_true(conn.wants_write(), "should want_write after send_request")

    _ = conn.drain()
    assert_true(not conn.wants_write(), "wants_write should be false after drain")
    print("PASS: test_client_state_transitions")


def main() raises:
    test_client_basic_flow()
    test_client_keep_alive_two_responses()
    test_client_head_response_no_body()
    test_client_must_close_after_connection_close()
    test_client_state_transitions()
    print("\nAll ClientConnection tests passed!")
