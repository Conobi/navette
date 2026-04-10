# tests/test_h2_session.mojo
#
# Tests for H2Session (M5.5 Tasks 8-9).

from std.collections.deque import Deque
from std.memory import Span

from lib.http1.types import Header
from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
)
from src.http.handler import Capabilities, ALPN_H2
from src.http.session import Session, RequestHandle
from src.http.request import Request, RequestBody
from src.http.method import Method
from src.http.version import Version
from src.http.headers import Headers
from src.h2.h2_session import H2Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _do_preface_exchange(
    mut session: H2Session, mut server: H2Connection
) raises:
    """Perform the HTTP/2 preface exchange between client session and server."""
    # Drain client preface (magic + SETTINGS)
    var client_preface = session.drain()

    # Feed client preface to server, get server SETTINGS + ACK
    _ = server.receive_data(client_preface)
    var server_resp = server.data_to_send()

    # Feed server response to client session
    session.feed(Span(server_resp))

    # Drain client SETTINGS ACK and feed to server
    var client_ack = session.drain()
    if len(client_ack) > 0:
        _ = server.receive_data(client_ack)
        _ = server.data_to_send()


# ---------------------------------------------------------------------------
# test_construction_and_preface
# ---------------------------------------------------------------------------


def test_construction_and_preface() raises:
    """Construct H2Session, drain output. Verify non-empty (client connection
    preface: magic + SETTINGS frame)."""
    var session = H2Session()
    var data = session.drain()
    # The HTTP/2 client connection preface is 24 bytes of magic followed by
    # at least one SETTINGS frame (9 byte header + payload).  Total must be
    # non-empty.
    if len(data) == 0:
        raise Error("drain after construction must produce client preface")
    # The first 24 bytes should be the HTTP/2 connection preface magic.
    # PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    if len(data) < 24:
        raise Error(
            "preface must be at least 24 bytes, got " + String(len(data))
        )
    var magic = String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    var magic_bytes = magic.as_bytes()
    for i in range(24):
        if data[i] != magic_bytes[i]:
            raise Error("preface byte mismatch at index " + String(i))
    _ = session^
    print("PASS test_construction_and_preface")


# ---------------------------------------------------------------------------
# test_capabilities
# ---------------------------------------------------------------------------


def test_capabilities() raises:
    """Verify capabilities() returns for_h2 and alpn() returns ALPN_H2."""
    var session = H2Session()
    var caps = session.capabilities()
    if not caps.multiplexed:
        raise Error("H2 must be multiplexed")
    if not caps.trailers:
        raise Error("H2 must support trailers")
    if caps.alpn != ALPN_H2:
        raise Error("capabilities.alpn must be ALPN_H2")
    if session.alpn() != ALPN_H2:
        raise Error("alpn() must return ALPN_H2")
    _ = session^
    print("PASS test_capabilities")


# ---------------------------------------------------------------------------
# test_close
# ---------------------------------------------------------------------------


def test_close() raises:
    """Verify close() does not raise on a freshly constructed session."""
    var session = H2Session()
    # Drain the preface bytes first so we have a clean outbuf
    _ = session.drain()
    session^.close()
    print("PASS test_close")


# ---------------------------------------------------------------------------
# test_drain_idempotent
# ---------------------------------------------------------------------------


def test_drain_idempotent() raises:
    """Verify drain() returns empty after draining once."""
    var session = H2Session()
    _ = session.drain()
    var second = session.drain()
    if len(second) != 0:
        raise Error(
            "second drain must be empty, got " + String(len(second)) + " bytes"
        )
    _ = session^
    print("PASS test_drain_idempotent")


# ---------------------------------------------------------------------------
# test_submit_get
# ---------------------------------------------------------------------------


def test_submit_get() raises:
    """Create H2Session, submit a GET request, drain output, feed to a server
    H2Connection. Verify server sees RequestReceived with GET method."""
    var session = H2Session()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()  # drain server initial SETTINGS

    _do_preface_exchange(session, server)

    # Submit a GET request
    var headers = Headers()
    headers.add("host", "localhost")
    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_2(),
        headers=headers^,
    )
    var handle = session.submit(req^)

    # Drain the request bytes and feed to server
    var req_data = session.drain()
    if len(req_data) == 0:
        raise Error("expected non-empty request data after submit")

    var events = server.receive_data(req_data)
    _ = server.data_to_send()

    # Find the REQUEST_RECEIVED event
    var found = False
    for i in range(len(events)):
        if events[i].kind == H2_EVT_REQUEST_RECEIVED:
            found = True
            # Check that :method is GET
            var got_method = String("")
            for j in range(len(events[i].headers)):
                if events[i].headers[j].name == ":method":
                    got_method = events[i].headers[j].value
            if got_method != "GET":
                raise Error(
                    "expected :method GET, got '" + got_method + "'"
                )
            # Check that :path is /
            var got_path = String("")
            for j in range(len(events[i].headers)):
                if events[i].headers[j].name == ":path":
                    got_path = events[i].headers[j].value
            if got_path != "/":
                raise Error(
                    "expected :path /, got '" + got_path + "'"
                )

    if not found:
        raise Error("no REQUEST_RECEIVED event found")

    _ = handle^
    _ = session^
    print("PASS test_submit_get")


# ---------------------------------------------------------------------------
# test_receive_response
# ---------------------------------------------------------------------------


def test_receive_response() raises:
    """Submit GET, get server-side response (send_headers with :status 200,
    send_data with body). Feed server output to session. Call run_one on
    handle. Verify handle has response with status 200."""
    var session = H2Session()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()

    _do_preface_exchange(session, server)

    # Submit a GET request
    var headers = Headers()
    headers.add("host", "localhost")
    var req = Request(
        method=Method.get(),
        target="/",
        version=Version.http_2(),
        headers=headers^,
    )
    var handle = session.submit(req^)

    # Drain request and feed to server
    var req_data = session.drain()
    _ = server.receive_data(req_data)
    _ = server.data_to_send()

    # Server sends response headers + body
    var resp_headers = List[Header]()
    resp_headers.append(Header(":status", "200"))
    resp_headers.append(Header("content-type", "text/plain"))
    server.send_headers(UInt32(1), resp_headers^, end_stream=False)

    var body_bytes = List[UInt8]()
    var hello = String("hello")
    for i in range(len(hello.as_bytes())):
        body_bytes.append(hello.as_bytes()[i])
    server.send_data(UInt32(1), body_bytes, end_stream=True)

    # Get server output and feed to session
    var server_output = server.data_to_send()
    session.feed(Span(server_output))
    _ = session.drain()  # drain any ACKs etc

    # run_one to deliver response to handle
    session.run_one(handle)

    # Verify
    if not handle.has_headers():
        raise Error("expected handle to have headers after run_one")
    if not handle.is_complete():
        raise Error("expected handle to be complete")

    var resp = handle^.take_response()
    if Int(resp.status.code()) != 200:
        raise Error(
            "expected status 200, got " + String(Int(resp.status.code()))
        )

    # Check body
    if len(resp.body) == 0:
        raise Error("expected body frames")
    if not resp.body[0].is_data():
        raise Error("expected first body frame to be data")
    var body_str = String("")
    for i in range(len(resp.body[0].data())):
        body_str += chr(Int(resp.body[0].data()[i]))
    if body_str != "hello":
        raise Error("expected body 'hello', got '" + body_str + "'")

    _ = session^
    print("PASS test_receive_response")


# ---------------------------------------------------------------------------
# test_multiple_inflight
# ---------------------------------------------------------------------------


def test_multiple_inflight() raises:
    """Submit two GETs. Generate server responses for both (different bodies).
    Feed to session. run_one both. Verify both handles populated correctly."""
    var session = H2Session()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.data_to_send()

    _do_preface_exchange(session, server)

    # Submit two GET requests
    var h1 = Headers()
    h1.add("host", "localhost")
    var req1 = Request(
        method=Method.get(),
        target="/a",
        version=Version.http_2(),
        headers=h1^,
    )
    var handle1 = session.submit(req1^)

    var h2 = Headers()
    h2.add("host", "localhost")
    var req2 = Request(
        method=Method.get(),
        target="/b",
        version=Version.http_2(),
        headers=h2^,
    )
    var handle2 = session.submit(req2^)

    # Drain and feed requests to server
    var req_data = session.drain()
    _ = server.receive_data(req_data)
    _ = server.data_to_send()

    # Server responds to stream 1
    var rh1 = List[Header]()
    rh1.append(Header(":status", "200"))
    server.send_headers(UInt32(1), rh1^, end_stream=False)
    var b1 = List[UInt8]()
    var s1 = String("body-a")
    for i in range(len(s1.as_bytes())):
        b1.append(s1.as_bytes()[i])
    server.send_data(UInt32(1), b1, end_stream=True)

    # Server responds to stream 3
    var rh2 = List[Header]()
    rh2.append(Header(":status", "201"))
    server.send_headers(UInt32(3), rh2^, end_stream=False)
    var b2 = List[UInt8]()
    var s2 = String("body-b")
    for i in range(len(s2.as_bytes())):
        b2.append(s2.as_bytes()[i])
    server.send_data(UInt32(3), b2, end_stream=True)

    # Feed all server output to session
    var server_output = server.data_to_send()
    session.feed(Span(server_output))
    _ = session.drain()

    # Run both handles
    session.run_one(handle1)
    session.run_one(handle2)

    # Verify handle1
    if not handle1.has_headers():
        raise Error("handle1 should have headers")
    if not handle1.is_complete():
        raise Error("handle1 should be complete")

    # Verify handle2
    if not handle2.has_headers():
        raise Error("handle2 should have headers")
    if not handle2.is_complete():
        raise Error("handle2 should be complete")

    # Check responses
    var resp1 = handle1^.take_response()
    if Int(resp1.status.code()) != 200:
        raise Error(
            "expected handle1 status 200, got "
            + String(Int(resp1.status.code()))
        )
    if len(resp1.body) == 0:
        raise Error("expected handle1 body")
    var body1_str = String("")
    for i in range(len(resp1.body[0].data())):
        body1_str += chr(Int(resp1.body[0].data()[i]))
    if body1_str != "body-a":
        raise Error("expected body 'body-a', got '" + body1_str + "'")

    var resp2 = handle2^.take_response()
    if Int(resp2.status.code()) != 201:
        raise Error(
            "expected handle2 status 201, got "
            + String(Int(resp2.status.code()))
        )
    if len(resp2.body) == 0:
        raise Error("expected handle2 body")
    var body2_str = String("")
    for i in range(len(resp2.body[0].data())):
        body2_str += chr(Int(resp2.body[0].data()[i]))
    if body2_str != "body-b":
        raise Error("expected body 'body-b', got '" + body2_str + "'")

    _ = session^
    print("PASS test_multiple_inflight")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    print("test_h2_session")
    test_construction_and_preface()
    test_capabilities()
    test_close()
    test_drain_idempotent()
    test_submit_get()
    test_receive_response()
    test_multiple_inflight()
    print("PASS")
