# tests/h1/test_h1_eof.mojo
"""End-of-stream contract of the H1 client: framing at EOF, ordering, reuse,
reset-is-not-EOF and session errors."""
from std.collections import Span
from navette.h1.h1_session import H1Session
from navette.http.request import Request
from navette.http.method import Method
from navette.http.headers import Headers
from navette.http.session import RequestHandle
from navette.http.session_slot import SessionSlot
from navette.http.handler import STREAM_ERR_PARSER, STREAM_ERR_CONNECTION_CLOSED
from navette.h1.parser import try_parse_response
from navette.h1.config import ParseConfig, ParserStrictness
from navette.h1.connection import H1Connection
from navette.http.client import HttpClient
from navette.http.coro_client import HttpCoroClient
from navette.http.handler import DetachedBody, RecvBody
from navette.http.request import RequestBody
from navette.http.body import BodyFrame
from navette.http.version import Version
from navette.http.alt_svc import Origin
from tests._test_util import assert_true, assert_equal_int, assert_equal_str


def _get(mut s: H1Session) raises -> RequestHandle:
    var h = Headers()
    h.add("Host", "example.test")
    var handle = s.submit(Request(method=Method.get(), target="/", headers=h^))
    _ = s.drain()
    return handle^


def _run_eof(wire: String) raises -> RequestHandle:
    """Submit, feed `wire`, feed EOF, run once."""
    var s = H1Session()
    var handle = _get(s)
    if wire.byte_length() > 0:
        s.feed(wire.as_bytes())
    s.feed_eof()
    s.run_one(handle)
    return handle^


def _body(var handle: RequestHandle) raises -> String:
    var resp = handle^.take_response()
    var out = String()
    for i in range(len(resp.body)):
        if resp.body[i].is_data():
            out += String(StringSlice(unsafe_from_utf8=Span(resp.body[i].data())))
    return out^


def test_eof_framing_matrix() raises:
    var h = _run_eof("HTTP/1.1 200 OK\r\n\r\nhello")
    assert_true(h.is_complete() and not h.is_errored(), "close-delimited completes at EOF")
    assert_true(_body(h^) == "hello", "close-delimited body intact")
    var cl_ok = _run_eof("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    assert_true(cl_ok.is_complete() and not cl_ok.is_errored(), "complete Content-Length body")
    var garbage = String("garbage\r\n\r\n")
    var garbage_buf = List[Byte]()
    garbage_buf.extend(garbage.as_bytes())
    var parsed = try_parse_response(garbage_buf, 0, 0, Method.get(), ParseConfig())
    assert_true(parsed.error.byte_length() > 0, "garbage must be a parse error")
    var rows: List[String] = [
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
        "HTTP/1.1 200 OK\r\nX-Partial: y",
        garbage,
    ]
    var messages: List[String] = [
        "body truncated: expected 10, got 5",
        "chunked body truncated",
        "response truncated in headers",
        parsed.error,
    ]
    for i in range(len(rows)):
        var label = "row " + String(i)
        var e = _run_eof(rows[i])
        assert_true(e.is_errored(), label + " must error at EOF")
        assert_equal_int(e._error.value().kind, STREAM_ERR_PARSER, label + " parser error")
        assert_equal_str(e._error.value().message, messages[i], label + " message")
    var lone_crlf = _run_eof("\r\n")
    assert_true(lone_crlf.is_errored(), "leading empty line only: nothing received")
    assert_equal_int(lone_crlf._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "connection_closed")


def test_interim_then_eof_is_connection_closed() raises:
    """A 1xx is not a final response, so EOF after it is "nothing received"."""
    var e = _run_eof("HTTP/1.1 100 Continue\r\n\r\n")
    assert_true(e.is_errored(), "EOF after 100 Continue must error")
    assert_equal_int(e._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "connection_closed")


def test_receive_data_after_eof_raises() raises:
    var s = H1Session()
    _ = _get(s)
    s.feed_eof()
    var raised = False
    try:
        s.feed(String("HTTP/1.1 200 OK\r\n\r\n").as_bytes())
    except e:
        raised = "data after EOF" in String(e)
    assert_true(raised, "feed after feed_eof must raise")


def test_submit_after_eof_raises() raises:
    var slot = SessionSlot.from_h1(H1Session())
    slot.feed_eof()
    var h = Headers()
    h.add("Host", "example.test")
    var raised = False
    try:
        _ = slot.submit(Request(method=Method.get(), target="/", headers=h^))
    except e:
        raised = "session closed" in String(e)
    assert_true(raised, "submit after EOF must raise through SessionSlot.submit")


def test_reset_is_not_eof() raises:
    """Without feed_eof (a reset), a partial close-delimited body never completes."""
    var s = H1Session()
    var handle = _get(s)
    s.feed(String("HTTP/1.1 200 OK\r\n\r\nhel").as_bytes())
    s.run_one(handle)
    assert_true(not handle.is_complete(), "no EOF fed: response stays incomplete")


def test_h1_session_errored_and_closed_before_response() raises:
    var handle = _run_eof("")
    assert_true(handle.is_complete(), "errored handle counts as complete (no hang)")
    assert_true(handle.is_errored(), "closed before response must error")
    assert_equal_int(handle._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "closed before response")


def test_empty_lines_then_eof_is_nothing_received() raises:
    """CR/LF-only input before any status line is "nothing received" at EOF."""
    var crlf = _run_eof("\r\n\r\n")
    assert_true(crlf.is_errored(), "CRLFCRLF then EOF must error")
    assert_equal_int(crlf._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "CRLFCRLF: connection_closed")
    var lf = String("\n\n")
    var lf_buf = List[Byte]()
    lf_buf.extend(lf.as_bytes())
    var cfg = ParseConfig(strictness=ParserStrictness(allow_bare_lf=True))
    var r = try_parse_response(lf_buf, 0, 0, Method.get(), cfg, peer_closed=True)
    assert_true(r.error.byte_length() == 0 and not r.has_response(), "bare LF lines then EOF: nothing received")


def test_interim_responses() raises:
    """100 Continue is skipped for the final 200; 101 completes the request."""
    var h = _run_eof("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    assert_true(h.is_complete() and not h.is_errored(), "100 then 200 completes")
    var resp = h^.take_response()
    assert_equal_int(Int(resp.status.code()), 200, "final status after 100")
    var up = _run_eof("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n")
    assert_true(up.is_complete() and not up.is_errored(), "101 completes")
    var up_resp = up^.take_response()
    assert_equal_int(Int(up_resp.status.code()), 101, "101 is not skipped")


def test_non_chunked_te_is_close_delimited() raises:
    var wire = String("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc")
    var buf = List[Byte]()
    buf.extend(wire.as_bytes())
    var cfg = ParseConfig(strictness=ParserStrictness(allow_non_chunked_te=True))
    var before = try_parse_response(buf, 0, 0, Method.get(), cfg)
    assert_true(before.error.byte_length() == 0 and not before.has_response(), "non-chunked TE incomplete before EOF")
    var at = try_parse_response(buf, 0, 0, Method.get(), cfg, peer_closed=True)
    assert_true(at.has_response(), "non-chunked TE completes at EOF")
    assert_equal_int(at.bytes_consumed, wire.byte_length(), "consumes the whole stream")


def test_stale_handle_does_not_steal_error() raises:
    var s = H1Session()
    var handle = _get(s)
    var stale = RequestHandle(id=handle.id() + 1)
    s.feed_eof()
    var raised = False
    try:
        s.run_one(stale)
    except:
        raised = True
    assert_true(raised and not stale.is_complete(), "foreign handle raises, untouched")
    s.run_one(handle)
    assert_true(handle.is_errored(), "pending handle still gets the EOF error")


def test_http_client_replaces_closed_slot() raises:
    """A pooled H1 slot whose peer closed is evicted on the next submit."""
    var client = HttpClient()
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = Headers()
    h.add("Host", "example.test")
    var handle = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h.copy()))
    var p = client._pool[origin][0].ptr()
    _ = p[].drain()
    p[].feed(String("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").as_bytes())
    p[].feed_eof()
    client.run_one(Origin(copy=origin), handle)
    assert_true(handle.is_complete() and not handle.is_errored(), "response before EOF completes")
    var raised = False
    try:
        _ = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h.copy()))
    except e:
        raised = "no available connection" in String(e)
    assert_true(raised, "closed slot evicted: caller must attach a fresh one")
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var fresh = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h.copy()))
    assert_true(not fresh.is_complete(), "fresh slot accepts the request")
    assert_equal_int(len(client._pool[origin]), 1, "only the fresh slot is pooled")


def _client_get(mut client: HttpClient, origin: Origin, wire: String) raises -> RequestHandle:
    """Submit a GET through `client`, answer it with `wire`, run once."""
    var h = Headers()
    h.add("Host", "example.test")
    var handle = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h^))
    var p = client._pool[origin][0].ptr()
    _ = p[].drain()
    p[].feed(wire.as_bytes())
    client.run_one(Origin(copy=origin), handle)
    return handle^


def _submit_raises(mut client: HttpClient, origin: Origin) -> Bool:
    var h = Headers()
    h.add("Host", "example.test")
    try:
        _ = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h^))
    except e:
        return "no available connection" in String(e)
    return False


def test_unusable_h1_slot_not_reused() raises:
    """A parse error or a Connection: close response retires the slot before FIN."""
    var s = H1Session()
    var handle = _get(s)
    s.feed(String("garbage\r\n\r\n").as_bytes())
    s.run_one(handle)
    assert_true(handle.is_errored(), "parse error errors the handle")
    var h = Headers()
    h.add("Host", "example.test")
    var raised = False
    try:
        _ = s.submit(Request(method=Method.get(), target="/", headers=h^))
    except e:
        raised = "session closed" in String(e)
    assert_true(raised and len(s.drain()) == 0, "submit after a parse error raises and writes nothing")
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var wires: List[String] = [
        "garbage\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    ]
    for i in range(len(wires)):
        var client = HttpClient()
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
        var done = _client_get(client, origin, wires[i])
        assert_true(done.is_complete(), "case " + String(i) + " finishes")
        assert_true(_submit_raises(client, origin), "case " + String(i) + ": slot evicted, submit raises")


def test_unpolled_handle_does_not_pin_closed_slot() raises:
    var client = HttpClient()
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = Headers()
    h.add("Host", "example.test")
    var handle = client.submit(Origin(copy=origin), Request(method=Method.get(), target="/", headers=h^))
    client._pool[origin][0].ptr()[].feed_eof()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    assert_equal_int(len(client._pool[origin]), 1, "closed slot evicted despite an unpolled handle")
    client.run_one(Origin(copy=origin), handle)
    assert_true(handle.is_errored(), "dropped handle errors")
    assert_equal_int(handle._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "dropped handle: connection_closed")


def _req(close: Bool = False, stream: Bool = False) -> Request:
    var h = Headers()
    h.add("Host", "example.test")
    if close:
        h.add("Connection", "close")
    if stream:
        return Request(method=Method.post(), target="/", headers=h^,
                       body=RequestBody.stream(DetachedBody(take_body=RecvBody())))
    return Request(method=Method.get(), target="/", headers=h^)


def _answer(mut client: HttpClient, origin: Origin, slot: Int, wire: String) raises:
    var p = client._pool[origin][slot].ptr()
    _ = p[].drain()
    p[].feed(wire.as_bytes())


def _ok(body: String) -> String:
    return "HTTP/1.1 200 OK\r\nContent-Length: " + String(body.byte_length()) + "\r\n\r\n" + body


def test_ids_not_crossed_after_eviction() raises:
    """A handle dropped with its slot never receives the next slot's response."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    for order in range(2):
        var client = HttpClient()
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
        var old = client.submit(Origin(copy=origin), _req())
        client._pool[origin][0].ptr()[].feed_eof()
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
        var fresh = client.submit(Origin(copy=origin), _req())
        assert_true(old.id() != fresh.id(), "client-wide ids differ")
        _answer(client, origin, 0, _ok("new"))
        if order == 0:
            client.run_one(Origin(copy=origin), fresh)
            client.run_one(Origin(copy=origin), old)
        else:
            client.run_one(Origin(copy=origin), old)
            client.run_one(Origin(copy=origin), fresh)
        assert_true(old.is_errored(), "dropped handle errors (order " + String(order) + ")")
        assert_equal_int(old._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "dropped: connection_closed")
        assert_true(fresh.is_complete() and not fresh.is_errored(), "new handle completes")
        assert_true(_body(fresh^) == "new", "new handle gets its own response")


def test_one_live_slot_per_origin() raises:
    """Attaching behind a live slot raises; after it closes, attach succeeds."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var a = client.submit(Origin(copy=origin), _req())
    var raised = False
    try:
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    except e:
        raised = "already has a live connection" in String(e)
    assert_true(raised, "attach behind a live slot raises")
    var busy = False
    try:
        _ = client.submit(Origin(copy=origin), _req())
    except e:
        busy = "in-flight" in String(e)
    assert_true(busy, "busy slot raises on a second submit")
    _answer(client, origin, 0, _ok("a"))
    client.run_one(Origin(copy=origin), a)
    var c = client.submit(Origin(copy=origin), _req())
    _answer(client, origin, 0, _ok("c"))
    client.run_one(Origin(copy=origin), c)
    assert_true(_body(a^) == "a" and _body(c^) == "c", "each handle gets its own response")
    client._pool[origin][0].ptr()[].feed_eof()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    assert_equal_int(len(client._pool[origin]), 1, "closed slot replaced")


def _req_conn(var values: List[String], v10: Bool = False) -> Request:
    var h = Headers()
    h.add("Host", "example.test")
    for i in range(len(values)):
        h.add("Connection", values[i])
    if v10:
        return Request(method=Method.get(), target="/", version=Version.http_1_0(), headers=h^)
    return Request(method=Method.get(), target="/", headers=h^)


def test_connection_tokens_all_fields_any_case() raises:
    """Every Connection field counts, tokens are case-insensitive, close wins."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var resp_wires: List[String] = [
        "HTTP/1.1 200 OK\r\nConnection: Keep-Alive, CLOSE\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    ]
    for i in range(6):
        var client = HttpClient()
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
        var req: Request
        if i == 0:
            req = _req_conn(["CLOSE"])
        elif i == 1:
            req = _req_conn(["keep-alive, close"])
        elif i == 2:
            req = _req_conn(["keep-alive", "Close"])
        elif i == 3:
            req = _req_conn(List[String](), v10=True)
        else:
            req = _req()
        var h = client.submit(Origin(copy=origin), req^)
        _answer(client, origin, 0, resp_wires[i - 4] if i >= 4 else _ok("x"))
        client.run_one(Origin(copy=origin), h)
        assert_true(h.is_complete() and not h.is_errored(), "case " + String(i) + " completes")
        assert_true(_submit_raises(client, origin), "case " + String(i) + ": slot retired")
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), _req_conn(["Keep-Alive"], v10=True))
    _answer(client, origin, 0, _ok("x"))
    client.run_one(Origin(copy=origin), h)
    assert_true(not _submit_raises(client, origin), "HTTP/1.0 with keep-alive stays reusable")


def test_streamed_body_finished_before_response_stays_reusable() raises:
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), _req(stream=True))
    client.feed_body(h, BodyFrame.data(List[Byte](length=3, fill=65)))
    client.feed_body(h, BodyFrame.end())
    _answer(client, origin, 0, _ok("x"))
    client.run_one(Origin(copy=origin), h)
    assert_true(h.is_complete() and not h.is_errored(), "upload then response completes")
    assert_true(not _submit_raises(client, origin), "finished upload keeps the slot reusable")


def test_connection_ending_exchanges_retire_slot() raises:
    """HTTP/1.0 without keep-alive, client Connection: close, early response mid-upload."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    for i in range(3):
        var client = HttpClient()
        client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
        var h = client.submit(Origin(copy=origin), _req(close=(i == 1), stream=(i == 2)))
        var wire = _ok("x")
        if i == 0:
            wire = String("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx")
        _answer(client, origin, 0, wire)
        client.run_one(Origin(copy=origin), h)
        assert_true(h.is_complete() and not h.is_errored(), "case " + String(i) + " completes")
        assert_true(_submit_raises(client, origin), "case " + String(i) + ": slot retired")


def test_detach_then_poll_is_connection_closed() raises:
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpCoroClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), _req())
    _ = client.detach_session(origin)
    client.run_one(Origin(copy=origin), h)
    assert_true(h.is_errored(), "detached slot's handle errors")
    assert_equal_int(h._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "detached: connection_closed")


def test_streamed_upload_through_client() raises:
    """feed_body routes the client handle to its session's own id."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    _ = client.submit(Origin(copy=origin), _req())
    client._pool[origin][0].ptr()[].feed_eof()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), _req(stream=True))  # client id 2, session id 1
    client.feed_body(h, BodyFrame.data(List[Byte](length=3, fill=65)))
    client.feed_body(h, BodyFrame.end())
    var p = client._pool[origin][0].ptr()
    var wire = String(StringSlice(unsafe_from_utf8=Span(p[].drain())))
    assert_true("3\r\nAAA\r\n0\r\n\r\n" in wire, "chunked upload on the wire: " + wire)
    p[].feed(_ok("done").as_bytes())
    client.run_one(Origin(copy=origin), h)
    var raised = False
    try:
        client.feed_body(h, BodyFrame.end())
    except e:
        raised = "unknown or finished" in String(e)
    assert_true(raised, "feed_body after completion raises")
    assert_true(_body(h^) == "done", "upload response delivered")


def _retired_after(var req: Request, wire: String) raises -> Bool:
    """Run one exchange on a fresh pooled slot; True if the slot was retired."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), req^)
    _answer(client, origin, 0, wire)
    client.run_one(Origin(copy=origin), h)
    assert_true(h.is_complete() and not h.is_errored(), "exchange completes")
    return _submit_raises(client, origin)


def test_connection_token_edges() raises:
    """Only exact tokens count; tab OWS and empty list elements are allowed."""
    var keep: List[String] = ["x-close", "closed", "keep-alive-ish"]
    for i in range(len(keep)):
        assert_true(not _retired_after(_req_conn([keep[i]]), _ok("x")), keep[i] + " is not close")
    assert_true(_retired_after(_req_conn(["keep-alive-ish"], v10=True), _ok("x")), "1.0 needs a real keep-alive")
    var close: List[String] = ["keep-alive,\tclose", ", ,close"]
    for i in range(len(close)):
        assert_true(_retired_after(_req_conn([close[i]]), _ok("x")), close[i] + " is close")


def test_keep_alive_decided_per_message() raises:
    """An HTTP/1.0 peer must repeat keep-alive on every message (RFC 9112 Section 9.3)."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h1 = client.submit(Origin(copy=origin), _req())
    _answer(client, origin, 0, String("HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nx"))
    client.run_one(Origin(copy=origin), h1)
    var h2 = client.submit(Origin(copy=origin), _req())
    _answer(client, origin, 0, String("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\ny"))
    client.run_one(Origin(copy=origin), h2)
    assert_true(h2.is_complete() and not h2.is_errored(), "second response completes")
    assert_true(_submit_raises(client, origin), "retired after a 1.0 response without keep-alive")
    var both = H1Connection(ParseConfig())
    var w1 = String("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n")
    both.receive_data(w1.as_bytes())
    assert_true(both.next_request().__bool__() and both.should_close(), "server: separate close field wins")
    var v10 = H1Connection(ParseConfig())
    var w2 = String("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.0\r\n\r\n")
    v10.receive_data(w2.as_bytes())
    assert_true(v10.next_request().__bool__() and not v10.should_close(), "server: 1.0 keep-alive persists")
    assert_true(v10.next_request().__bool__() and v10.should_close(), "server: next 1.0 request without it closes")


def test_feed_body_after_close_raises() raises:
    """A routed streaming upload stops once the slot's session closed."""
    var origin = Origin(scheme="http", host="example.test", port=UInt16(80))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h1(H1Session()))
    var h = client.submit(Origin(copy=origin), _req(stream=True))
    client.feed_body(h, BodyFrame.data(List[Byte](length=3, fill=65)))
    var p = client._pool[origin][0].ptr()
    _ = p[].drain()
    p[].feed_eof()
    var raised = False
    try:
        client.feed_body(h, BodyFrame.data(List[Byte](length=3, fill=66)))
    except e:
        raised = "session closed" in String(e)
    assert_true(raised, "feed_body after EOF raises session closed")
    assert_equal_int(len(p[].drain()), 0, "nothing written after EOF")
    client.run_one(Origin(copy=origin), h)
    assert_equal_int(h.error().value().kind, STREAM_ERR_CONNECTION_CLOSED, "error() reports connection_closed")


def main() raises:
    var passed = 0
    var total = 23
    var names: List[String] = [
        "test_eof_framing_matrix", "test_receive_data_after_eof_raises",
        "test_submit_after_eof_raises", "test_reset_is_not_eof",
        "test_h1_session_errored_and_closed_before_response",
        "test_interim_then_eof_is_connection_closed",
        "test_empty_lines_then_eof_is_nothing_received",
        "test_interim_responses", "test_non_chunked_te_is_close_delimited",
        "test_stale_handle_does_not_steal_error",
        "test_http_client_replaces_closed_slot",
        "test_unusable_h1_slot_not_reused",
        "test_unpolled_handle_does_not_pin_closed_slot",
        "test_ids_not_crossed_after_eviction", "test_one_live_slot_per_origin",
        "test_connection_ending_exchanges_retire_slot",
        "test_detach_then_poll_is_connection_closed",
        "test_connection_tokens_all_fields_any_case",
        "test_streamed_body_finished_before_response_stays_reusable",
        "test_streamed_upload_through_client",
        "test_connection_token_edges", "test_keep_alive_decided_per_message",
        "test_feed_body_after_close_raises",
    ]
    for i in range(total):
        try:
            if i == 0: test_eof_framing_matrix()
            elif i == 1: test_receive_data_after_eof_raises()
            elif i == 2: test_submit_after_eof_raises()
            elif i == 3: test_reset_is_not_eof()
            elif i == 4: test_h1_session_errored_and_closed_before_response()
            elif i == 5: test_interim_then_eof_is_connection_closed()
            elif i == 6: test_empty_lines_then_eof_is_nothing_received()
            elif i == 7: test_interim_responses()
            elif i == 8: test_non_chunked_te_is_close_delimited()
            elif i == 9: test_stale_handle_does_not_steal_error()
            elif i == 10: test_http_client_replaces_closed_slot()
            elif i == 11: test_unusable_h1_slot_not_reused()
            elif i == 12: test_unpolled_handle_does_not_pin_closed_slot()
            elif i == 13: test_ids_not_crossed_after_eviction()
            elif i == 14: test_one_live_slot_per_origin()
            elif i == 15: test_connection_ending_exchanges_retire_slot()
            elif i == 16: test_detach_then_poll_is_connection_closed()
            elif i == 17: test_connection_tokens_all_fields_any_case()
            elif i == 18: test_streamed_body_finished_before_response_stays_reusable()
            elif i == 19: test_streamed_upload_through_client()
            elif i == 20: test_connection_token_edges()
            elif i == 21: test_keep_alive_decided_per_message()
            else: test_feed_body_after_close_raises()
            print("PASS: " + names[i])
            passed += 1
        except e:
            print("FAIL: " + names[i] + ": " + String(e))
    print("test_h1_eof: " + String(passed) + "/" + String(total) + " passed")
    if passed != total:
        raise "some h1 eof tests failed"
