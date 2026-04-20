# tests/test_http_client.mojo
#
# Unit tests for M6a HttpClient (pool, dispatch, convenience API).

from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from src.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1
from src.http.handler import Capabilities, ALPN_H1, StreamHandler, RecvBody, ResponseWriter, StreamError
from src.http.request import Request, RequestBody
from src.http.method import Method
from src.http.headers import Headers
from src.http.status import StatusCode
from src.http.response import Response
from src.http.alt_svc import Origin
from src.http.url import parse_url
from src.http.client import HttpClient, _is_redirect, _is_idempotent
from src.h1.h1_session import H1Session
from src.h1.handler_server import H1HandlerServer
from src.h2.h2_session import H2Session
from tests._test_util import assert_true, assert_equal_int


def test_session_slot_from_h1() raises:
    """SessionSlot wraps H1Session and delegates submit."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    assert_equal_int(Int(slot.kind), Int(SLOT_H1), "kind")
    assert_true(not slot.is_idle(), "should be active initially")
    var caps = slot.capabilities()
    assert_equal_int(caps.alpn, ALPN_H1, "alpn")


def test_session_slot_idle_tracking() raises:
    """Mark_idle / mark_active transitions."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    assert_true(not slot.is_idle(), "not idle initially")
    slot.mark_idle(UInt64(1000))
    assert_true(slot.is_idle(), "idle after mark")
    assert_true(slot.idle_since == UInt64(1000), "idle_since")
    slot.mark_active()
    assert_true(not slot.is_idle(), "active after mark_active")


def test_session_slot_submit_h1() raises:
    """Submit a request through SessionSlot -> H1Session."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    var req = Request(
        method=Method.get(),
        target=String("/"),
        headers=hdrs^,
        body=RequestBody.empty(),
    )
    var handle = slot.submit(req^)
    assert_true(handle.id() == UInt64(1), "handle id")


def test_session_slot_ptr_round_trip() raises:
    """SessionSlotPtr stores on heap and retrieves."""
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var ptr = _heap_alloc[SessionSlot](1).as_any_origin()
    ptr.init_pointee_move(slot^)
    var slot_ptr = SessionSlotPtr(UInt64(Int(ptr)))
    # Access through pointer
    var caps = slot_ptr.ptr()[].capabilities()
    assert_equal_int(caps.alpn, ALPN_H1, "ptr round-trip")
    # Cleanup
    slot_ptr.ptr().destroy_pointee()
    slot_ptr.ptr().free()


struct OkHandler(StreamHandler):
    def __init__(out self):
        pass
    def __init__(out self, *, deinit take: Self):
        pass
    def on_request(
        mut self, var req: Request, mut body: RecvBody,
        mut resp: ResponseWriter, caps: Capabilities,
    ) raises:
        var h = Headers()
        h.add("x-method", String(req.method))
        h.add("x-path", req.target)
        resp.send_status(StatusCode(200), h^)
        resp.end()
    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass
    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass
    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass
    def on_reset(mut self, error: StreamError):
        pass


def test_client_attach_and_submit() raises:
    """Attach a session and submit through pool."""
    var client = HttpClient.default()
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var origin = Origin(scheme="https", host="example.com", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    var req = Request(
        Method.get(),
        String("/"),
        headers=hdrs^,
        body=RequestBody.empty(),
    )
    var handle = client.submit(Origin(other=origin), req^)
    assert_true(handle.id() > UInt64(0), "got handle")


def test_client_no_connection_raises() raises:
    """Submit with no attached session raises."""
    var client = HttpClient.default()
    var origin = Origin(scheme="https", host="unknown.com", port=UInt16(443))
    var req = Request(
        Method.get(), String("/"),
        headers=Headers(), body=RequestBody.empty(),
    )
    var raised = False
    try:
        _ = client.submit(Origin(other=origin), req^)
    except:
        raised = True
    assert_true(raised, "should raise when no connection")


def test_client_idle_eviction() raises:
    """close_idle keeps non-expired sessions."""
    var client = HttpClient.with_config(idle_timeout_ms=UInt64(1000))
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    slot.mark_idle(UInt64(100))
    var origin = Origin(scheme="https", host="example.com", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)
    # At t=500, not expired (500 - 100 = 400 < 1000)
    client.close_idle(UInt64(500))
    var req = Request(
        Method.get(), String("/"),
        headers=Headers(), body=RequestBody.empty(),
    )
    var handle = client.submit(Origin(other=origin), req^)
    assert_true(handle.id() > UInt64(0), "still available")


def test_client_idle_eviction_expired() raises:
    """close_idle removes expired sessions."""
    var client = HttpClient.with_config(idle_timeout_ms=UInt64(1000))
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    slot.mark_idle(UInt64(100))
    var origin = Origin(scheme="https", host="example.com", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)
    # At t=1200, expired (1200 - 100 = 1100 > 1000)
    client.close_idle(UInt64(1200))
    var req = Request(
        Method.get(), String("/"),
        headers=Headers(), body=RequestBody.empty(),
    )
    var raised = False
    try:
        _ = client.submit(Origin(other=origin), req^)
    except:
        raised = True
    assert_true(raised, "evicted — no connection")


def test_client_get_convenience() raises:
    """Convenience get() builds correct request."""
    var client = HttpClient.default()
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var origin = Origin(scheme="https", host="api.test", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)
    var handle = client.get("https://api.test/v1/data")
    assert_true(handle.id() > UInt64(0), "got handle from get()")


def test_client_loopback_roundtrip() raises:
    """Full round-trip: submit -> drain -> server -> feed -> run_one -> response."""
    var client = HttpClient.default()
    var session = H1Session()
    var slot = SessionSlot.from_h1(session^)
    var origin = Origin(scheme="https", host="loop.test", port=UInt16(443))
    client.attach_session(Origin(other=origin), slot^)

    var hdrs = Headers()
    hdrs.add("Host", "loop.test")
    var req = Request(
        Method.get(), String("/hello"),
        headers=hdrs^, body=RequestBody.empty(),
    )
    var handle = client.submit(Origin(other=origin), req^)

    # Pump: drain from slot -> server -> feed back
    var server = H1HandlerServer[OkHandler](handler=OkHandler())
    ref slots = client._pool[origin]
    var p = slots[0].ptr()
    var req_bytes = p[].drain()
    server.feed(Span(req_bytes))
    var resp_bytes = server.drain()
    p[].feed(Span(resp_bytes))
    client.run_one(Origin(other=origin), handle)

    assert_true(handle.is_complete(), "complete")
    var resp = handle^.take_response()
    assert_equal_int(Int(resp.status.code()), 200, "status 200")


def test_client_max_conns_h1() raises:
    """Cannot exceed max H1 connections per origin."""
    var client = HttpClient.with_config(max_conns_h1=2)
    var origin = Origin(scheme="https", host="limited.test", port=UInt16(443))
    var s1 = H1Session()
    client.attach_session(Origin(other=origin), SessionSlot.from_h1(s1^))
    var s2 = H1Session()
    client.attach_session(Origin(other=origin), SessionSlot.from_h1(s2^))
    var s3 = H1Session()
    var raised = False
    try:
        client.attach_session(Origin(other=origin), SessionSlot.from_h1(s3^))
    except:
        raised = True
    assert_true(raised, "should reject 3rd H1 session")


def test_client_max_conns_mux() raises:
    """H2 origins enforce max_conns_mux (default 1)."""
    var client = HttpClient.with_config(max_conns_mux=1)
    var origin = Origin(scheme="https", host="mux.test", port=UInt16(443))
    var s1 = H2Session()
    client.attach_session(Origin(other=origin), SessionSlot.from_h2(s1^))
    var s2 = H2Session()
    var raised = False
    try:
        client.attach_session(Origin(other=origin), SessionSlot.from_h2(s2^))
    except:
        raised = True
    assert_true(raised, "should reject 2nd H2 session")


def test_client_multiple_origins() raises:
    """Pool supports multiple origins simultaneously."""
    var client = HttpClient.default()
    var s1 = H1Session()
    var o1 = Origin(scheme="https", host="alpha.test", port=UInt16(443))
    client.attach_session(Origin(other=o1), SessionSlot.from_h1(s1^))
    var s2 = H1Session()
    var o2 = Origin(scheme="https", host="beta.test", port=UInt16(443))
    client.attach_session(Origin(other=o2), SessionSlot.from_h1(s2^))
    var r1 = Request(Method.get(), String("/a"), headers=Headers(), body=RequestBody.empty())
    var r2 = Request(Method.get(), String("/b"), headers=Headers(), body=RequestBody.empty())
    var h1 = client.submit(Origin(other=o1), r1^)
    var h2 = client.submit(Origin(other=o2), r2^)
    assert_true(h1.id() > UInt64(0), "h1 valid")
    assert_true(h2.id() > UInt64(0), "h2 valid")


def test_is_redirect() raises:
    """Redirect status codes are detected."""
    assert_true(_is_redirect(UInt16(301)), "301")
    assert_true(_is_redirect(UInt16(302)), "302")
    assert_true(_is_redirect(UInt16(307)), "307")
    assert_true(_is_redirect(UInt16(308)), "308")
    assert_true(not _is_redirect(UInt16(200)), "200 not redirect")
    assert_true(not _is_redirect(UInt16(404)), "404 not redirect")


def test_is_idempotent() raises:
    """Idempotent methods are detected."""
    assert_true(_is_idempotent(Method.get()), "GET")
    assert_true(_is_idempotent(Method.head()), "HEAD")
    assert_true(_is_idempotent(Method.put()), "PUT")
    assert_true(_is_idempotent(Method.delete()), "DELETE")
    assert_true(not _is_idempotent(Method.post()), "POST not idempotent")


def test_build_redirect_request_301() raises:
    """301 rewrites to GET and drops body."""
    var client = HttpClient.default()
    var hdrs = Headers()
    hdrs.add("Host", "example.com")
    hdrs.add("Authorization", "Bearer token123")
    var body_data = List[UInt8]()
    body_data.extend(String("data").as_bytes())
    var req = Request(
        method=Method.post(), target=String("/submit"),
        headers=hdrs^, body=RequestBody.buffered(body_data^),
    )
    var redirect_req = client.build_redirect_request(req^, UInt16(301), "/new-location")
    assert_true(String(redirect_req.method) == "GET", "method rewritten to GET")
    assert_true(redirect_req.target == "/new-location", "target updated")
    assert_true(redirect_req.body.is_empty(), "body dropped")
    assert_true(not redirect_req.headers.has("authorization"), "auth dropped")


def test_build_redirect_request_307() raises:
    """307 preserves method and body."""
    var client = HttpClient.default()
    var body_data = List[UInt8]()
    body_data.extend(String("payload").as_bytes())
    var req = Request(
        method=Method.post(), target=String("/api"),
        headers=Headers(), body=RequestBody.buffered(body_data^),
    )
    var redirect_req = client.build_redirect_request(req^, UInt16(307), "/api/v2")
    assert_true(String(redirect_req.method) == "POST", "method preserved")
    assert_true(redirect_req.target == "/api/v2", "target updated")
    assert_true(redirect_req.body.is_buffered(), "body preserved")


def test_build_redirect_absolute_url() raises:
    """Redirect to absolute URL extracts path."""
    var client = HttpClient.default()
    var req = Request(
        method=Method.get(), target=String("/old"),
        headers=Headers(), body=RequestBody.empty(),
    )
    var redirect_req = client.build_redirect_request(req^, UInt16(301), "https://other.com/new?q=1")
    assert_true(redirect_req.target == "/new?q=1", "path extracted from absolute URL")


def main() raises:
    test_session_slot_from_h1()
    test_session_slot_idle_tracking()
    test_session_slot_submit_h1()
    test_session_slot_ptr_round_trip()
    test_client_attach_and_submit()
    test_client_no_connection_raises()
    test_client_idle_eviction()
    test_client_idle_eviction_expired()
    test_client_get_convenience()
    test_client_loopback_roundtrip()
    test_client_max_conns_h1()
    test_client_max_conns_mux()
    test_client_multiple_origins()
    test_is_redirect()
    test_is_idempotent()
    test_build_redirect_request_301()
    test_build_redirect_request_307()
    test_build_redirect_absolute_url()
    print("test_http_client: 18/18 passed")
