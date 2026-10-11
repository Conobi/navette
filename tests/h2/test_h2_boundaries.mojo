# tests/h2/test_h2_boundaries.mojo
"""H2 client: EOF with open streams errors them; large bodies arrive intact
at any split with flow control (WINDOW_UPDATE) in the loop."""
from std.collections import Span
from navette.h2.h2_session import H2Session
from navette.h2.connection import H2Connection
from navette.h2.header import Header
from navette.http.request import Request
from navette.http.method import Method
from navette.http.version import Version
from navette.http.headers import Headers
from navette.http.session import RequestHandle
from navette.http.handler import STREAM_ERR_CONNECTION_CLOSED
from navette.http.client import HttpClient
from navette.http.session_slot import SessionSlot
from navette.http.alt_svc import Origin
from tests._test_util import assert_true, assert_equal_int
from tests._split_harness import split_plans, payload, assert_bytes_equal, MAX_DRIVE_ITERS


def _pair(mut session: H2Session, mut server: H2Connection) raises -> RequestHandle:
    """Preface exchange, then a GET on stream 1 delivered to the server."""
    server.initiate_connection()
    _ = server.receive_data(session.drain())
    session.feed(Span(server.data_to_send()))
    _ = server.receive_data(session.drain())
    _ = server.data_to_send()
    var h = Headers()
    h.add("host", "localhost")
    var handle = session.submit(Request(method=Method.get(), target="/", version=Version.http_2(), headers=h^))
    _ = server.receive_data(session.drain())
    _ = server.data_to_send()
    return handle^


def test_feed_eof_errors_open_streams() raises:
    var session = H2Session()
    var server = H2Connection(client_side=False)
    var handle = _pair(session, server)
    var hdrs = List[Header]()
    hdrs.append(Header(":status", "200"))
    server.send_headers(UInt32(1), hdrs^, end_stream=False)
    session.feed(Span(server.data_to_send()))
    session.feed_eof()
    session.run_one(handle)
    assert_true(handle.is_errored(), "open stream must error at EOF")
    assert_equal_int(handle._error.value().kind, STREAM_ERR_CONNECTION_CLOSED, "connection_closed")


def test_live_pair_body_sizes_and_splits() raises:
    var sizes: List[Int] = [65535, 65536, 65537, 1 << 20]
    for si in range(len(sizes)):
        var body = payload(sizes[si], UInt64(sizes[si]))
        var session0 = H2Session()
        var server0 = H2Connection(client_side=False)
        _ = _pair(session0, server0)
        var hdrs0 = List[Header]()
        hdrs0.append(Header(":status", "200"))
        server0.send_headers(UInt32(1), hdrs0^, end_stream=False)
        server0.send_data(UInt32(1), Span(body), end_stream=True)
        var first_len = len(server0.data_to_send())
        var plans = split_plans(first_len, UInt64(si), sampled=4, randoms=2)
        for p in range(len(plans)):
            var label = "h2 body=" + String(sizes[si]) + " plan=" + plans[p].label
            var session = H2Session()
            var server = H2Connection(client_side=False)
            var handle = _pair(session, server)
            var hdrs = List[Header]()
            hdrs.append(Header(":status", "200"))
            server.send_headers(UInt32(1), hdrs^, end_stream=False)
            server.send_data(UInt32(1), Span(body), end_stream=True)
            var wire = server.data_to_send()
            var off = 0
            for c in range(len(plans[p].chunks)):
                var n = min(plans[p].chunks[c], len(wire) - off)
                if n <= 0:
                    break
                session.feed(Span(wire)[off:off + n])
                off += n
            if off < len(wire):
                session.feed(Span(wire)[off:])
            for _ in range(MAX_DRIVE_ITERS):
                session.run_one(handle)
                if handle.is_complete():
                    break
                _ = server.receive_data(session.drain())
                var more = server.data_to_send()
                if len(more) == 0:
                    break
                session.feed(Span(more))
            assert_true(handle.is_complete() and not handle.is_errored(), label + ": incomplete")
            var resp = handle^.take_response()
            var got = List[Byte]()
            for i in range(len(resp.body)):
                if resp.body[i].is_data():
                    got.extend(Span(resp.body[i].data()))
            assert_bytes_equal(got, body, label)


def test_after_eof_complete_delivered_and_reuse_raises() raises:
    """A stream finished before EOF is still delivered; feed and submit raise."""
    var session = H2Session()
    var server = H2Connection(client_side=False)
    var handle = _pair(session, server)
    var hdrs = List[Header]()
    hdrs.append(Header(":status", "204"))
    server.send_headers(UInt32(1), hdrs^, end_stream=True)
    session.feed(Span(server.data_to_send()))
    session.feed_eof()
    session.run_one(handle)
    assert_true(handle.is_complete() and not handle.is_errored(), "completed stream delivered after EOF")
    var feed_raised = False
    try:
        session.feed(Span(List[Byte](length=1, fill=0)))
    except e:
        feed_raised = "data after EOF" in String(e)
    assert_true(feed_raised, "feed after EOF must raise")
    var h = Headers()
    h.add("host", "localhost")
    var submit_raised = False
    try:
        _ = session.submit(Request(method=Method.get(), target="/", version=Version.http_2(), headers=h^))
    except e:
        submit_raised = "session closed" in String(e)
    assert_true(submit_raised, "submit after EOF must raise")


def _h2_get() -> Request:
    var h = Headers()
    h.add("host", "localhost")
    return Request(method=Method.get(), target="/", version=Version.http_2(), headers=h^)


def test_two_h2_handles_on_one_slot_through_client() raises:
    """Two multiplexed streams on one pooled slot each get their own body."""
    var origin = Origin(scheme="https", host="localhost", port=UInt16(443))
    var client = HttpClient()
    client.attach_session(Origin(copy=origin), SessionSlot.from_h2(H2Session()))
    var p = client._pool[origin][0].ptr()
    var server = H2Connection(client_side=False)
    server.initiate_connection()
    _ = server.receive_data(p[].drain())
    p[].feed(Span(server.data_to_send()))
    var a = client.submit(Origin(copy=origin), _h2_get())
    var b = client.submit(Origin(copy=origin), _h2_get())
    _ = server.receive_data(p[].drain())
    _ = server.data_to_send()
    var bodies: List[String] = ["stream-one", "stream-three"]
    for i in range(2):
        var sid = UInt32(3 - 2 * i)  # answer stream 3 first
        var hdrs = List[Header]()
        hdrs.append(Header(":status", "200"))
        server.send_headers(sid, hdrs^, end_stream=False)
        server.send_data(sid, bodies[1 - i].as_bytes(), end_stream=True)
    p[].feed(Span(server.data_to_send()))
    client.run_one(Origin(copy=origin), b)
    client.run_one(Origin(copy=origin), a)
    assert_true(a.is_complete() and b.is_complete(), "both streams complete")
    var ra = a^.take_response()
    var rb = b^.take_response()
    var got_a = String(StringSlice(unsafe_from_utf8=Span(ra.body[0].data())))
    var got_b = String(StringSlice(unsafe_from_utf8=Span(rb.body[0].data())))
    assert_true(got_a == "stream-one" and got_b == "stream-three", "responses not crossed")


def main() raises:
    var passed = 0
    try:
        test_two_h2_handles_on_one_slot_through_client()
        print("PASS: test_two_h2_handles_on_one_slot_through_client"); passed += 1
    except e:
        print("FAIL: test_two_h2_handles_on_one_slot_through_client: " + String(e))
    try:
        test_after_eof_complete_delivered_and_reuse_raises()
        print("PASS: test_after_eof_complete_delivered_and_reuse_raises"); passed += 1
    except e:
        print("FAIL: test_after_eof_complete_delivered_and_reuse_raises: " + String(e))
    try:
        test_feed_eof_errors_open_streams(); print("PASS: test_feed_eof_errors_open_streams"); passed += 1
    except e:
        print("FAIL: test_feed_eof_errors_open_streams: " + String(e))
    try:
        test_live_pair_body_sizes_and_splits(); print("PASS: test_live_pair_body_sizes_and_splits"); passed += 1
    except e:
        print("FAIL: test_live_pair_body_sizes_and_splits: " + String(e))
    print("test_h2_boundaries: " + String(passed) + "/4 passed")
    if passed != 4:
        raise "some h2 boundary tests failed"
