# tests/test_sse.mojo
#
# Unit tests for Server-Sent Events (WHATWG event-stream, M2.5b §7.3).
from std.collections.optional import Optional
from mojo_net.http.sse import ServerSentEvent, EventStreamReader, try_write_event
from mojo_net.http.handler import RecvBody, DetachedBody, ResponseWriter
from mojo_net.http.body import BodyFrame
from mojo_net.http.headers import Headers
from mojo_net.http.status import StatusCode
from tests._test_util import assert_true, assert_false, assert_equal_int, assert_equal_str


def test_event_default_fields() raises:
    var e = ServerSentEvent()
    assert_false(Bool(e.event), "default.event_none")
    assert_equal_str(e.data, String(""), "default.data_empty")
    assert_false(Bool(e.id), "default.id_none")
    assert_false(Bool(e.retry), "default.retry_none")


def test_event_populated() raises:
    var e = ServerSentEvent()
    e.event = Optional[String](String("message"))
    e.data = String("hello")
    e.id = Optional[String](String("42"))
    e.retry = Optional[UInt](UInt(5000))
    assert_equal_str(e.event.value(), String("message"), "populated.event")
    assert_equal_str(e.data, String("hello"), "populated.data")
    assert_equal_str(e.id.value(), String("42"), "populated.id")
    assert_equal_int(Int(e.retry.value()), 5000, "populated.retry")


def _bytes_from_str(s: String) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8]()
    var i = 0
    while i < len(b):
        out.append(b[i])
        i += 1
    return out^


def _bytes_from_str_frame(s: String) -> BodyFrame:
    return BodyFrame.data(_bytes_from_str(s))


def test_reader_single_data_event() raises:
    var body = RecvBody()
    body._push(BodyFrame.data(_bytes_from_str("data: hello\n\n")))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev_opt = reader.try_next_event()
    assert_true(Bool(ev_opt), "single.has_event")
    var ev = ev_opt.value().copy()
    assert_equal_str(ev.data, String("hello"), "single.data")


def test_reader_multi_data_lines_joined_with_lf() raises:
    var body = RecvBody()
    body._push(BodyFrame.data(_bytes_from_str("data: line1\ndata: line2\n\n")))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.data, String("line1\nline2"), "multi.data")


def test_reader_event_and_id_fields() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame("event: ping\nid: 7\ndata: pong\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.event.value(), String("ping"), "fields.event")
    assert_equal_str(ev.id.value(), String("7"), "fields.id")
    assert_equal_str(ev.data, String("pong"), "fields.data")


def test_reader_comment_line_ignored() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame(": keepalive\ndata: foo\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_equal_str(ev.data, String("foo"), "comment.data")


def test_reader_retry_parses_int() raises:
    var body = RecvBody()
    body._push(_bytes_from_str_frame("retry: 5000\ndata: ok\n\n"))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev = reader.try_next_event().value().copy()
    assert_true(Bool(ev.retry), "retry.some")
    assert_equal_int(Int(ev.retry.value()), 5000, "retry.value")


def test_reader_end_reports_is_end() raises:
    var body = RecvBody()
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev_opt = reader.try_next_event()
    assert_false(Bool(ev_opt), "end.no_event")
    assert_true(reader.is_end(), "end.is_end")


def test_reader_partial_event_at_end_discarded() raises:
    # WHATWG §9.2: an incomplete event (no blank-line terminator) at the
    # end of the stream is discarded rather than dispatched. is_end() must
    # return True so callers stop polling.
    var body = RecvBody()
    body._push(BodyFrame.data(_bytes_from_str("data: partial\n")))
    body._set_end()
    var reader = EventStreamReader(body^.detach())
    var ev_opt = reader.try_next_event()
    assert_false(Bool(ev_opt), "partial.no_event")
    assert_true(reader.is_end(), "partial.is_end")


def test_write_simple_data_event_roundtrips() raises:
    var resp = ResponseWriter()
    resp.send_status(StatusCode(200), Headers())
    var ev = ServerSentEvent()
    ev.data = String("hello world")
    var r = try_write_event(resp, ev)
    assert_true(r.is_ok(), "write.ok")

    # Drain the written bytes through a RecvBody → EventStreamReader and
    # confirm the event comes back out unchanged.
    var recv = RecvBody()
    while True:
        var frame_opt = resp._pop_body_frame()
        if not Bool(frame_opt):
            break
        var frame = frame_opt.value().copy()
        if frame.is_data():
            recv._push(BodyFrame.data(frame.data().copy()))
    recv._set_end()
    var reader = EventStreamReader(recv^.detach())
    var decoded = reader.try_next_event().value().copy()
    assert_equal_str(decoded.data, String("hello world"), "roundtrip.data")


def test_write_all_fields_roundtrips() raises:
    var resp = ResponseWriter()
    resp.send_status(StatusCode(200), Headers())
    var ev = ServerSentEvent()
    ev.event = Optional[String](String("message"))
    ev.data = String("line1\nline2")
    ev.id = Optional[String](String("42"))
    ev.retry = Optional[UInt](UInt(3000))
    var r = try_write_event(resp, ev)
    assert_true(r.is_ok(), "all.ok")

    var recv = RecvBody()
    while True:
        var frame_opt = resp._pop_body_frame()
        if not Bool(frame_opt):
            break
        var frame = frame_opt.value().copy()
        if frame.is_data():
            recv._push(BodyFrame.data(frame.data().copy()))
    recv._set_end()
    var reader = EventStreamReader(recv^.detach())
    var decoded = reader.try_next_event().value().copy()
    assert_equal_str(decoded.event.value(), String("message"), "all.event")
    assert_equal_str(decoded.data, String("line1\nline2"), "all.data")
    assert_equal_str(decoded.id.value(), String("42"), "all.id")
    assert_equal_int(Int(decoded.retry.value()), 3000, "all.retry")


def main() raises:
    test_event_default_fields()
    test_event_populated()
    test_reader_single_data_event()
    test_reader_multi_data_lines_joined_with_lf()
    test_reader_event_and_id_fields()
    test_reader_comment_line_ignored()
    test_reader_retry_parses_int()
    test_reader_end_reports_is_end()
    test_reader_partial_event_at_end_discarded()
    test_write_simple_data_event_roundtrips()
    test_write_all_fields_roundtrips()
    print("test_sse: all tests passed")
