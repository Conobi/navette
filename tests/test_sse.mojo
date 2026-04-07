# tests/test_sse.mojo
#
# Unit tests for Server-Sent Events (WHATWG event-stream, M2.5b §7.3).
from std.collections.optional import Optional
from src.http.sse import ServerSentEvent
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


def main() raises:
    test_event_default_fields()
    test_event_populated()
    print("test_sse: all tests passed")
