# tests/test_response_writer.mojo
#
# Unit tests for ResponseWriter (M2.5a §5.8).
from navette.http.handler import ResponseWriter, WriteResult
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.status import StatusCode
from tests._test_util import assert_true, assert_false


def test_send_status_then_body_ok() raises:
    var w = ResponseWriter()
    w.send_status(StatusCode(200), Headers())
    var b: List[UInt8] = [UInt8(1)]
    var r = w.try_send_body(BodyFrame.data(b^))
    assert_true(r.is_ok(), "ok")


def test_send_body_before_status_raises() raises:
    var w = ResponseWriter()
    var raised = False
    try:
        var b: List[UInt8] = [UInt8(1)]
        _ = w.try_send_body(BodyFrame.data(b^))
    except:
        raised = True
    assert_true(raised, "body_before_status_raises")


def test_double_send_status_raises() raises:
    var w = ResponseWriter()
    w.send_status(StatusCode(200), Headers())
    var raised = False
    try:
        w.send_status(StatusCode(200), Headers())
    except:
        raised = True
    assert_true(raised, "double_send_raises")


def test_send_informational_then_status_then_body() raises:
    var w = ResponseWriter()
    w.send_informational(StatusCode(103), Headers())
    w.send_informational(StatusCode(103), Headers())
    w.send_status(StatusCode(200), Headers())
    var b: List[UInt8] = [UInt8(1)]
    assert_true(w.try_send_body(BodyFrame.data(b^)).is_ok(), "info_then_body")


def test_send_informational_after_status_raises() raises:
    var w = ResponseWriter()
    w.send_status(StatusCode(200), Headers())
    var raised = False
    try:
        w.send_informational(StatusCode(103), Headers())
    except:
        raised = True
    assert_true(raised, "info_after_status_raises")


def test_end_marks_closed() raises:
    var w = ResponseWriter()
    w.send_status(StatusCode(200), Headers())
    w.end()
    var b: List[UInt8] = [UInt8(1)]
    var r = w.try_send_body(BodyFrame.data(b^))
    assert_true(r.is_closed(), "closed_after_end")


def test_send_prebuilt_captures_wire() raises:
    """send_prebuilt records the wire bytes and flips _has_prebuilt_response."""
    var w = ResponseWriter()
    var wire = String("HTTP/1.1 200 OK\r\nx: y\r\n\r\nhi").as_bytes()
    w.send_prebuilt(wire)
    assert_true(w._has_status(), "status_marker_set")
    assert_true(w._has_prebuilt_response(), "prebuilt_flag_set")
    var out = w._take_prebuilt()
    assert_true(len(out) == 27, "prebuilt_len_matches")
    assert_false(w._has_prebuilt_response(), "flag_cleared_after_take")


def test_send_prebuilt_after_send_status_raises() raises:
    var w = ResponseWriter()
    w.send_status(StatusCode(200), Headers())
    var raised = False
    try:
        w.send_prebuilt(String("x").as_bytes())
    except:
        raised = True
    assert_true(raised, "prebuilt_after_status_raises")


def test_send_status_after_send_prebuilt_raises() raises:
    var w = ResponseWriter()
    w.send_prebuilt(String("x").as_bytes())
    var raised = False
    try:
        w.send_status(StatusCode(200), Headers())
    except:
        raised = True
    assert_true(raised, "status_after_prebuilt_raises")


def test_double_send_prebuilt_raises() raises:
    var w = ResponseWriter()
    w.send_prebuilt(String("a").as_bytes())
    var raised = False
    try:
        w.send_prebuilt(String("b").as_bytes())
    except:
        raised = True
    assert_true(raised, "double_prebuilt_raises")


def main() raises:
    test_send_status_then_body_ok()
    test_send_body_before_status_raises()
    test_double_send_status_raises()
    test_send_informational_then_status_then_body()
    test_send_informational_after_status_raises()
    test_end_marks_closed()
    test_send_prebuilt_captures_wire()
    test_send_prebuilt_after_send_status_raises()
    test_send_status_after_send_prebuilt_raises()
    test_double_send_prebuilt_raises()
    print("test_response_writer: all tests passed")
