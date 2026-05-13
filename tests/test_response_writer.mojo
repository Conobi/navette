# tests/test_response_writer.mojo
#
# Unit tests for ResponseWriter (M2.5a §5.8).
from mojo_net.http.handler import ResponseWriter, WriteResult
from mojo_net.http.body import BodyFrame
from mojo_net.http.headers import Headers
from mojo_net.http.status import StatusCode
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


def main() raises:
    test_send_status_then_body_ok()
    test_send_body_before_status_raises()
    test_double_send_status_raises()
    test_send_informational_then_status_then_body()
    test_send_informational_after_status_raises()
    test_end_marks_closed()
    print("test_response_writer: all tests passed")
