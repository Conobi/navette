# tests/test_request_clone.mojo
#
# Unit tests for Request.clone() / try_clone() (M2.5a §5.13).
from src.http.request import Request, RequestBody
from src.http.method import Method
from src.http.handler import RecvBody
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_clone_buffered_succeeds() raises:
    var bytes: List[UInt8] = [UInt8(1), UInt8(2)]
    var req = Request(
        method=Method.get(),
        target=String("/"),
        body=RequestBody.buffered(bytes^),
    )
    var c = req.clone()
    assert_true(c.body.is_buffered(), "clone.is_buffered")
    assert_equal_int(len(c.body.bytes()), 2, "clone.len")


def test_clone_stream_raises() raises:
    var inner = RecvBody()
    inner._set_end()
    var req = Request(
        method=Method.get(),
        target=String("/"),
        body=RequestBody.stream(inner^.detach()),
    )
    var raised = False
    try:
        var _c = req.clone()
    except:
        raised = True
    assert_true(raised, "stream.clone_raises")


def test_try_clone_buffered_returns_some() raises:
    var bytes: List[UInt8] = [UInt8(1)]
    var req = Request(
        method=Method.get(),
        target=String("/"),
        body=RequestBody.buffered(bytes^),
    )
    var c_opt = req.try_clone()
    assert_true(Bool(c_opt), "buffered.try_clone_some")


def test_try_clone_stream_returns_none() raises:
    var inner = RecvBody()
    inner._set_end()
    var req = Request(
        method=Method.get(),
        target=String("/"),
        body=RequestBody.stream(inner^.detach()),
    )
    var c_opt = req.try_clone()
    assert_false(Bool(c_opt), "stream.try_clone_none")


def main() raises:
    test_clone_buffered_succeeds()
    test_clone_stream_raises()
    test_try_clone_buffered_returns_some()
    test_try_clone_stream_returns_none()
    print("test_request_clone: all tests passed")
