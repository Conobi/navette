# tests/h1/test_h1_close_delimited_existing_api.mojo
"""Red Gate (existing API): a response without Content-Length or chunked
framing ends at connection close, so it must not complete on a partial read.
"""
from std.collections import Span
from navette.h1.h1_session import H1Session
from navette.http.request import Request
from navette.http.method import Method
from navette.http.headers import Headers
from tests._test_util import assert_true


def test_split_close_delimited_not_complete_early() raises:
    var session = H1Session()
    var hdrs = Headers()
    hdrs.add("Host", "example.test")
    var handle = session.submit(Request(method=Method.get(), target="/", headers=hdrs^))
    _ = session.drain()
    var wire = String("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhel")
    session.feed(wire.as_bytes())
    session.run_one(handle)
    assert_true(
        not handle.is_complete(),
        "close-delimited response completed before the connection closed",
    )


def main() raises:
    try:
        test_split_close_delimited_not_complete_early()
        print("PASS: test_split_close_delimited_not_complete_early")
    except e:
        print("FAIL: test_split_close_delimited_not_complete_early: " + String(e))
        raise "h1 close-delimited test failed"
