# tests/test_stream_error.mojo
#
# Unit tests for StreamError (M2.5a §5.3).
from mojo_net.http.handler import (
    StreamError,
    STREAM_ERR_PEER_CLOSED,
    STREAM_ERR_RST_STREAM,
    STREAM_ERR_PARSER,
    STREAM_ERR_LOCAL_ABORT,
    STREAM_ERR_CONNECTION_CLOSED,
    STREAM_ERR_PROTOCOL,
)
from tests._test_util import assert_equal_int, assert_equal_str


def test_peer_closed_factory() raises:
    var e = StreamError.peer_closed()
    assert_equal_int(e.kind, STREAM_ERR_PEER_CLOSED, "peer_closed.kind")
    assert_equal_int(Int(e.code), 0, "peer_closed.code")


def test_rst_stream_carries_code() raises:
    var e = StreamError.rst_stream(UInt32(8))
    assert_equal_int(e.kind, STREAM_ERR_RST_STREAM, "rst_stream.kind")
    assert_equal_int(Int(e.code), 8, "rst_stream.code")


def test_parser_carries_message() raises:
    var e = StreamError.parser(String("bad framing"))
    assert_equal_int(e.kind, STREAM_ERR_PARSER, "parser.kind")
    assert_equal_str(e.message, String("bad framing"), "parser.message")


def test_protocol_carries_both() raises:
    var e = StreamError.protocol(UInt32(1), String("flow control"))
    assert_equal_int(e.kind, STREAM_ERR_PROTOCOL, "protocol.kind")
    assert_equal_int(Int(e.code), 1, "protocol.code")
    assert_equal_str(e.message, String("flow control"), "protocol.message")


def test_local_abort_and_connection_closed() raises:
    assert_equal_int(StreamError.local_abort(String("x")).kind, STREAM_ERR_LOCAL_ABORT, "local_abort.kind")
    assert_equal_int(StreamError.connection_closed().kind, STREAM_ERR_CONNECTION_CLOSED, "connection_closed.kind")


def main() raises:
    test_peer_closed_factory()
    test_rst_stream_carries_code()
    test_parser_carries_message()
    test_protocol_carries_both()
    test_local_abort_and_connection_closed()
    print("test_stream_error: all tests passed")
