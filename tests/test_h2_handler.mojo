# tests/test_h2_handler.mojo
#
# Minimal smoke test for H2HandlerServer (M5.5 Task 4).

from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request
from src.h2.h2_handler_server import H2HandlerServer


# ---------------------------------------------------------------------------
# _DummyHandler — empty StreamHandler implementation
# ---------------------------------------------------------------------------


struct _DummyHandler(StreamHandler):

    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        pass

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        pass

    def on_reset(
        mut self,
        error: StreamError,
    ):
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_construct_and_drain() raises:
    """Construct H2HandlerServer, drain initial output (server SETTINGS
    preface).  Verify it's non-empty."""
    var server = H2HandlerServer[_DummyHandler](handler=_DummyHandler())
    var initial = server.drain()
    if len(initial) == 0:
        raise Error("expected non-empty initial output (server SETTINGS preface)")
    # A SETTINGS frame is at least 9 bytes (frame header) + payload.
    if len(initial) < 9:
        raise Error(
            "initial output too short for a SETTINGS frame: "
            + String(len(initial))
            + " bytes"
        )
    print("PASS test_construct_and_drain")


def test_should_close_initially_false() raises:
    """A freshly constructed server should not be closed."""
    var server = H2HandlerServer[_DummyHandler](handler=_DummyHandler())
    _ = server.drain()
    if server.should_close():
        raise Error("expected should_close() == False on a fresh connection")
    print("PASS test_should_close_initially_false")


def main() raises:
    test_construct_and_drain()
    test_should_close_initially_false()
    print("PASS")
