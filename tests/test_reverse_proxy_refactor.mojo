# tests/test_reverse_proxy_refactor.mojo
#
# Validates the reverse-proxy pattern against the M2.5a trait surface
# (M2.5a §8.3). The test composes a `ProxyHandler` (a `StreamHandler`
# parameterized over a `Session`) with a `MockSession` backend so the
# entire flow is in-process and synchronous: detach inbound body, wrap as
# RequestBody.stream, submit to backend, project the backend response onto
# the frontend writer.
#
# The full main.mojo refactor (replacing the I/O loop in
# examples/reverse_proxy/main.mojo) is intentionally deferred — that file
# has pre-existing compilation errors on main (boucle.net path imports +
# duplicate __init__) that are out of scope for M2.5a. The purpose of this
# test is to prove the trait surface supports the proxy pattern.

from src.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.session import Session, RequestHandle
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.method import Method
from src.http.headers import Headers
from src.http.status import StatusCode
from src.http.body import BodyFrame
from src.http.mock_session import MockServer, MockSession
from tests._test_util import assert_true, assert_equal_int


# --- Backend handler used by the proxy's MockSession ---
struct BackendEcho(StreamHandler):
    def __init__(out self):
        pass

    def __init__(out self, *, deinit take: Self):
        pass

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        var headers = Headers()
        headers.add("via", "1.1 backend")
        resp.send_status(StatusCode(200), headers^)
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


# --- ProxyHandler: detach inbound body, forward via Session, project the
#     backend response onto the frontend writer.
struct ProxyHandler[Backend: Session](StreamHandler):
    var backend: Self.Backend

    def __init__(out self, *, var backend: Self.Backend):
        self.backend = backend^

    def __init__(out self, *, deinit take: Self):
        self.backend = take.backend^

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        # Detach inbound body and wrap as a streaming outbound RequestBody.
        var detached = body^.detach()
        var outbound = Request(
            method=Method(other=req.method),
            target=req.target,
            headers=Headers(other=req.headers),
            body=RequestBody.stream(detached^),
        )
        var handle = self.backend.submit(outbound^)
        self.backend.run_one(handle)
        var backend_resp = handle^.take_response()
        resp.send_status(
            StatusCode(other=backend_resp.status),
            Headers(other=backend_resp.headers),
        )
        resp.end()

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_request_end(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        pass

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        pass

    def on_reset(mut self, error: StreamError):
        pass


def test_proxy_forwards_via_session_substrate() raises:
    # Build the in-process backend: MockSession[BackendEcho].
    var backend_server = MockServer[BackendEcho](handler=BackendEcho())
    var backend_session = MockSession[BackendEcho](server=backend_server^)

    # Wrap the backend session in a ProxyHandler.
    var proxy = ProxyHandler[MockSession[BackendEcho]](backend=backend_session^)

    # Drive the proxy directly via on_request (the H1HandlerServer path is
    # exercised by tests/test_h1_server_handler.mojo).
    var req = Request(
        method=Method.get(),
        target=String("/upstream"),
        body=RequestBody.empty(),
    )
    var inbound_body = RecvBody()
    inbound_body._set_end()
    var resp_writer = ResponseWriter()
    proxy.on_request(req^, inbound_body^, resp_writer, Capabilities.for_h1())

    # Drain the proxy's captured status to verify the projection succeeded.
    var status_opt = resp_writer._take_status()
    assert_true(Bool(status_opt), "proxy.captured_status")
    var status = status_opt.take()
    assert_equal_int(Int(status.code()), 200, "proxy.status_code")

    var headers_opt = resp_writer._take_headers()
    assert_true(Bool(headers_opt), "proxy.captured_headers")
    var headers = headers_opt.take()
    assert_true(headers.has("via"), "proxy.via_header_projected")


def main() raises:
    test_proxy_forwards_via_session_substrate()
    print("test_reverse_proxy_refactor: all tests passed")
