# src/http/mock_session.mojo
#
# In-memory H1 substrate for trait conformance tests (M2.5a §5).
# Lives in src/, not tests/, so HC-4 / M5 / application code can import it
# without depending on test infrastructure. v1 only models H1 mode (single
# in-flight request, no multiplexing).

from std.collections.deque import Deque
from std.collections.optional import Optional
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamHandler,
    StreamError,
)
from src.http.body import BodyFrame
from src.http.session import Session, RequestHandle
from src.http.request import Request
from src.http.response import Response
from src.http.headers import Headers
from src.http.status import StatusCode


struct MockServer[H: StreamHandler](Movable):
    """Drives a single StreamHandler in-process. Each request is dispatched
    by calling on_request synchronously. The mock does not multiplex."""

    var handler: Self.H
    var caps: Capabilities

    def __init__(out self, *, var handler: Self.H):
        self.handler = handler^
        self.caps = Capabilities.for_h1()

    def __init__(out self, *, deinit take: Self):
        self.handler = take.handler^
        self.caps = take.caps^

    def dispatch(mut self, var req: Request) raises -> Response:
        var body = RecvBody()
        body._set_end()  # mock has no streaming inbound bodies in v1
        var resp_writer = ResponseWriter()
        self.handler.on_request(req^, body, resp_writer, Capabilities(other=self.caps))
        # Drain captured status/headers into a Response. Body frames are
        # accessible via _pop_body_frame; the mock discards them since
        # Response.body is List[BodyFrame] and trait conformance tests only
        # exercise status/headers in v1.
        var status_opt = resp_writer._take_status()
        var headers_opt = resp_writer._take_headers()
        if not Bool(status_opt):
            raise Error("MockServer.dispatch: handler did not call send_status")
        var status = status_opt.take()
        var headers: Headers
        if Bool(headers_opt):
            headers = headers_opt.take()
        else:
            headers = Headers()
        return Response(status=status^, headers=headers^)


struct MockSession[H: StreamHandler](Session):
    """Session that routes every submitted request to a single MockServer."""

    var _server: MockServer[Self.H]
    var _next_id: UInt64
    var _pending: Optional[Request]

    def __init__(out self, *, var server: MockServer[Self.H]):
        self._server = server^
        self._next_id = UInt64(0)
        self._pending = Optional[Request]()

    def __init__(out self, *, deinit take: Self):
        self._server = take._server^
        self._next_id = take._next_id
        self._pending = take._pending^

    def submit(mut self, var req: Request) raises -> RequestHandle:
        self._next_id += UInt64(1)
        self._pending = Optional[Request](req^)
        return RequestHandle(id=self._next_id)

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        # Mock is synchronous: every submit's request is drained on the next
        # `run_one`. The IDs are unused here because the mock holds at most
        # one pending request.
        pass

    def run_one(mut self, mut handle: RequestHandle) raises:
        if not Bool(self._pending):
            return
        var pending = self._pending^
        self._pending = Optional[Request]()
        var req = pending.take()
        var resp = self._server.dispatch(req^)
        handle._set_response(resp^)
        handle._mark_complete()

    def capabilities(self) -> Capabilities:
        return Capabilities(other=self._server.caps)

    def alpn(self) -> Int:
        return self._server.caps.alpn

    def close(deinit self) raises:
        pass

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        pass
