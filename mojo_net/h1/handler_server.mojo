# src/h1/handler_server.mojo
#
# Runtime adapter that dispatches a StreamHandler against a sans-I/O
# H1 ServerConnection. Owns the connection state machine and translates
# lifecycle events into handler callbacks (M2.5a §8.1).

from std.memory import Span
from mojo_net.h1.config import ParseConfig
from mojo_net.h1.server import ServerConnection
from mojo_net.http.body import BodyFrame
from mojo_net.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    StreamHandler,
)
from mojo_net.http.headers import Headers
from mojo_net.http.request import Request
from mojo_net.http.response import Response
from mojo_net.http.status import StatusCode


struct H1HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an H1 ServerConnection. Request-at-a-time
    in v1: the entire request body is materialized before on_request fires.
    HC-4 will introduce streaming inbound bodies."""

    var _conn: ServerConnection
    var handler: Self.H
    var _outbuf: List[UInt8]

    def __init__(out self, *, var handler: Self.H):
        self._conn = ServerConnection(ParseConfig())
        self.handler = handler^
        self._outbuf = List[UInt8]()

    def __init__(out self, *, var handler: Self.H, var config: ParseConfig):
        self._conn = ServerConnection(config^)
        self.handler = handler^
        self._outbuf = List[UInt8]()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self.handler = take.handler^
        self._outbuf = take._outbuf^

    # --- Transport bridging API ---

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound transport bytes and dispatch any complete requests."""
        self._conn.receive_data(data)
        self._dispatch_pending()

    def drain(mut self) raises -> List[UInt8]:
        """Drain queued outbound bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    def should_close(self) -> Bool:
        return self._conn.should_close()

    # --- Internal: dispatch loop ---

    def _dispatch_pending(mut self) raises:
        while True:
            var req_opt = self._conn.next_request()
            if not Bool(req_opt):
                break
            var req = req_opt.take()
            self._dispatch_one(req^)

    def _dispatch_one(mut self, var req: Request) raises:
        var body = RecvBody()
        # H1 v1: parser already materialized the request body into
        # RequestBody.buffered. We hand the handler a RecvBody whose terminal
        # frame is already queued (one Data frame + End) so try_read drains
        # both, then is_end() reports True.
        if req.body.is_buffered():
            var bytes = req.body.bytes().copy()
            if len(bytes) > 0:
                body._push(BodyFrame.data(bytes^))
        body._set_end()

        var resp_writer = ResponseWriter()
        try:
            self.handler.on_request(
                req^, body, resp_writer, Capabilities.for_h1(),
            )
        except e:
            self.handler.on_reset(StreamError.local_abort(String(e)))
            return

        if not resp_writer._has_status():
            # Handler did not respond; treat as a local abort.
            self.handler.on_reset(
                StreamError.local_abort(String("handler did not call send_status"))
            )
            return

        # Drain any 1xx informational responses captured before the final
        # status, and emit them on the wire first.
        var info_statuses = resp_writer._take_informational()
        var info_headers = resp_writer._take_informational_headers()
        var ii = 0
        while ii < len(info_statuses):
            self._conn.send_informational(info_statuses[ii].copy(), Headers(other=info_headers[ii]))
            ii += 1

        var status_opt = resp_writer._take_status()
        var headers_opt = resp_writer._take_headers()
        var status = status_opt.take()
        var headers: Headers
        if Bool(headers_opt):
            headers = headers_opt.take()
        else:
            headers = Headers()

        # Materialize the response body from the queued SendBody frames.
        var body_frames = List[BodyFrame]()
        while True:
            var f_opt = resp_writer._pop_body_frame()
            if not Bool(f_opt):
                break
            var f = f_opt.take()
            if f.is_end() or f.is_error():
                continue
            body_frames.append(f^)

        var response = Response(
            status=status^,
            reason="",
            headers=headers^,
            body=body_frames^,
        )
        self._conn.send_response(response^)
        self._outbuf.extend(self._conn.drain())
