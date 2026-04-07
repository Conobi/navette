# src/http/h3_extension.mojo
#
# Standalone H3 trait + H3-specific per-stream context (M2.5a §5.10).
# M2.5a ships scaffolding only — datagram methods are stubs that return
# Closed until M5 wires up the QUIC datagram path.

from std.collections.deque import Deque
from std.collections.optional import Optional
from std.memory import Span
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    WriteResult,
)
from src.http.request import Request


struct H3Context(Movable):
    """H3-specific per-stream context. Datagram support is scaffolded
    in v1; methods return WriteResult.closed() until M5 wires them up."""

    var _stream_id: UInt64
    var _datagram_recv_queue: Deque[List[UInt8]]

    def __init__(out self, *, stream_id: UInt64):
        self._stream_id = stream_id
        self._datagram_recv_queue = Deque[List[UInt8]]()

    def __init__(out self, *, deinit take: Self):
        self._stream_id = take._stream_id
        self._datagram_recv_queue = take._datagram_recv_queue^

    def stream_id(self) -> UInt64:
        return self._stream_id

    def try_send_datagram(mut self, payload: Span[UInt8, _]) -> WriteResult:
        return WriteResult.closed()

    def try_recv_datagram(mut self) raises -> Optional[List[UInt8]]:
        if len(self._datagram_recv_queue) == 0:
            return Optional[List[UInt8]]()
        return Optional[List[UInt8]](self._datagram_recv_queue.popleft())


trait H3StreamExtension(Movable):
    """Standalone trait for HTTP/3 handlers. Does NOT inherit from
    StreamHandler. A handler that wants to serve both H3 and lower
    protocols implements both traits explicitly."""

    def on_h3_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
        caps: Capabilities,
    ) raises:
        ...

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        ...

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        ...

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises:
        ...

    def on_reset(
        mut self,
        error: StreamError,
    ):
        ...
