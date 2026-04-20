# src/h1/h1_session.mojo
#
# Session implementation backed by ClientConnection. Exposes a feed/drain
# byte interface for tests and example I/O loops; the actual transport is
# the caller's responsibility (boucle, raw socket, mock). M2.5a §8.2.

from std.collections.deque import Deque
from std.collections.optional import Optional
from std.memory import Span
from src.h1.client import ClientConnection
from src.h1.config import ParseConfig
from src.http.body import BodyFrame
from src.http.handler import Capabilities, RecvBody
from src.http.method import Method
from src.http.request import Request
from src.http.session import Session, RequestHandle


struct H1Session(Session):
    """H1 client session — single in-flight request per connection."""

    var _conn: ClientConnection
    var _outbuf: List[UInt8]
    var _next_id: UInt64
    var _pending_handle_id: UInt64
    var _has_inflight: Bool
    var _inflight_method: Optional[Method]

    def __init__(out self):
        self._conn = ClientConnection(ParseConfig())
        self._outbuf = List[UInt8]()
        self._next_id = UInt64(0)
        self._pending_handle_id = UInt64(0)
        self._has_inflight = False
        self._inflight_method = Optional[Method]()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self._outbuf = take._outbuf^
        self._next_id = take._next_id
        self._pending_handle_id = take._pending_handle_id
        self._has_inflight = take._has_inflight
        self._inflight_method = take._inflight_method^

    # --- Session trait API ---

    def submit(mut self, var req: Request) raises -> RequestHandle:
        if self._has_inflight:
            raise Error("H1Session.submit: H1 has only one in-flight request per connection")
        if req.body.is_stream():
            raise Error("H1Session.submit: streaming request bodies not supported in v1")
        self._next_id += UInt64(1)
        self._inflight_method = Optional[Method](Method(other=req.method))
        self._conn.send_request(req^)
        self._outbuf.extend(self._conn.drain())
        self._pending_handle_id = self._next_id
        self._has_inflight = True
        return RequestHandle(id=self._next_id)

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        # H1 has at most one in-flight request, so this is a no-op once the
        # request has completed. Real callers drive the byte pump themselves.
        pass

    def run_one(mut self, mut handle: RequestHandle) raises:
        if not Bool(self._inflight_method):
            return
        var method_opt = self._inflight_method^
        var method = method_opt.take()
        var resp_opt = self._conn.next_response(Method(other=method))
        if not Bool(resp_opt):
            # Response not yet available — restore the method for the next
            # poll attempt and bail out.
            self._inflight_method = Optional[Method](method^)
            return
        if handle.id() != self._pending_handle_id:
            self._inflight_method = Optional[Method](method^)
            raise Error("H1Session.run_one: handle id does not match pending request")
        var resp = resp_opt.take()
        handle._set_response(resp^)
        handle._mark_complete()
        self._has_inflight = False
        self._inflight_method = Optional[Method]()

    def capabilities(self) -> Capabilities:
        return Capabilities.for_h1()

    def alpn(self) -> Int:
        return Capabilities.for_h1().alpn

    def close(deinit self) raises:
        pass

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        raise Error("H1Session.feed_body: streaming bodies not yet supported")

    # --- Transport bridging API ---

    def feed(mut self, data: Span[UInt8, _]) raises:
        self._conn.receive_data(data)

    def drain(mut self) -> List[UInt8]:
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^
