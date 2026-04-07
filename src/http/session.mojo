# src/http/session.mojo
#
# Client-side session abstraction (M2.5a §5.11). Defines the Session trait
# and the RequestHandle owning state container.

from std.collections.deque import Deque
from std.collections.optional import Optional
from src.http.handler import Capabilities, RecvBody, StreamError
from src.http.request import Request
from src.http.response import Response


comptime _HANDLE_PENDING          = 0
comptime _HANDLE_HEADERS_RECEIVED = 1
comptime _HANDLE_COMPLETE         = 2
comptime _HANDLE_ERRORED          = 3


struct RequestHandle(Movable):
    """Owning handle to an in-flight client request. Created by Session.submit,
    consumed by Session.run_until + take_response."""

    var _id: UInt64
    var _state: Int
    var _response: Optional[Response]
    var _recv_body: Optional[RecvBody]
    var _error: Optional[StreamError]

    def __init__(out self, *, id: UInt64):
        self._id = id
        self._state = _HANDLE_PENDING
        self._response = Optional[Response]()
        self._recv_body = Optional[RecvBody]()
        self._error = Optional[StreamError]()

    def __init__(out self, *, deinit take: Self):
        self._id = take._id
        self._state = take._state
        self._response = take._response^
        self._recv_body = take._recv_body^
        self._error = take._error^

    # --- Public API ---

    def id(self) -> UInt64:
        return self._id

    def is_complete(self) -> Bool:
        return self._state == _HANDLE_COMPLETE or self._state == _HANDLE_ERRORED

    def has_headers(self) -> Bool:
        return Bool(self._response)

    def is_errored(self) -> Bool:
        return self._state == _HANDLE_ERRORED

    def try_take_response(mut self) -> Optional[Response]:
        if not Bool(self._response):
            return Optional[Response]()
        var r = self._response^
        self._response = Optional[Response]()
        return r^

    def take_response(deinit self) raises -> Response:
        if self._state == _HANDLE_ERRORED:
            raise Error("RequestHandle.take_response: handle is errored")
        if not Bool(self._response):
            raise Error("RequestHandle.take_response: no response available")
        var r = self._response^
        return r.take()

    def take_body(mut self) raises -> RecvBody:
        if not Bool(self._recv_body):
            raise Error("RequestHandle.take_body: no body available")
        var b = self._recv_body^
        self._recv_body = Optional[RecvBody]()
        return b.take()

    # --- Runtime-internal API ---

    def _set_response(mut self, var resp: Response):
        self._response = Optional[Response](resp^)
        self._state = _HANDLE_HEADERS_RECEIVED

    def _set_recv_body(mut self, var body: RecvBody):
        self._recv_body = Optional[RecvBody](body^)

    def _mark_complete(mut self):
        self._state = _HANDLE_COMPLETE

    def _set_error(mut self, var err: StreamError):
        self._error = Optional[StreamError](err^)
        self._state = _HANDLE_ERRORED


# ---------------------------------------------------------------------------
# Session trait (§5.11)
# ---------------------------------------------------------------------------

trait Session(Movable):
    """Client-side connection session. Owns the underlying connection.
    Single-connection only; pooling lives in M6's HttpClient.

    Reentrancy:
      - Cross-session calls from inside a handler callback are SUPPORTED
        (the reverse-proxy pattern).
      - Same-session calls (calling submit on the SAME session from inside
        a handler driven by run_until) are UNSUPPORTED in v1.

    NOTE on `run_until` API: spec §5.11 sketches a `List[RequestHandle]`
    parameter, but Mojo 0.26.2's `List` and `Deque` require Copyable element
    types and `RequestHandle` is move-only (it owns Optional[RecvBody] /
    Optional[Response]). M2.5a passes a `Deque[UInt64]` of handle IDs that
    the session resolves internally. Callers register handles via `submit`,
    keep them, and pass the corresponding IDs to wait on."""

    def submit(mut self, var req: Request) raises -> RequestHandle:
        ...

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        ...

    def run_one(mut self, mut handle: RequestHandle) raises:
        ...

    def capabilities(self) -> Capabilities:
        ...

    def alpn(self) -> Int:
        ...

    def close(deinit self) raises:
        ...
