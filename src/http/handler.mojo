# src/http/handler.mojo
#
# Protocol-agnostic HTTP handler trait surface (M2.5a).

from std.collections.deque import Deque
from std.collections.optional import Optional
from src.http.body import BodyFrame
from src.http.config import DEFAULT_STREAM_WINDOW_HIGH, DEFAULT_STREAM_WINDOW_LOW
from src.http.headers import Headers
from src.http.status import StatusCode
from src.http.request import Request

comptime ALPN_H1 = 0
comptime ALPN_H2 = 1
comptime ALPN_H3 = 2


struct Capabilities(Copyable, Movable):
    """Per-stream protocol capability flags. Cheap to copy. Passed to handlers
    on every lifecycle callback so they can branch on protocol features."""

    var multiplexed: Bool
    var trailers: Bool
    var priority_hints: Bool
    var datagrams: Bool
    var alpn: Int

    def __init__(
        out self,
        *,
        multiplexed: Bool,
        trailers: Bool,
        priority_hints: Bool,
        datagrams: Bool,
        alpn: Int,
    ):
        self.multiplexed = multiplexed
        self.trailers = trailers
        self.priority_hints = priority_hints
        self.datagrams = datagrams
        self.alpn = alpn

    def __init__(out self, *, other: Self):
        self.multiplexed = other.multiplexed
        self.trailers = other.trailers
        self.priority_hints = other.priority_hints
        self.datagrams = other.datagrams
        self.alpn = other.alpn

    def __init__(out self, *, deinit take: Self):
        self.multiplexed = take.multiplexed
        self.trailers = take.trailers
        self.priority_hints = take.priority_hints
        self.datagrams = take.datagrams
        self.alpn = take.alpn

    @staticmethod
    def for_h1() -> Self:
        return Self(
            multiplexed=False, trailers=False, priority_hints=False,
            datagrams=False, alpn=ALPN_H1,
        )

    @staticmethod
    def for_h2() -> Self:
        return Self(
            multiplexed=True, trailers=True, priority_hints=True,
            datagrams=False, alpn=ALPN_H2,
        )

    @staticmethod
    def for_h3() -> Self:
        return Self(
            multiplexed=True, trailers=True, priority_hints=True,
            datagrams=True, alpn=ALPN_H3,
        )

    def is_h1(self) -> Bool:
        return self.alpn == ALPN_H1

    def is_h2(self) -> Bool:
        return self.alpn == ALPN_H2

    def is_h3(self) -> Bool:
        return self.alpn == ALPN_H3

    def alpn_string(self) -> String:
        if self.alpn == ALPN_H1:
            return String("http/1.1")
        if self.alpn == ALPN_H2:
            return String("h2")
        if self.alpn == ALPN_H3:
            return String("h3")
        return String("unknown")


# ---------------------------------------------------------------------------
# StreamError (§5.3)
# ---------------------------------------------------------------------------

# Stream error kinds. Public — handlers may pattern-match.
comptime STREAM_ERR_PEER_CLOSED       = 0
comptime STREAM_ERR_RST_STREAM        = 1
comptime STREAM_ERR_PARSER            = 2
comptime STREAM_ERR_LOCAL_ABORT       = 3
comptime STREAM_ERR_CONNECTION_CLOSED = 4
comptime STREAM_ERR_PROTOCOL          = 5


struct StreamError(Copyable, Movable):
    """Per-stream error. `code` is the protocol-specific error code (H2/H3
    stream error code; 0 for H1 since H1 has no per-stream codes)."""

    var kind: Int
    var code: UInt32
    var message: String

    def __init__(out self, *, kind: Int, code: UInt32, var message: String):
        self.kind = kind
        self.code = code
        self.message = message^

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.code = other.code
        self.message = other.message.copy()

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.code = take.code
        self.message = take.message^

    @staticmethod
    def peer_closed() -> Self:
        return Self(kind=STREAM_ERR_PEER_CLOSED, code=UInt32(0), message=String("peer closed"))

    @staticmethod
    def rst_stream(code: UInt32) -> Self:
        return Self(kind=STREAM_ERR_RST_STREAM, code=code, message=String("rst_stream"))

    @staticmethod
    def parser(var message: String) -> Self:
        return Self(kind=STREAM_ERR_PARSER, code=UInt32(0), message=message^)

    @staticmethod
    def local_abort(var message: String) -> Self:
        return Self(kind=STREAM_ERR_LOCAL_ABORT, code=UInt32(0), message=message^)

    @staticmethod
    def connection_closed() -> Self:
        return Self(kind=STREAM_ERR_CONNECTION_CLOSED, code=UInt32(0), message=String("connection closed"))

    @staticmethod
    def protocol(code: UInt32, var message: String) -> Self:
        return Self(kind=STREAM_ERR_PROTOCOL, code=code, message=message^)


# ---------------------------------------------------------------------------
# WriteResult (§5.4)
# ---------------------------------------------------------------------------

comptime _WRITE_OK          = 0
comptime _WRITE_WOULD_BLOCK = 1
comptime _WRITE_CLOSED      = 2


struct WriteResult(Copyable, Movable):
    """Result of a backpressure-aware write. Tagged enum: Ok | WouldBlock | Closed."""

    var tag: Int

    def __init__(out self, *, tag: Int):
        self.tag = tag

    def __init__(out self, *, other: Self):
        self.tag = other.tag

    def __init__(out self, *, deinit take: Self):
        self.tag = take.tag

    @staticmethod
    def ok() -> Self:
        return Self(tag=_WRITE_OK)

    @staticmethod
    def would_block() -> Self:
        return Self(tag=_WRITE_WOULD_BLOCK)

    @staticmethod
    def closed() -> Self:
        return Self(tag=_WRITE_CLOSED)

    def is_ok(self) -> Bool:
        return self.tag == _WRITE_OK

    def is_would_block(self) -> Bool:
        return self.tag == _WRITE_WOULD_BLOCK

    def is_closed(self) -> Bool:
        return self.tag == _WRITE_CLOSED


# ---------------------------------------------------------------------------
# RecvBody (§5.6)
# ---------------------------------------------------------------------------

comptime _BODY_OPEN     = 0
comptime _BODY_END      = 1
comptime _BODY_ERRORED  = 2
comptime _BODY_DETACHED = 3


struct RecvBody(Movable):
    """Inbound body stream. Sans-I/O queue: the runtime pushes BodyFrames as
    they arrive from the wire; the handler pulls via try_read.

    Backpressure: when bytes_buffered exceeds high_water, _paused becomes True
    and the runtime is expected to stop reading from the transport for this
    stream. When bytes_buffered drains back below low_water, _paused returns
    to False.

    Frame ordering rule: zero-or-more Data, optional Trailers, then exactly
    one terminal frame (End or Error). Once the terminal is consumed,
    is_end() is True forever and subsequent try_reads return None."""

    var _frames: Deque[BodyFrame]
    var _state: Int
    var _bytes_buffered: UInt
    var _high_water: UInt
    var _low_water: UInt
    var _paused: Bool
    var _terminal_consumed: Bool

    def __init__(out self):
        self._frames = Deque[BodyFrame]()
        self._state = _BODY_OPEN
        self._bytes_buffered = UInt(0)
        self._high_water = UInt(DEFAULT_STREAM_WINDOW_HIGH)
        self._low_water = UInt(DEFAULT_STREAM_WINDOW_LOW)
        self._paused = False
        self._terminal_consumed = False

    def __init__(out self, *, deinit take: Self):
        self._frames = take._frames^
        self._state = take._state
        self._bytes_buffered = take._bytes_buffered
        self._high_water = take._high_water
        self._low_water = take._low_water
        self._paused = take._paused
        self._terminal_consumed = take._terminal_consumed

    # --- Public API ---

    def try_read(mut self) raises -> Optional[BodyFrame]:
        if len(self._frames) == 0:
            return Optional[BodyFrame]()
        var frame = self._frames.popleft()
        if frame.is_data():
            self._bytes_buffered -= UInt(len(frame.data()))
            if self._paused and self._bytes_buffered <= self._low_water:
                self._paused = False
        if frame.is_end() or frame.is_error():
            self._terminal_consumed = True
        return Optional[BodyFrame](frame^)

    def is_end(self) -> Bool:
        return self._terminal_consumed

    def is_errored(self) -> Bool:
        return self._state == _BODY_ERRORED

    def bytes_buffered(self) -> UInt:
        return self._bytes_buffered

    def set_watermarks(mut self, *, high: UInt, low: UInt):
        self._high_water = high
        self._low_water = low

    def is_paused(self) -> Bool:
        return self._paused

    # --- Runtime-internal API ---

    def _push(mut self, var frame: BodyFrame):
        # Drop pushes after the body has been terminated. This guards against
        # cross-layer ordering bugs that would otherwise corrupt the
        # "exactly one terminal frame" invariant.
        if self._state != _BODY_OPEN:
            return
        if frame.is_data():
            self._bytes_buffered += UInt(len(frame.data()))
            if not self._paused and self._bytes_buffered > self._high_water:
                self._paused = True
        self._frames.append(frame^)

    def _set_end(mut self):
        if self._state != _BODY_OPEN:
            return  # idempotent: error wins, second end is a no-op
        self._state = _BODY_END
        self._frames.append(BodyFrame.end())

    def _set_error(mut self, var err: StreamError):
        if self._state == _BODY_ERRORED or self._state == _BODY_DETACHED:
            return
        self._state = _BODY_ERRORED
        self._frames.append(BodyFrame.error(err^))

    def try_detach(mut self) -> Optional[DetachedBody]:
        """Non-consuming detach. Swaps internals into a new DetachedBody,
        leaves self as a _BODY_DETACHED tombstone. Returns None if body is
        not in _BODY_OPEN state. Use Optional.unsafe_take() to extract —
        Optional.value() copies, which fails for move-only DetachedBody."""
        if self._state != _BODY_OPEN:
            return Optional[DetachedBody]()
        # Move frames out of self into a fresh RecvBody for the DetachedBody.
        # self._frames^ moves the Deque; immediate reinit satisfies the
        # compiler's use-after-move check.
        var inner = RecvBody()
        inner._frames = self._frames^
        self._frames = Deque[BodyFrame]()
        inner._state = self._state
        inner._bytes_buffered = self._bytes_buffered
        inner._high_water = self._high_water
        inner._low_water = self._low_water
        inner._paused = self._paused
        inner._terminal_consumed = self._terminal_consumed
        # Tombstone: _BODY_DETACHED makes _push/_set_end/_set_error no-ops
        self._state = _BODY_DETACHED
        self._bytes_buffered = UInt(0)
        self._paused = False
        self._terminal_consumed = False
        return Optional[DetachedBody](DetachedBody(take_body=inner^))

    # --- Detach (§5.5, §5.7) ---

    def detach(deinit self) -> DetachedBody:
        """Move this RecvBody into a DetachedBody owned by the handler. The
        runtime keeps a typed pointer to the detached body for continued
        frame pushes. Detach is one-way: no resurrection."""
        return DetachedBody(take_body=self^)


# ---------------------------------------------------------------------------
# DetachedBody (§5.5)
# ---------------------------------------------------------------------------

struct DetachedBody(Movable):
    """Owned RecvBody that has been moved out of the runtime's per-stream
    state. Once detached, the runtime stops invoking on_body_available /
    on_request_end for this stream — the handler is fully responsible for
    draining frames. Detach is one-way; resurrection is forbidden."""

    var _inner: RecvBody

    def __init__(out self, *, var take_body: RecvBody):
        self._inner = take_body^

    def __init__(out self, *, deinit take: Self):
        self._inner = take._inner^

    def try_read(mut self) raises -> Optional[BodyFrame]:
        return self._inner.try_read()

    def is_end(self) -> Bool:
        return self._inner.is_end()

    def is_errored(self) -> Bool:
        return self._inner.is_errored()

    def bytes_buffered(self) -> UInt:
        return self._inner.bytes_buffered()

    def take_inner(deinit self) -> RecvBody:
        """Consume the DetachedBody and return the underlying RecvBody. The
        returned RecvBody MUST NOT be re-attached to the runtime — detach is
        one-way and the runtime no longer holds a stable handle to it."""
        return self._inner^

    # --- Runtime-internal: forwarded so the runtime can keep pushing ---
    def _push(mut self, var frame: BodyFrame):
        self._inner._push(frame^)

    def _set_end(mut self):
        self._inner._set_end()

    def _set_error(mut self, var err: StreamError):
        self._inner._set_error(err^)


# ---------------------------------------------------------------------------
# SendBody (§5.7)
# ---------------------------------------------------------------------------

comptime _SEND_OPEN    = 0
comptime _SEND_ENDED   = 1
comptime _SEND_ABORTED = 2


struct SendBody(Movable):
    """Outbound body stream. Handlers write frames; the runtime drains them."""

    var _frames: Deque[BodyFrame]
    var _state: Int
    var _bytes_buffered: UInt
    var _high_water: UInt
    var _low_water: UInt
    var _abort_code: UInt32

    def __init__(out self):
        self._frames = Deque[BodyFrame]()
        self._state = _SEND_OPEN
        self._bytes_buffered = UInt(0)
        self._high_water = UInt(DEFAULT_STREAM_WINDOW_HIGH)
        self._low_water = UInt(DEFAULT_STREAM_WINDOW_LOW)
        self._abort_code = UInt32(0)

    def __init__(out self, *, deinit take: Self):
        self._frames = take._frames^
        self._state = take._state
        self._bytes_buffered = take._bytes_buffered
        self._high_water = take._high_water
        self._low_water = take._low_water
        self._abort_code = take._abort_code

    def try_write(mut self, var frame: BodyFrame) -> WriteResult:
        if self._state != _SEND_OPEN:
            return WriteResult.closed()
        if frame.is_data():
            self._bytes_buffered += UInt(len(frame.data()))
        self._frames.append(frame^)
        if self._bytes_buffered > self._high_water:
            return WriteResult.would_block()
        return WriteResult.ok()

    def end(mut self) raises:
        if self._state != _SEND_OPEN:
            raise Error("SendBody.end: stream is not open")
        self._state = _SEND_ENDED
        self._frames.append(BodyFrame.end())

    def abort(mut self, code: UInt32) raises:
        if self._state == _SEND_ABORTED:
            raise Error("SendBody.abort: already aborted")
        self._state = _SEND_ABORTED
        self._abort_code = code
        # Drop any queued frames — abort means cancel: the runtime must not
        # emit a half-body before the RST/close.
        self._frames = Deque[BodyFrame]()
        self._bytes_buffered = UInt(0)

    def bytes_buffered(self) -> UInt:
        return self._bytes_buffered

    def set_watermarks(mut self, *, high: UInt, low: UInt):
        self._high_water = high
        self._low_water = low

    def is_ended(self) -> Bool:
        return self._state == _SEND_ENDED

    def is_aborted(self) -> Bool:
        return self._state == _SEND_ABORTED

    def abort_code(self) -> UInt32:
        return self._abort_code

    def _pop(mut self) raises -> Optional[BodyFrame]:
        if len(self._frames) == 0:
            return Optional[BodyFrame]()
        var frame = self._frames.popleft()
        if frame.is_data():
            self._bytes_buffered -= UInt(len(frame.data()))
        return Optional[BodyFrame](frame^)


# ---------------------------------------------------------------------------
# ResponseWriter (§5.8)
# ---------------------------------------------------------------------------

struct ResponseWriter(Movable):
    """Server-side outbound writer. Composes status/headers send with a
    SendBody. send_status must be called before any try_send_body. The
    runtime owns the actual byte emission for status/headers; M2.5a stores
    them in _captured_status / _captured_headers and the H1 adapter polls
    them after each handler invocation."""

    var _status_sent: Bool
    var _send_body: SendBody
    var _captured_status: Optional[StatusCode]
    var _captured_headers: Optional[Headers]
    var _captured_informational: List[StatusCode]
    var _captured_informational_headers: List[Headers]

    def __init__(out self):
        self._status_sent = False
        self._send_body = SendBody()
        self._captured_status = Optional[StatusCode]()
        self._captured_headers = Optional[Headers]()
        self._captured_informational = List[StatusCode]()
        self._captured_informational_headers = List[Headers]()

    def __init__(out self, *, deinit take: Self):
        self._status_sent = take._status_sent
        self._send_body = take._send_body^
        self._captured_status = take._captured_status^
        self._captured_headers = take._captured_headers^
        self._captured_informational = take._captured_informational^
        self._captured_informational_headers = take._captured_informational_headers^

    def send_status(mut self, var status: StatusCode, var headers: Headers) raises:
        if self._status_sent:
            raise Error("ResponseWriter.send_status: already sent")
        self._status_sent = True
        self._captured_status = Optional[StatusCode](status^)
        self._captured_headers = Optional[Headers](headers^)

    def send_informational(mut self, var status: StatusCode, var headers: Headers) raises:
        if self._status_sent:
            raise Error("ResponseWriter.send_informational: status already sent")
        if not status.is_informational():
            raise Error("ResponseWriter.send_informational: status is not 1xx")
        self._captured_informational.append(status^)
        self._captured_informational_headers.append(headers^)

    def try_send_body(mut self, var frame: BodyFrame) raises -> WriteResult:
        if not self._status_sent:
            raise Error("ResponseWriter.try_send_body: status not sent yet")
        return self._send_body.try_write(frame^)

    def end(mut self) raises:
        if not self._status_sent:
            raise Error("ResponseWriter.end: status not sent yet")
        self._send_body.end()

    def abort(mut self, code: UInt32) raises:
        self._send_body.abort(code)

    def bytes_buffered(self) -> UInt:
        return self._send_body.bytes_buffered()

    # --- Runtime-internal API (called by the H1 adapter) ---
    def _has_status(self) -> Bool:
        return self._status_sent

    def _take_status(mut self) -> Optional[StatusCode]:
        var s = self._captured_status^
        self._captured_status = Optional[StatusCode]()
        return s^

    def _take_headers(mut self) -> Optional[Headers]:
        var h = self._captured_headers^
        self._captured_headers = Optional[Headers]()
        return h^

    def _take_informational(mut self) -> List[StatusCode]:
        """Drain any captured informational (1xx) status codes. The H1 adapter
        polls this after each handler invocation and pairs each entry with the
        corresponding headers from `_take_informational_headers()`."""
        var s = self._captured_informational^
        self._captured_informational = List[StatusCode]()
        return s^

    def _take_informational_headers(mut self) -> List[Headers]:
        """Drain any captured informational (1xx) headers. Order matches
        `_take_informational()` and entries pair index-by-index."""
        var h = self._captured_informational_headers^
        self._captured_informational_headers = List[Headers]()
        return h^

    def _pop_body_frame(mut self) raises -> Optional[BodyFrame]:
        return self._send_body._pop()


# ---------------------------------------------------------------------------
# StreamHandler trait (§5.9)
# ---------------------------------------------------------------------------

trait StreamHandler(Movable, ImplicitlyDestructible):
    """Server-side request handler. The runtime calls these methods as the
    request lifecycle progresses. Lifecycle order per stream:

        on_request                 (exactly once)
        on_body_available*         (0..N, only if body NOT detached)
        on_request_end             (exactly once after End frame, if not detached)
        on_send_drained*           (0..N, after try_send_body returned WouldBlock)
        on_reset                   (at most once, if the stream is reset)

    If the handler calls body.detach() inside on_request, on_body_available
    and on_request_end are NOT invoked for that stream — the handler is
    responsible for draining the DetachedBody itself."""

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises:
        ...

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        ...

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises:
        ...

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises:
        ...

    def on_reset(
        mut self,
        error: StreamError,
    ):
        ...
