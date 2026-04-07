# src/http/handler.mojo
#
# Protocol-agnostic HTTP handler trait surface (M2.5a).

from std.collections.deque import Deque
from std.collections.optional import Optional
from src.http.body import BodyFrame
from src.http.config import DEFAULT_STREAM_WINDOW_HIGH, DEFAULT_STREAM_WINDOW_LOW

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

comptime _BODY_OPEN    = 0
comptime _BODY_END     = 1
comptime _BODY_ERRORED = 2


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
        if frame.is_data():
            self._bytes_buffered += UInt(len(frame.data()))
            if not self._paused and self._bytes_buffered > self._high_water:
                self._paused = True
        self._frames.append(frame^)

    def _set_end(mut self):
        if self._state == _BODY_ERRORED:
            return  # error wins
        self._state = _BODY_END
        self._frames.append(BodyFrame.end())

    def _set_error(mut self, var err: StreamError):
        if self._state == _BODY_ERRORED:
            return
        self._state = _BODY_ERRORED
        self._frames.append(BodyFrame.error(err^))
