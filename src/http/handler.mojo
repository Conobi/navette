# src/http/handler.mojo
#
# Protocol-agnostic HTTP handler trait surface (M2.5a).
# This file currently contains: Capabilities. Subsequent tasks add the rest.

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
