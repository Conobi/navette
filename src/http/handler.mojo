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
