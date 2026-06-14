# src/http/session_slot.mojo
#
# SessionSlot — tagged enum wrapping H1/H2/H3 Sessions (M6a §5).

from std.collections.optional import Optional
from std.memory import Span, UnsafePointer

from navette.http.handler import Capabilities, ALPN_H1, ALPN_H2, ALPN_H3
from navette.http.session import Session, RequestHandle
from navette.http.request import Request
from navette.http.body import BodyFrame
from navette.h1.h1_session import H1Session
from navette.h2.h2_session import H2Session
from navette.h3.h3_session import H3Session


comptime SLOT_H1: UInt8 = 1
comptime SLOT_H2: UInt8 = 2
comptime SLOT_H3: UInt8 = 3


struct SessionSlot(Movable):
    """Tagged enum holding one of H1Session/H2Session/H3Session.
    Delegates Session-like methods to the active variant."""

    var kind: UInt8
    var h1: Optional[H1Session]
    var h2: Optional[H2Session]
    var h3: Optional[H3Session]
    var idle_since: UInt64       # monotonic ms, 0 = active

    def __init__(
        out self,
        *,
        kind: UInt8,
        var h1: Optional[H1Session],
        var h2: Optional[H2Session],
        var h3: Optional[H3Session],
        idle_since: UInt64,
    ):
        self.kind = kind
        self.h1 = h1^
        self.h2 = h2^
        self.h3 = h3^
        self.idle_since = idle_since

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.h1 = take.h1^
        self.h2 = take.h2^
        self.h3 = take.h3^
        self.idle_since = take.idle_since

    @staticmethod
    def from_h1(var session: H1Session) -> Self:
        return Self(
            kind=SLOT_H1,
            h1=Optional[H1Session](session^),
            h2=Optional[H2Session](),
            h3=Optional[H3Session](),
            idle_since=UInt64(0),
        )

    @staticmethod
    def from_h2(var session: H2Session) -> Self:
        return Self(
            kind=SLOT_H2,
            h1=Optional[H1Session](),
            h2=Optional[H2Session](session^),
            h3=Optional[H3Session](),
            idle_since=UInt64(0),
        )

    @staticmethod
    def from_h3(var session: H3Session) -> Self:
        return Self(
            kind=SLOT_H3,
            h1=Optional[H1Session](),
            h2=Optional[H2Session](),
            h3=Optional[H3Session](session^),
            idle_since=UInt64(0),
        )

    @staticmethod
    def empty_for_tests() raises -> Self:
        """Test-only fixture — fabricates a SessionSlot wrapping a fresh,
        unused H1Session so that downstream pool / bookkeeping tests can
        instantiate slot-bearing structs without driving real I/O.

        Do not call from production code: the embedded session has never
        seen a socket, so any submit / feed / drain on this slot will
        produce protocol-level nonsense.
        """
        return Self.from_h1(H1Session())

    def submit(mut self, var req: Request) raises -> RequestHandle:
        self.mark_active()
        if self.kind == SLOT_H1:
            return self.h1.value().submit(req^)
        elif self.kind == SLOT_H2:
            return self.h2.value().submit(req^)
        else:
            return self.h3.value().submit(req^)

    def run_one(mut self, mut handle: RequestHandle) raises:
        if self.kind == SLOT_H1:
            self.h1.value().run_one(handle)
        elif self.kind == SLOT_H2:
            self.h2.value().run_one(handle)
        else:
            self.h3.value().run_one(handle)

    def feed(mut self, data: Span[UInt8, _]) raises:
        if self.kind == SLOT_H1:
            self.h1.value().feed(data)
        elif self.kind == SLOT_H2:
            self.h2.value().feed(data)
        else:
            self.h3.value().feed_datagram(data, UInt64(0))

    def drain(mut self) raises -> List[UInt8]:
        if self.kind == SLOT_H1:
            return self.h1.value().drain()
        elif self.kind == SLOT_H2:
            return self.h2.value().drain()
        # H3 uses datagrams (List[List[UInt8]]) — concatenate into flat buffer.
        # M6c's HttpCoroClient will use drain_datagrams() directly for proper
        # UDP framing; this flat drain is a fallback for uniform API.
        var out = List[UInt8]()
        var datagrams = self.h3.value().drain_datagrams(UInt64(0))
        for i in range(len(datagrams)):
            out.extend(datagrams[i].copy())
        return out^

    def feed_datagram(
        mut self, data: Span[UInt8, _], now: UInt64
    ) raises:
        """Feed inbound bytes preserving QUIC datagram boundaries.

        For H1/H2 (byte streams) this is identical to `feed` and `now` is
        ignored — the byte path doesn't care about timestamps. For H3 it
        threads the wall-clock `now` into the QUIC stack so PTO / loss
        detection get accurate samples.
        """
        if self.kind == SLOT_H1:
            self.h1.value().feed(data)
        elif self.kind == SLOT_H2:
            self.h2.value().feed(data)
        else:
            self.h3.value().feed_datagram(data, now)

    def drain_datagrams(
        mut self, now: UInt64
    ) raises -> List[List[UInt8]]:
        """Drain outbound bytes preserving QUIC datagram boundaries.

        For H1/H2 returns a single-element list wrapping the whole flat
        byte stream (empty list when there's nothing to send). For H3,
        returns one element per QUIC packet so the caller can `send(2)`
        each with the right boundary. `now` is the QUIC clock — pass
        microsecond monotonic time at the call site for correct PTO.
        """
        var out = List[List[UInt8]]()
        if self.kind == SLOT_H3:
            return self.h3.value().drain_datagrams(now)
        var stream: List[UInt8]
        if self.kind == SLOT_H1:
            stream = self.h1.value().drain()
        else:
            stream = self.h2.value().drain()
        if len(stream) > 0:
            out.append(stream^)
        return out^

    def feed_body(mut self, handle_id: UInt64, var frame: BodyFrame) raises:
        if self.kind == SLOT_H1:
            self.h1.value().feed_body(handle_id, frame^)
        elif self.kind == SLOT_H2:
            self.h2.value().feed_body(handle_id, frame^)
        else:
            self.h3.value().feed_body(handle_id, frame^)

    def capabilities(self) -> Capabilities:
        if self.kind == SLOT_H1:
            return Capabilities.for_h1()
        if self.kind == SLOT_H2:
            return Capabilities.for_h2()
        return Capabilities.for_h3()

    def is_idle(self) -> Bool:
        return self.idle_since != UInt64(0)

    def mark_idle(mut self, now: UInt64):
        self.idle_since = now

    def mark_active(mut self):
        self.idle_since = UInt64(0)


struct SessionSlotPtr(Copyable, Movable):
    """Heap pointer wrapper for Dict storage (SessionSlot is move-only)."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[SessionSlot, MutAnyOrigin]:
        return UnsafePointer[SessionSlot, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )
