# src/h3/h3_streaming_server.mojo
#
# HTTP/3 server-side adapter for STREAMING handlers. Each stream gets a
# 64 KiB stackful coroutine (boucle.stackful) so the handler can suspend
# across upstream I/O boundaries (LLM token emission, SSE, gRPC server-
# streaming, reverse proxy, file upload). Companion to
# `src/h3/h3_sync_server.mojo` — that's the default tier; this is opt-in.
#
# R8' compile-time budget: size_of[H3StreamingCtx]() < 96 KiB.
# R1' grep gate: this file IS allowed to import boucle.stackful.
#
# Backpressure note (Sprint 2 design): write_chunk calls H3Connection.send_data
# directly and returns. H3 does not surface FC backpressure to the caller;
# QUIC's per-stream FC absorbs slow consumers transparently. No WouldBlock
# handling is needed at this layer. If the handler emits faster than the
# QUIC stream window can accept, the data accumulates in QuicConnection's
# send buffers (bounded by the QUIC stream window). Production rate
# limiting is the handler's responsibility, not the streaming-server's.
#
# API note: boucle.stackful's CoroBody type is:
#   fn (mut CoroYielder) raises -> None
# The handler receives its per-stream ctx via yld.user_data() cast to
# UnsafePointer[H3StreamingCtx, MutAnyOrigin]. This matches the CoroBody
# signature exactly.
#
# CoroYielder.yield_to_caller() is the suspension primitive (not .suspend()).
# The helper functions next_chunk / write_chunk / finish call yield_to_caller
# internally so handlers can use them directly.
#
# See plans/2026-04-27-sprint-2b-streaming.md.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

from boucle.stackful import (
    CoroutinePool,
    CoroHandle,
    CoroYielder,
    CoroBody,
)

from navette.quic.connection import QuicConnection
from navette.h3.connection import H3Connection, H3Event
from navette.h3.error import H3_REQUEST_CANCELLED
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.method import Method
from navette.http.request import Request
from navette.http.status import StatusCode
from navette.http.version import Version


# ---------------------------------------------------------------------------
# H3StreamingHandlerFn — handler type alias
# ---------------------------------------------------------------------------
#
# Must match boucle.stackful.CoroBody exactly:
#   fn (mut CoroYielder) raises -> None
#
# Inside the body, access the per-stream ctx via:
#   var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
#
# The handler may call next_chunk(ctx_ptr, yld) / write_chunk(ctx_ptr, yld, bytes)
# / finish(ctx_ptr, yld) to suspend across event-loop passes.

comptime H3StreamingHandlerFn = CoroBody


# ---------------------------------------------------------------------------
# H3StreamingCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct H3StreamingCtx(Movable):
    """Per-stream context for H3 streaming serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.

    Extends the sync-server CoroStreamCtx shape with:
      - body_frame_ring: incoming body frames drained by next_chunk()
      - cancelled:       set true by adapter on peer reset / GOAWAY
      - coro_addr:       address of heap-allocated CoroHandle (0 = none)

    No writer_pending_chunk field — Option A: write_chunk does not suspend
    on backpressure; QUIC's send_data absorbs output transparently.
    """

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt64
    var extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool
    var body_frame_ring: List[BodyFrame]
    var cancelled: Bool
    var coro_addr: UInt64

    def __init__(
        out self,
        var request: Request,
        caps: Capabilities,
        stream_id: UInt64,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin],
    ):
        self.request = request^
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.caps = Capabilities(other=caps)
        self.stream_id = stream_id
        self.extra_data = extra_data
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False
        self.body_frame_ring = List[BodyFrame]()
        self.cancelled = False
        self.coro_addr = UInt64(0)

    def __init__(out self, *, deinit take: Self):
        self.request = take.request^
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.caps = take.caps^
        self.stream_id = take.stream_id
        self.extra_data = take.extra_data
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent
        self.body_frame_ring = take.body_frame_ring^
        self.cancelled = take.cancelled
        self.coro_addr = take.coro_addr

    def coro_ptr(self) -> UnsafePointer[CoroHandle, MutAnyOrigin]:
        """Convert coro_addr to a typed CoroHandle pointer."""
        return UnsafePointer[CoroHandle, MutAnyOrigin](
            unsafe_from_address=Int(self.coro_addr)
        )


# ---------------------------------------------------------------------------
# Per-stream memory budget (R8' in the sprint roadmap)
# ---------------------------------------------------------------------------
#
# 64 KiB stack (boucle.stackful default) is heap-allocated INSIDE the
# CoroHandle (pointed to by coro_addr); not counted toward H3StreamingCtx's
# direct size. The struct itself holds: Request + RecvBody + ResponseWriter +
# Capabilities + stream_id + extra_data + coro_addr + 3 bools + body_frame_ring +
# cancelled bool. Should land around the same size as the sync ctx (~600 B)
# plus the body_frame_ring overhead (List[BodyFrame] = pointer + len + cap = ~24 B
# header + variable content). Streaming ctx total: well under 96 KiB.


def _check_streaming_ctx_size():
    comptime assert size_of[H3StreamingCtx]() < 96 * 1024, (
        "H3StreamingCtx exceeded R8' budget (96 KiB) — investigate"
        " before raising the cap"
    )


# ---------------------------------------------------------------------------
# Streaming-handler API helpers (Option A — direct call, no WouldBlock)
# ---------------------------------------------------------------------------


def next_chunk(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises -> Optional[BodyFrame]:
    """Yield the next body chunk. Suspends if none ready. Returns None on EOF.
    Polls cancellation between suspends."""
    while not ctx_ptr[].request_ended and len(ctx_ptr[].body_frame_ring) == 0:
        if ctx_ptr[].cancelled:
            raise Error("H3StreamCancelled")
        yld.yield_to_caller()
    if len(ctx_ptr[].body_frame_ring) > 0:
        # FIFO: pop(0) preserves arrival order. Default pop() is LIFO and
        # would deliver multi-chunk bodies to the handler in reverse order.
        var frame = ctx_ptr[].body_frame_ring.pop(0)
        return Optional[BodyFrame](frame^)
    return Optional[BodyFrame](None)


def write_chunk(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
    var bytes: List[UInt8],
) raises:
    """Send a body chunk via H3Connection.send_data. Does NOT suspend on
    backpressure — H3's send_data does not surface WouldBlock; QUIC's
    per-stream FC absorbs slow consumers internally. The yld parameter is
    accepted for API symmetry (and future-proofing) but unused in this
    implementation. If the handler emits faster than the QUIC stream window
    can accept, data accumulates in QuicConnection's internal buffers.

    The actual H3Connection.send_data call happens in the streaming server's
    _drain_responses on the next event-loop pass — write_chunk just buffers
    the chunk into ctx.resp_writer for the drain to pick up."""
    if ctx_ptr[].cancelled:
        raise Error("H3StreamCancelled")
    # Buffer the data into resp_writer via try_send_body.
    # The adapter's _drain_responses calls H3Connection.send_data with
    # this content + fin=False on each event-loop pass.
    var frame = BodyFrame.data(bytes^)
    _ = ctx_ptr[].resp_writer.try_send_body(frame^)


def finish(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    """Close the response body. The handler should return immediately after
    this call. Adapter's _drain_responses sends the final FIN on the next
    event-loop pass.

    Design note: finish() is synchronous — it buffers the end BodyFrame into
    resp_writer but does NOT call yield_to_caller(). The handler returns and
    the coro reaches DONE state. On the next feed_datagram call, _drain_responses
    processes the buffered end frame and sets response_ended=True.

    Why no yield_to_caller here? If finish() suspended, the coro would be in
    SUSPENDED state when _maybe_cleanup_stream (called from _on_stream_ended)
    runs — which triggers a boucle debug_assert when destroying the still-
    suspended CoroHandle. Keeping finish() synchronous avoids that invariant
    violation and is simpler: the handler just returns and the coro is DONE."""
    ctx_ptr[].resp_writer.end()
    # yld is accepted for API symmetry; not used because finish is synchronous.


def cancelled(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin]
) -> Bool:
    return ctx_ptr[].cancelled


# ---------------------------------------------------------------------------
# _StreamingPtr — thin wrapper so Dict[Int, _StreamingPtr] satisfies
# CollectionElement (Copyable + Movable).
# ---------------------------------------------------------------------------


struct _StreamingPtr(Copyable, Movable):
    """Holds the address of a heap-allocated H3StreamingCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[H3StreamingCtx, MutAnyOrigin]:
        return UnsafePointer[H3StreamingCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# _free_streaming_stream — DESTRUCTOR-PATH-ONLY cleanup for H3StreamingCtx
# ---------------------------------------------------------------------------


def _free_streaming_stream(ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin]):
    """DESTRUCTOR PATH ONLY. Bypasses the ctx pool. Runtime sites must use
    H3StreamingServer._free_streaming_stream() instead — this module-level
    variant exists only because __del__(deinit self) cannot call mut-self
    methods. ALWAYS call _streams.pop(sid) BEFORE calling this function."""
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# H3StreamingCtxPool — per-connection allocation pool
# ---------------------------------------------------------------------------
#
# Recycles H3StreamingCtx-sized heap blocks across requests on the same
# connection. Capacity 4 (smaller than sync's 16; streaming ctxs are larger
# and long-lived across many event-loop passes).


struct H3StreamingCtxPool(Movable):
    """Free-list of typed H3StreamingCtx-sized heap blocks. Caller
    owns initialisation/destruction of the pointee; the pool only
    manages the underlying memory."""

    var _free: List[UInt64]
    var _capacity: Int

    def __init__(out self, *, capacity: Int = 4):
        self._free = List[UInt64]()
        self._capacity = capacity

    def __init__(out self, *, deinit take: Self):
        self._free = take._free^
        self._capacity = take._capacity

    def __del__(deinit self):
        for i in range(len(self._free)):
            var p = UnsafePointer[H3StreamingCtx, MutAnyOrigin](
                unsafe_from_address=Int(self._free[i])
            )
            p.free()

    def acquire(mut self) raises -> UnsafePointer[H3StreamingCtx, MutAnyOrigin]:
        """Take a free slot if one is available, else allocate fresh."""
        if len(self._free) > 0:
            var addr = self._free.pop()
            return UnsafePointer[H3StreamingCtx, MutAnyOrigin](
                unsafe_from_address=Int(addr)
            )
        return _heap_alloc[H3StreamingCtx](1).as_any_origin()

    def release(
        mut self, ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin]
    ):
        """Return a slot whose pointee has already been destroyed.
        Beyond capacity → free; under capacity → keep for reuse."""
        if len(self._free) < self._capacity:
            self._free.append(UInt64(Int(ptr)))
        else:
            ptr.free()

    def idle_count(self) -> Int:
        return len(self._free)


# ---------------------------------------------------------------------------
# H3StreamingServer — server adapter using per-stream stackful coroutines
# ---------------------------------------------------------------------------


struct H3StreamingServer(Movable):
    """Drive per-stream stackful coroutines from an HTTP/3 H3Connection.
    Sans-IO: the caller feeds inbound QUIC datagrams via
    `feed_datagram_from_buffer()` and drains outbound datagrams via `drain()`.
    Each new request spawns a CoroHandle (via CoroutinePool) that suspends
    and resumes as body data and write-drains occur.

    Note: `_h3: H3Connection` already wraps and owns the `QuicConnection`
    internally (H3Connection._quic field). A separate top-level `_quic`
    field is intentionally absent to avoid double-ownership — mirrors
    H3CoroServer and H3HandlerServer patterns.

    The handler function must match CoroBody:
        fn (mut CoroYielder) raises -> None
    Access per-stream ctx inside the handler via:
        var ctx_ptr = yld.user_data().bitcast[H3StreamingCtx]().as_any_origin()
    """

    var _h3: H3Connection
    var _handler_fn: H3StreamingHandlerFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[List[UInt8]]
    var _streams: Dict[Int, _StreamingPtr]
    var _ctx_pool: H3StreamingCtxPool
    var _coro_pool: CoroutinePool

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        handler_fn: H3StreamingHandlerFn,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](unsafe_from_address=0),
    ) raises:
        """Create with a server-side QuicConnection."""
        _check_streaming_ctx_size()
        self._h3 = H3Connection.server(quic^)
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[List[UInt8]]()
        self._streams = Dict[Int, _StreamingPtr]()
        self._ctx_pool = H3StreamingCtxPool(capacity=4)
        self._coro_pool = CoroutinePool(capacity=4)

    def __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts and coroutines."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                # Set cancelled so any resumed coro exits cleanly
                ctx_ptr[].cancelled = True
                if ctx_ptr[].coro_addr != UInt64(0):
                    var coro_p = ctx_ptr[].coro_ptr()
                    if coro_p[].can_resume():
                        try:
                            coro_p[].resume()
                        except:
                            pass
                _free_streaming_stream(ctx_ptr)
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy).
        Dispatches H3 events, drains responses, accumulates outbound datagrams."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)
        self._flush_outbound(now)

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram. Dispatches H3 events and drains
        pending response data."""
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)
        self._flush_outbound(now)

    def drain(mut self) -> List[List[UInt8]]:
        """Drain queued outbound QUIC datagrams for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[List[UInt8]]()
        return out^

    def should_close(self) -> Bool:
        """True when the H3 connection has reached terminal state."""
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        return sid in self._streams

    def _free_streaming_stream(
        mut self, ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin]
    ):
        """Destroy the stream's CoroHandle + H3StreamingCtx and return the
        ctx slot to the per-connection pool. The pool's release() decides
        whether to keep the slot for reuse (under capacity) or free it
        (beyond capacity), so this restores the freelist that earlier
        revisions silently bypassed by calling ctx_ptr.free() directly.
        ALWAYS call _streams.pop(sid) BEFORE invoking this method."""
        if ctx_ptr[].coro_addr != UInt64(0):
            var coro_p = ctx_ptr[].coro_ptr()
            coro_p.destroy_pointee()
            coro_p.free()
        ctx_ptr.destroy_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self, now: UInt64) raises:
        """Move pending outbound QUIC datagrams from H3Connection into buffer."""
        var pending = self._h3.drain_datagrams(now)
        for i in range(len(pending)):
            self._outbuf.append(pending[i].copy())

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context and remove from dict."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _ = self._streams.pop(stream_id)
        self._free_streaming_stream(ctx_ptr)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(stream_id)
            self._free_streaming_stream(ctx_ptr)

    def _resume_stream(mut self, sid: Int) raises:
        """Resume the coroutine for stream sid. On error, set cancelled + free.

        When the coro finishes normally (DONE after finish() returns), the
        stream is NOT freed here. Instead, _drain_responses will drain the
        queued end BodyFrame, set response_ended=True, and _maybe_cleanup_stream
        will free the stream. This deferred cleanup ensures response data is
        actually sent before the H3StreamingCtx is freed."""
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].coro_addr == UInt64(0):
            return
        var coro_p = ctx_ptr[].coro_ptr()
        if not coro_p[].can_resume():
            # Coroutine already done — nothing to do here; drain will handle cleanup
            return
        try:
            coro_p[].resume()
        except e:
            # Handler raised an error — send RST, clean up
            try:
                self._h3.reset_stream(UInt64(sid), H3_REQUEST_CANCELLED)
            except:
                pass
            _ = self._streams.pop(sid)
            self._free_streaming_stream(ctx_ptr)
            return
        # Coro finished or suspended — if done, drain will clean up via
        # _maybe_cleanup_stream (called at end of _drain_responses).
        # No immediate pop/free here.

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        """Poll and dispatch all pending H3 events."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                if Int(ev.stream_id) not in self._streams:
                    self._on_request(ev)
                else:
                    self._on_trailers(ev)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)
            elif ev.kind == H3Event.GOAWAY_RECEIVED or ev.kind == H3Event.CONNECTION_CLOSED:
                self._on_goaway(ev)
            # H3Event.HANDSHAKE_COMPLETE and H3Event.SETTINGS_RECEIVED are
            # informational only — no per-stream action needed.

    def _on_request(mut self, ev: H3Event) raises:
        """First HEADERS_RECEIVED: parse pseudo-fields into Request, allocate
        H3StreamingCtx + CoroHandle (via CoroutinePool) on heap, register in
        streams dict, and do the first resume.
        If ev.fin==True (bodyless GET), set request_ended + recv_body._set_end()."""
        var method_str = String("GET")
        var path_str = String("/")
        var authority_str = String("")
        var user_headers = Headers()

        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            var value = ev.fields[i].value
            if name == ":method":
                method_str = value
            elif name == ":path":
                path_str = value
            elif name == ":authority":
                authority_str = value
            elif name == ":scheme":
                pass
            else:
                user_headers.add(name, value)

        var req_headers = Headers()
        if authority_str != "":
            req_headers.add("host", authority_str)
        for i in range(len(user_headers)):
            req_headers.add(user_headers.name_at(i), user_headers.value_at(i))

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var stream_id = Int(ev.stream_id)

        # Allocate ctx from pool
        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = H3StreamingCtx(
            request=req^,
            caps=Capabilities.for_h3(),
            stream_id=ev.stream_id,
            extra_data=self._extra_data,
        )

        # FIN on HEADERS = bodyless request (e.g. GET) — mark ended immediately
        if ev.fin:
            ctx.request_ended = True
            ctx.recv_body._set_end()

        ctx_ptr.init_pointee_move(ctx^)

        # Acquire CoroHandle from pool; user_data = ctx_ptr cast to NoneType ptr
        var user_data = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(ctx_ptr)
        )
        var coro_heap = self._coro_pool.acquire(self._handler_fn, user_data)
        ctx_ptr[].coro_addr = UInt64(Int(coro_heap))

        # Insert BEFORE first resume so _drain_responses can find the stream
        self._streams[stream_id] = _StreamingPtr(UInt64(Int(ctx_ptr)))

        # First resume: runs handler until first suspend or completion
        self._resume_stream(stream_id)

    def _on_trailers(mut self, ev: H3Event) raises:
        """Second HEADERS_RECEIVED on an open stream = trailers.
        Push as BodyFrame.trailers into body_frame_ring, resume coroutine."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var trailer_headers = Headers()
        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            if not name.startswith(":"):
                trailer_headers.add(name, ev.fields[i].value)
        ctx.body_frame_ring.append(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_stream(sid)

    def _on_data(mut self, ev: H3Event) raises:
        """DATA_RECEIVED: push data into body_frame_ring, resume coroutine.
        No flow-control ACK — QUIC handles FC internally."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.body_frame_ring.append(BodyFrame.data(data_copy^))
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_stream(sid)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark body ended, resume coroutine."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_stream(sid)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET / STOP_SENDING: set cancelled, resume once for unwind,
        then pop BEFORE free."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        ctx_ptr[].cancelled = True
        if ctx_ptr[].coro_addr != UInt64(0):
            var coro_p = ctx_ptr[].coro_ptr()
            if coro_p[].can_resume():
                try:
                    coro_p[].resume()
                except:
                    pass
        _ = self._streams.pop(sid)  # pop BEFORE free
        self._free_streaming_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: set cancelled for ALL streams,
        resume each once for unwind, pop BEFORE free for each."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            var sid = keys[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            ctx_ptr[].cancelled = True
            if ctx_ptr[].coro_addr != UInt64(0):
                var coro_p = ctx_ptr[].coro_ptr()
                if coro_p[].can_resume():
                    try:
                        coro_p[].resume()
                    except:
                        pass
            _ = self._streams.pop(sid)  # pop BEFORE free
            self._free_streaming_stream(ctx_ptr)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Drain pending response data from stream contexts into H3Connection.
        Uses take_pointee/init_pointee_move to safely interleave ctx access
        with self._h3 mutations.

        For streaming: the handler may have written multiple chunks via
        write_chunk (buffered into resp_writer) across several suspends.
        This drain sends them in order with fin=False; when response_ended
        is set (by finish()), the next drain sends the terminal FIN."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
                continue
            # Send response headers if not yet sent
            if not ctx.headers_sent and ctx.resp_writer._has_status():
                var status_opt = ctx.resp_writer._take_status()
                var headers_opt = ctx.resp_writer._take_headers()
                var status = status_opt.unsafe_take()
                var resp_headers: Headers
                if Bool(headers_opt):
                    resp_headers = headers_opt.unsafe_take()
                else:
                    resp_headers = Headers()
                var fields = List[QpackHeaderField]()
                fields.append(QpackHeaderField(":status", String(Int(status.code()))))
                for j in range(len(resp_headers)):
                    fields.append(QpackHeaderField(resp_headers.name_at(j), resp_headers.value_at(j)))
                try:
                    self._h3.send_headers(UInt64(sid), fields, False)
                except:
                    pass
                ctx.headers_sent = True
            # Drain body frames written by write_chunk / finish
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    var data_copy = f.data().copy()
                    try:
                        self._h3.send_data(UInt64(sid), data_copy^, False)
                    except:
                        pass
                elif f.is_end():
                    try:
                        self._h3.send_data(UInt64(sid), List[UInt8](), True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
                elif f.is_trailers():
                    var trailer_hdrs = f.trailers().copy()
                    var t_fields = List[QpackHeaderField]()
                    for j in range(len(trailer_hdrs)):
                        t_fields.append(QpackHeaderField(trailer_hdrs.name_at(j), trailer_hdrs.value_at(j)))
                    try:
                        self._h3.send_headers(UInt64(sid), t_fields, True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
            ctx_ptr.init_pointee_move(ctx^)
            self._maybe_cleanup_stream(sid)
