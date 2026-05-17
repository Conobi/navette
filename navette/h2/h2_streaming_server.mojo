# src/h2/h2_streaming_server.mojo
#
# HTTP/2 server-side adapter for STREAMING handlers. Each stream gets a
# 64 KiB stackful coroutine (boucle.stackful) so the handler can suspend
# across upstream I/O boundaries (LLM token emission, SSE, gRPC server-
# streaming, reverse proxy, file upload). Companion to
# `src/h2/h2_sync_server.mojo` — that's the default tier; this is opt-in.
#
# R8' compile-time budget: size_of[H2StreamingCtx]() < 96 KiB.
# R1' grep gate: this file IS allowed to import boucle.stackful.
#
# Backpressure note (Sprint 2 design): write_chunk calls H2Connection.send_data
# directly and returns. H2 flow control is handled by H2Connection internally —
# oversized writes are queued in _pending_data and drained on WINDOW_UPDATE.
# No WouldBlock handling is needed at this layer.
#
# API note: boucle.stackful's CoroBody type is:
#   fn (mut CoroYielder) raises -> None
# The handler receives its per-stream ctx via yld.user_data() cast to
# UnsafePointer[H2StreamingCtx, MutAnyOrigin]. This matches the CoroBody
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

from navette.h2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_REQUEST_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_TRAILERS_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_GOAWAY_RECEIVED,
    H2_EVT_CONNECTION_TERMINATED,
    H2_CANCEL,
)
from navette.h2.config import h2_production_config
from navette.h2.pseudo_headers import (
    request_from_h2_headers,
    response_to_h2_headers,
    headers_from_h2,
    headers_to_h2,
)
from navette.h2.header import Header
from navette.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from navette.http.body import BodyFrame
from navette.http.headers import Headers
from navette.http.request import Request
from navette.http.status import StatusCode
from navette.http.version import Version


# ---------------------------------------------------------------------------
# H2StreamingHandlerFn — handler type alias
# ---------------------------------------------------------------------------
#
# Must match boucle.stackful.CoroBody exactly:
#   fn (mut CoroYielder) raises -> None
#
# Inside the body, access the per-stream ctx via:
#   var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
#
# The handler may call next_chunk(ctx_ptr, yld) / write_chunk(ctx_ptr, yld, bytes)
# / finish(ctx_ptr, yld) to suspend across event-loop passes.

comptime H2StreamingHandlerFn = CoroBody


# ---------------------------------------------------------------------------
# H2StreamingCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct H2StreamingCtx(Movable):
    """Per-stream context for H2 streaming serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.

    Extends the sync-server CoroStreamCtx shape with:
      - body_frame_ring: incoming body frames drained by next_chunk()
      - cancelled:       set true by adapter on peer reset / GOAWAY
      - coro_addr:       address of heap-allocated CoroHandle (0 = none)

    No writer_pending_chunk field — Option A: write_chunk does not suspend
    on backpressure; H2Connection's send_data queues oversized writes and
    drains them on WINDOW_UPDATE transparently.
    """

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt32
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
        stream_id: UInt32,
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
# CoroHandle (pointed to by coro_addr); not counted toward H2StreamingCtx's
# direct size. The struct itself holds: Request + RecvBody + ResponseWriter +
# Capabilities + stream_id + extra_data + coro_addr + 3 bools + body_frame_ring +
# cancelled bool. Should land around the same size as the sync ctx (~600 B)
# plus the body_frame_ring overhead (List[BodyFrame] = pointer + len + cap = ~24 B
# header + variable content). Streaming ctx total: well under 96 KiB.


def _check_streaming_ctx_size():
    comptime assert size_of[H2StreamingCtx]() < 96 * 1024, (
        "H2StreamingCtx exceeded R8' budget (96 KiB) — investigate"
        " before raising the cap"
    )


# ---------------------------------------------------------------------------
# Streaming-handler API helpers (Option A — direct call, no WouldBlock)
# ---------------------------------------------------------------------------


def next_chunk(
    ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises -> Optional[BodyFrame]:
    """Yield the next body chunk. Suspends if none ready. Returns None on EOF.
    Polls cancellation between suspends."""
    while not ctx_ptr[].request_ended and len(ctx_ptr[].body_frame_ring) == 0:
        if ctx_ptr[].cancelled:
            raise Error("H2StreamCancelled")
        yld.yield_to_caller()
    if len(ctx_ptr[].body_frame_ring) > 0:
        # FIFO: pop(0) preserves arrival order. Default pop() is LIFO and
        # would deliver multi-chunk bodies to the handler in reverse order.
        var frame = ctx_ptr[].body_frame_ring.pop(0)
        return Optional[BodyFrame](frame^)
    return Optional[BodyFrame](None)


def write_chunk(
    ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
    var bytes: List[UInt8],
) raises:
    """Send a body chunk via H2Connection.send_data. Does NOT suspend on
    backpressure — H2Connection.send_data queues oversized writes internally
    and drains them when WINDOW_UPDATE arrives. The yld parameter is
    accepted for API symmetry (and future-proofing) but unused in this
    implementation.

    The actual H2Connection.send_data call happens in the streaming server's
    _drain_responses on the next event-loop pass — write_chunk just buffers
    the chunk into ctx.resp_writer for the drain to pick up."""
    if ctx_ptr[].cancelled:
        raise Error("H2StreamCancelled")
    # Buffer the data into resp_writer via try_send_body.
    # The adapter's _drain_responses calls H2Connection.send_data with
    # this content + end_stream=False on each event-loop pass.
    var frame = BodyFrame.data(bytes^)
    _ = ctx_ptr[].resp_writer.try_send_body(frame^)


def finish(
    ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    """Close the response body. The handler should return immediately after
    this call. Adapter's _drain_responses sends the final END_STREAM on the
    next event-loop pass.

    Design note: finish() is synchronous — it buffers the end BodyFrame into
    resp_writer but does NOT call yield_to_caller(). The handler returns and
    the coro reaches DONE state. On the next feed call, _drain_responses
    processes the buffered end frame and sets response_ended=True.

    Why no yield_to_caller here? If finish() suspended, the coro would be in
    SUSPENDED state when _maybe_cleanup_stream (called from _on_stream_ended)
    runs — which triggers a boucle debug_assert when destroying the still-
    suspended CoroHandle. Keeping finish() synchronous avoids that invariant
    violation and is simpler: the handler just returns and the coro is DONE."""
    ctx_ptr[].resp_writer.end()
    # yld is accepted for API symmetry; not used because finish is synchronous.


def cancelled(
    ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin]
) -> Bool:
    return ctx_ptr[].cancelled


# ---------------------------------------------------------------------------
# _StreamingPtr — thin wrapper so Dict[Int, _StreamingPtr] satisfies
# CollectionElement (Copyable + Movable).
# ---------------------------------------------------------------------------


struct _StreamingPtr(Copyable, Movable):
    """Holds the address of a heap-allocated H2StreamingCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[H2StreamingCtx, MutAnyOrigin]:
        return UnsafePointer[H2StreamingCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# _free_streaming_stream — DESTRUCTOR-PATH-ONLY cleanup for H2StreamingCtx
# ---------------------------------------------------------------------------


def _free_streaming_stream(ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin]):
    """DESTRUCTOR PATH ONLY. Bypasses the ctx pool. Runtime sites must use
    H2StreamingServer._free_streaming_stream() instead — this module-level
    variant exists only because __del__(deinit self) cannot call mut-self
    methods. ALWAYS call _streams.pop(sid) BEFORE calling this function."""
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# H2StreamingCtxPool — per-connection allocation pool
# ---------------------------------------------------------------------------
#
# Recycles H2StreamingCtx-sized heap blocks across requests on the same
# connection. Capacity 4 (smaller than sync's 16; streaming ctxs are larger
# and long-lived across many event-loop passes).


struct H2StreamingCtxPool(Movable):
    """Free-list of typed H2StreamingCtx-sized heap blocks. Caller
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
            var p = UnsafePointer[H2StreamingCtx, MutAnyOrigin](
                unsafe_from_address=Int(self._free[i])
            )
            p.free()

    def acquire(mut self) raises -> UnsafePointer[H2StreamingCtx, MutAnyOrigin]:
        """Take a free slot if one is available, else allocate fresh."""
        if len(self._free) > 0:
            var addr = self._free.pop()
            return UnsafePointer[H2StreamingCtx, MutAnyOrigin](
                unsafe_from_address=Int(addr)
            )
        return _heap_alloc[H2StreamingCtx](1).as_any_origin()

    def release(
        mut self, ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin]
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
# H2StreamingServer — server adapter using per-stream stackful coroutines
# ---------------------------------------------------------------------------


struct H2StreamingServer(Movable):
    """Drive per-stream stackful coroutines from an HTTP/2 H2Connection.
    Sans-IO: the caller feeds inbound TCP bytes via `feed()` and drains
    outbound bytes via `drain()`. Each new request spawns a CoroHandle
    (via CoroutinePool) that suspends and resumes as body data and
    write-drains occur.

    The handler function must match CoroBody:
        fn (mut CoroYielder) raises -> None
    Access per-stream ctx inside the handler via:
        var ctx_ptr = yld.user_data().bitcast[H2StreamingCtx]().as_any_origin()
    """

    var _conn: H2Connection
    var _handler_fn: H2StreamingHandlerFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _StreamingPtr]
    var _ctx_pool: H2StreamingCtxPool
    var _coro_pool: CoroutinePool

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        handler_fn: H2StreamingHandlerFn,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with default production config (server-side)."""
        _check_streaming_ctx_size()
        self._conn = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
        )
        self._conn.initiate_connection()
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamingPtr]()
        self._ctx_pool = H2StreamingCtxPool(capacity=4)
        self._coro_pool = CoroutinePool(capacity=4)
        self._flush_outbound()

    def __init__(
        out self,
        *,
        handler_fn: H2StreamingHandlerFn,
        config: H2Config,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with a custom H2Config (server-side)."""
        _check_streaming_ctx_size()
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamingPtr]()
        self._ctx_pool = H2StreamingCtxPool(capacity=4)
        self._coro_pool = CoroutinePool(capacity=4)
        self._flush_outbound()

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

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound TCP bytes. Dispatches H2 events, drains responses."""
        var data_list = List[UInt8]()
        for i in range(len(data)):
            data_list.append(data[i])
        var events = self._conn.receive_data(data_list)
        self._dispatch_events(events)
        self._drain_responses()
        self._flush_outbound()

    def drain(mut self) -> List[UInt8]:
        """Drain queued outbound TCP bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()

    def resume_stream(mut self, sid: Int) raises:
        """Externally resume a suspended per-stream coroutine.

        Designed for proxy / pipelined-backend use cases where the streaming
        handler suspends waiting on an out-of-band signal (e.g. a backend
        response arriving on a different transport). The caller plants
        whatever state the handler was waiting on (typically into a shared
        struct it found via `extra_data`) and then calls this to wake the
        coro. The streaming server then drains any response frames the coro
        emitted and pushes them into the outbound buffer for the next
        `drain()` call.

        Safe to call when the stream does not exist or its coro is already
        DONE — both are no-ops. Errors raised by the coro are converted to
        RST_STREAM in `_resume_stream`, so this method only propagates
        accounting errors from `_drain_responses` / `_flush_outbound`.
        """
        if not self._has_stream(sid):
            return
        self._resume_stream(sid)
        self._drain_responses()
        self._flush_outbound()

    def has_stream(self, sid: Int) -> Bool:
        """Public wrapper around `_has_stream` for external coordination
        (e.g. a proxy keying its handle→stream map needs to check whether
        the stream still exists before resuming)."""
        return self._has_stream(sid)

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        return sid in self._streams

    def _free_streaming_stream(
        mut self, ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin]
    ):
        """Destroy the stream's CoroHandle + H2StreamingCtx and return the
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

    def _flush_outbound(mut self):
        """Move pending outbound bytes from H2Connection into our buffer."""
        var pending = self._conn.data_to_send()
        if len(pending) > 0:
            self._outbuf.extend(pending^)

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
        actually sent before the H2StreamingCtx is freed."""
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
            # Handler raised an error — send RST_STREAM, clean up
            try:
                self._conn.send_rst_stream(
                    UInt32(sid), UInt32(H2_CANCEL)
                )
            except:
                pass
            _ = self._streams.pop(sid)
            self._free_streaming_stream(ctx_ptr)
            return
        # Coro finished or suspended — if done, drain will clean up via
        # _maybe_cleanup_stream (called at end of _drain_responses).
        # No immediate pop/free here.

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch all H2 events."""
        for i in range(len(events)):
            var evt = H2Event(other=events[i])
            if evt.kind == H2_EVT_REQUEST_RECEIVED:
                if Int(evt.stream_id) not in self._streams:
                    self._on_request(evt)
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                self._on_data(evt)
            elif evt.kind == H2_EVT_TRAILERS_RECEIVED:
                self._on_trailers(evt)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self._on_stream_ended(evt)
            elif evt.kind == H2_EVT_STREAM_RESET:
                self._on_stream_reset(evt)
            elif evt.kind == H2_EVT_GOAWAY_RECEIVED or evt.kind == H2_EVT_CONNECTION_TERMINATED:
                self._on_goaway(evt)
            # H2_EVT_SETTINGS_ACKNOWLEDGED, H2_EVT_SETTINGS_CHANGED,
            # H2_EVT_WINDOW_UPDATED, H2_EVT_PING_* are informational — no
            # per-stream action needed.

    def _on_request(mut self, evt: H2Event) raises:
        """REQUEST_RECEIVED: parse headers into Request, allocate
        H2StreamingCtx + CoroHandle (via CoroutinePool) on heap, register in
        streams dict, and do the first resume.
        If evt.stream_ended==True (bodyless GET), set request_ended + recv_body._set_end()."""
        var req = request_from_h2_headers(evt.stream_id, evt.headers)
        var stream_id = Int(evt.stream_id)

        # Allocate ctx from pool
        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = H2StreamingCtx(
            request=req^,
            caps=Capabilities.for_h2(),
            stream_id=evt.stream_id,
            extra_data=self._extra_data,
        )

        # stream_ended on REQUEST_RECEIVED = bodyless request (e.g. GET)
        if evt.stream_ended:
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

    def _on_trailers(mut self, evt: H2Event) raises:
        """TRAILERS_RECEIVED: push as BodyFrame.trailers into body_frame_ring,
        resume coroutine."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var trailer_headers = headers_from_h2(evt.headers)
        ctx.body_frame_ring.append(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_stream(sid)

    def _on_data(mut self, evt: H2Event) raises:
        """DATA_RECEIVED: push data into body_frame_ring, resume coroutine.
        Also acknowledge received bytes for H2 flow control."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        if len(evt.data) > 0:
            var data_copy = List[UInt8](copy=evt.data)
            ctx.body_frame_ring.append(BodyFrame.data(data_copy^))
        ctx_ptr.init_pointee_move(ctx^)
        # Acknowledge flow control bytes
        try:
            self._conn.acknowledge_received_data(evt.flow_controlled_length, evt.stream_id)
        except:
            pass
        if evt.stream_ended:
            var ctx2 = ctx_ptr.take_pointee()
            if not ctx2.request_ended:
                ctx2.request_ended = True
                ctx2.recv_body._set_end()
            ctx_ptr.init_pointee_move(ctx2^)
        self._resume_stream(sid)
        if evt.stream_ended:
            self._maybe_cleanup_stream(sid)

    def _on_stream_ended(mut self, evt: H2Event) raises:
        """STREAM_ENDED: mark body ended, resume coroutine."""
        var sid = Int(evt.stream_id)
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

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """STREAM_RESET: set cancelled, resume once for unwind,
        then pop BEFORE free."""
        var sid = Int(evt.stream_id)
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

    def _on_goaway(mut self, evt: H2Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_TERMINATED: set cancelled for ALL streams,
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

    def _drain_responses(mut self) raises:
        """Drain pending response data from stream contexts into H2Connection.
        Uses take_pointee/init_pointee_move to safely interleave ctx access
        with self._conn mutations.

        For streaming: the handler may have written multiple chunks via
        write_chunk (buffered into resp_writer) across several suspends.
        This drain sends them in order with end_stream=False; when
        response_ended is set (by finish()), the drain sends the terminal
        END_STREAM.

        The DATA frame folding from h2_sync_server._drain_responses is
        reproduced here: we buffer data frames and fold END_STREAM onto the
        last DATA payload to avoid sending a separate 0-byte DATA(END_STREAM)
        frame (some H2 clients misbehave on that)."""
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
            var made_progress = False
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
                var h2_hdrs = response_to_h2_headers(status^, resp_headers^)
                try:
                    self._conn.send_headers(
                        UInt32(sid), h2_hdrs^, end_stream=False
                    )
                except:
                    pass
                ctx.headers_sent = True
                made_progress = True
            # Drain body frames written by write_chunk / finish.
            # Buffer data frames so we can fold END_STREAM onto the last
            # DATA payload instead of emitting a 0-byte trailer frame.
            var pending_data = List[List[UInt8]]()
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    pending_data.append(f.data().copy())
                    made_progress = True
                elif f.is_end():
                    if len(pending_data) == 0:
                        try:
                            self._conn.send_data(
                                UInt32(sid), List[UInt8](), end_stream=True
                            )
                        except:
                            pass
                    else:
                        var n = len(pending_data)
                        for k in range(n - 1):
                            try:
                                self._conn.send_data(
                                    UInt32(sid), pending_data[k].copy(), end_stream=False
                                )
                            except:
                                pass
                        try:
                            self._conn.send_data(
                                UInt32(sid), pending_data[n - 1].copy(), end_stream=True
                            )
                        except:
                            pass
                        pending_data = List[List[UInt8]]()
                    ctx.response_ended = True
                    made_progress = True
                    break
                elif f.is_trailers():
                    for k in range(len(pending_data)):
                        try:
                            self._conn.send_data(
                                UInt32(sid), pending_data[k].copy(), end_stream=False
                            )
                        except:
                            pass
                    pending_data = List[List[UInt8]]()
                    var trailer_h2 = headers_to_h2(f.trailers())
                    try:
                        self._conn.send_headers(
                            UInt32(sid), trailer_h2^, end_stream=True
                        )
                    except:
                        pass
                    ctx.response_ended = True
                    made_progress = True
                    break
            # Flush any leftover pending data (no END_STREAM yet)
            for k in range(len(pending_data)):
                try:
                    self._conn.send_data(
                        UInt32(sid), pending_data[k].copy(), end_stream=False
                    )
                except:
                    pass
            ctx_ptr.init_pointee_move(ctx^)
            if made_progress:
                self._maybe_cleanup_stream(sid)
