# src/h2/h2_streaming_server.mojo
#
# HTTP/2 server-side adapter for STREAMING handlers. Each stream gets a
# 64 KiB stackful coroutine (bouclette.coroutine) so the handler can suspend
# across upstream I/O boundaries (LLM token emission, SSE, gRPC server-
# streaming, reverse proxy, file upload). Companion to
# `src/h2/h2_sync_server.mojo` — that's the default tier; this is opt-in.
#
# R8' compile-time budget: size_of[H2StreamingCtx]() < 96 KiB.
# R1' grep gate: this file IS allowed to import bouclette.coroutine.
#
# Backpressure note: write_chunk calls H2Connection.send_data
# directly and returns. H2 flow control is handled by H2Connection internally —
# oversized writes are queued in _pending_data and drained on WINDOW_UPDATE.
# No WouldBlock handling is needed at this layer.
#
# API note: bouclette's coroutine handle is `Coroutine[State]`, parametric on a
# typed state value that both the caller and the body can reach. This adapter
# instantiates it with `State = Pointer[H2StreamingCtx, MutUntrackedOrigin]`,
# so a body declared as `CoroutineBody[H2StreamingState]`, i.e.
#   def (mut Yielder[H2StreamingState]) raises -> None
# recovers its per-stream ctx with a plain `yld.state()[]` — no untyped
# `user_data()` pointer and no `bitcast`, so a handler written against the
# wrong ctx type is a compile error rather than a type confusion at runtime.
#
# `Yielder.suspend()` is the suspension primitive. The helper functions
# next_chunk / write_chunk / finish wrap it, so handlers call them directly.
#
# `Coroutine` is a LINEAR type (`@explicit_destroy`, `Deinitable where False`):
# it has no destructor, and every path that drops one must call `close()` or
# the 64 KiB mmap'd stack leaks. `close()` further requires the coroutine to be
# in CREATED or DONE state, so every teardown path here calls `cancel()` first
# — that drains a SUSPENDED body to DONE, swallowing errors. See
# `_free_streaming_stream` (both the method and the module-level twin), which
# are the only two places that release a coroutine.
#
# HANDLER CONTRACT: a body must never suspend unconditionally. `cancel()`
# resumes the body in a loop until it returns, so a body that suspends
# without ever checking `yld.is_cancelled()` (or `ctx.cancelled`) makes
# connection teardown spin — bouclette's 1000-iteration debug_assert catches
# that in a checked build, but a release build would livelock. The
# next_chunk / write_chunk helpers below poll both flags, so handlers built
# from them are safe by construction; handlers that call `yld.suspend()`
# directly must poll one of the two themselves.

from std.collections import Dict, Optional
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _heap_alloc
from std.sys.info import size_of

from bouclette.coroutine import (
    Coroutine,
    CoroutineBody,
    StackPool,
    Yielder,
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
from navette.util.ctx_pool import CtxPool
from navette.util.ptrbox import PtrBox
from navette.util.null_ptr import null_ptr


# ---------------------------------------------------------------------------
# Coroutine type aliases — typed state channel
# ---------------------------------------------------------------------------
#
# The coroutine's typed state IS the per-stream ctx pointer. The ctx itself
# stays owned by the adapter (`_streams` + `H2StreamingCtxPool`) because
# non-coroutine code must reach it while the body is suspended AND after the
# body has returned — `_drain_responses` flushes the frames buffered by
# `finish()` on a later event-loop pass, which is strictly after the coroutine
# reaches DONE.
#
# Inside the body, access the per-stream ctx via:
#   var ctx_ptr = yld.state()[]
#
# The handler may call next_chunk(ctx_ptr, yld) / write_chunk(ctx_ptr, yld, bytes)
# / finish(ctx_ptr, yld) to suspend across event-loop passes.

comptime H2StreamingState = Pointer[H2StreamingCtx, MutUntrackedOrigin]
"""Typed coroutine state for H2 streaming: a pointer to the per-stream ctx."""

comptime H2StreamingCoro = Coroutine[H2StreamingState]
"""Caller-side coroutine handle for one H2 request stream (linear type)."""

comptime H2StreamingYielder = Yielder[H2StreamingState]
"""Coroutine-side handle handed to an H2 streaming handler body."""

comptime H2StreamingHandlerFn = CoroutineBody[H2StreamingState]
"""Handler signature: `def (mut Yielder[H2StreamingState]) raises -> None`."""


# ---------------------------------------------------------------------------
# H2StreamingCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct H2StreamingCtx(Movable):
    """Per-stream context for H2 streaming serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.

    Extends the sync-server CoroStreamCtx shape with:
      - body_frame_ring: incoming body frames drained by next_chunk()
      - cancelled:       set true by adapter on peer reset / GOAWAY
      - coro_addr:       address of the heap slot holding this stream's
                         H2StreamingCoro (null = none). The slot is owned by
                         the ctx; `_free_streaming_stream` is the only place
                         that cancel()s + close()s and frees it.

    No writer_pending_chunk field — Option A: write_chunk does not suspend
    on backpressure; H2Connection's send_data queues oversized writes and
    drains them on WINDOW_UPDATE transparently.
    """

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt32
    var extra_data: Pointer[NoneType, MutUntrackedOrigin]
    var request_ended: Bool
    var response_ended: Bool
    var headers_sent: Bool
    var body_frame_ring: List[BodyFrame]
    var cancelled: Bool
    var coro_addr: PtrBox[H2StreamingCoro]

    def __init__(
        out self,
        var request: Request,
        caps: Capabilities,
        stream_id: UInt32,
        extra_data: Pointer[NoneType, MutUntrackedOrigin],
    ):
        self.request = request^
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.caps = Capabilities(copy=caps)
        self.stream_id = stream_id
        self.extra_data = extra_data
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False
        self.body_frame_ring = List[BodyFrame]()
        self.cancelled = False
        self.coro_addr = PtrBox[H2StreamingCoro].null()

    def coro_ptr(self) -> Pointer[H2StreamingCoro, MutUntrackedOrigin]:
        """Typed pointer into the coro's heap slot (null if none)."""
        return self.coro_addr.ptr()


# ---------------------------------------------------------------------------
# Per-stream memory budget (R8' in the sprint roadmap)
# ---------------------------------------------------------------------------
#
# The 64 KiB stack (bouclette.coroutine default) is mmap'd by the StackPool and
# reached through coro_addr; it is not counted toward H2StreamingCtx's
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
    ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_],
    mut yld: H2StreamingYielder,
) raises -> Optional[BodyFrame]:
    """Yield the next body chunk. Suspends if none ready. Returns None on EOF.

    Polls cancellation between suspends, from BOTH sources: `ctx.cancelled`
    (set by the adapter on peer reset / GOAWAY) and `yld.is_cancelled()` (set
    by `Coroutine.cancel()`). Honouring the coroutine's own flag is what makes
    `cancel()` terminate — it resumes the body in a loop until DONE, so a body
    that only watched `ctx.cancelled` would spin forever if the adapter ever
    cancelled without setting it.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder for this stream.

    Returns:
        The next BodyFrame, or None once the request body has ended.

    Raises:
        `H2StreamCancelled` if the stream is cancelled while waiting.
    """
    while not ctx_ptr[].request_ended and len(ctx_ptr[].body_frame_ring) == 0:
        if ctx_ptr[].cancelled or yld.is_cancelled():
            raise Error("H2StreamCancelled")
        yld.suspend()
    if len(ctx_ptr[].body_frame_ring) > 0:
        # FIFO: pop(0) preserves arrival order. Default pop() is LIFO and
        # would deliver multi-chunk bodies to the handler in reverse order.
        var frame = ctx_ptr[].body_frame_ring.pop(0)
        return Optional[BodyFrame](frame^)
    return Optional[BodyFrame](None)


def write_chunk(
    ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_],
    mut yld: H2StreamingYielder,
    var bytes: List[Byte],
) raises:
    """Buffer a body chunk for the adapter to send. Does NOT suspend on
    backpressure — H2Connection.send_data queues oversized writes internally
    and drains them when WINDOW_UPDATE arrives.

    The actual H2Connection.send_data call happens in the streaming server's
    _drain_responses on the next event-loop pass — write_chunk just buffers
    the chunk into ctx.resp_writer for the drain to pick up.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder; consulted for cancellation only,
            since this helper never suspends.
        bytes: The chunk to buffer (ownership transferred in).

    Raises:
        `H2StreamCancelled` if the stream has been cancelled.
    """
    if ctx_ptr[].cancelled or yld.is_cancelled():
        raise Error("H2StreamCancelled")
    # Buffer the data into resp_writer via try_send_body.
    # The adapter's _drain_responses calls H2Connection.send_data with
    # this content + end_stream=False on each event-loop pass.
    var frame = BodyFrame.data(bytes^)
    _ = ctx_ptr[].resp_writer.try_send_body(frame^)


def finish(
    ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_],
    mut yld: H2StreamingYielder,
) raises:
    """Close the response body. The handler should return immediately after
    this call. Adapter's _drain_responses sends the final END_STREAM on the
    next event-loop pass.

    Design note: finish() is synchronous — it buffers the end BodyFrame into
    resp_writer but does NOT suspend. The handler returns and the coro reaches
    DONE state. On the next feed call, _drain_responses processes the buffered
    end frame and sets response_ended=True.

    Why no suspend here? If finish() suspended, the coro would be SUSPENDED
    when _maybe_cleanup_stream (called from _on_stream_ended) runs, and
    `Coroutine.close()` debug_asserts on a non-CREATED/DONE phase. Keeping
    finish() synchronous avoids that invariant violation and is simpler: the
    handler just returns and the coro is DONE.

    Args:
        ctx_ptr: Pointer to this stream's context.
        yld: The coroutine-side yielder, accepted for API symmetry with
            next_chunk / write_chunk; unused because finish never suspends.
    """
    ctx_ptr[].resp_writer.end()


def cancelled(ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_]) -> Bool:
    """Report whether the adapter has cancelled this stream.

    Args:
        ctx_ptr: Pointer to this stream's context.

    Returns:
        True once the adapter has flagged the stream cancelled.
    """
    return ctx_ptr[].cancelled


# ---------------------------------------------------------------------------
# _free_streaming_stream — DESTRUCTOR-PATH-ONLY cleanup for H2StreamingCtx
# ---------------------------------------------------------------------------


def _release_coro(ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_]):
    """Cancel, close and free this stream's coroutine, if it still has one.

    `Coroutine` is linear: it has no destructor, so dropping the heap slot
    without `close()` leaks a 64 KiB mmap'd stack — one per request, which on
    a server is an unbounded DoS vector. `close()` in turn debug_asserts
    unless the coroutine is CREATED or DONE, so a still-SUSPENDED body must
    first be drained by `cancel()`, which resumes it until it returns and
    swallows any error it raises on the way out. `cancel()` is a no-op on an
    already-DONE coroutine, so this is safe to call on every path.

    `ctx.cancelled` is set first so handlers that poll the ctx flag (rather
    than `yld.is_cancelled()`) also unwind on the very first resume.

    Idempotent: clears `coro_addr` so a double call cannot double-free.

    Args:
        ctx_ptr: Pointer to the stream context owning the coroutine slot.
    """
    if not ctx_ptr[].coro_addr.is_some():
        return
    var coro_p = ctx_ptr[].coro_ptr()
    ctx_ptr[].coro_addr = PtrBox[H2StreamingCoro].null()
    ctx_ptr[].cancelled = True
    coro_p[].cancel()
    var coro = coro_p.unsafe_take_pointee()
    coro^.close()
    coro_p.unsafe_free()


def _free_streaming_stream(ctx_ptr: Pointer[mut=True, T=H2StreamingCtx, origin=_]):
    """DESTRUCTOR PATH ONLY. Bypasses the ctx pool. Runtime sites must use
    H2StreamingServer._free_streaming_stream() instead — this module-level
    variant exists only because __deinit__(deinit self) cannot call mut-self
    methods. ALWAYS call _streams.pop(sid) BEFORE calling this function.

    Args:
        ctx_ptr: Pointer to the stream context to tear down and free.
    """
    _release_coro(ctx_ptr)
    ctx_ptr.unsafe_deinit_pointee()
    ctx_ptr.unsafe_free()


# ---------------------------------------------------------------------------
# H2StreamingCtxPool — per-connection allocation pool
# ---------------------------------------------------------------------------
#
# Recycles H2StreamingCtx-sized heap blocks across requests on the same
# connection. Capacity 4 (smaller than sync's 16; streaming ctxs are larger
# and long-lived across many event-loop passes).


# ---------------------------------------------------------------------------
# H2StreamingServer — server adapter using per-stream stackful coroutines
# ---------------------------------------------------------------------------


struct H2StreamingServer(Movable):
    """Drive per-stream stackful coroutines from an HTTP/2 H2Connection.
    Sans-IO: the caller feeds inbound TCP bytes via `feed()` and drains
    outbound bytes via `drain()`. Each new request spawns an H2StreamingCoro
    on a stack borrowed from a per-connection `StackPool`, which suspends
    and resumes as body data and
    write-drains occur.

    The handler function must match H2StreamingHandlerFn:
        def (mut Yielder[H2StreamingState]) raises -> None
    Access per-stream ctx inside the handler via:
        var ctx_ptr = yld.state()[]
    """

    var _conn: H2Connection
    var _handler_fn: H2StreamingHandlerFn
    var _extra_data: Pointer[NoneType, MutUntrackedOrigin]
    var _outbuf: List[Byte]
    var _streams: Dict[Int, PtrBox[H2StreamingCtx]]
    var _ctx_pool: CtxPool[H2StreamingCtx]
    var _coro_pool: StackPool

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        handler_fn: H2StreamingHandlerFn,
        extra_data: Pointer[NoneType, MutUntrackedOrigin] = null_ptr[
            NoneType, MutUntrackedOrigin
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
        self._outbuf = List[Byte]()
        self._streams = Dict[Int, PtrBox[H2StreamingCtx]]()
        self._ctx_pool = CtxPool[H2StreamingCtx](capacity=4)
        self._coro_pool = StackPool(capacity=4)
        self._flush_outbound()

    def __init__(
        out self,
        *,
        handler_fn: H2StreamingHandlerFn,
        config: H2Config,
        extra_data: Pointer[NoneType, MutUntrackedOrigin] = null_ptr[
            NoneType, MutUntrackedOrigin
        ](),
    ) raises:
        """Create with a custom H2Config (server-side)."""
        _check_streaming_ctx_size()
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[Byte]()
        self._streams = Dict[Int, PtrBox[H2StreamingCtx]]()
        self._ctx_pool = CtxPool[H2StreamingCtx](capacity=4)
        self._coro_pool = StackPool(capacity=4)
        self._flush_outbound()

    def __deinit__(deinit self):
        """Close every live coroutine and free all heap-allocated contexts.

        Uses the module-level `_free_streaming_stream`, which drains each
        coroutine to DONE via `cancel()` before `close()`. Without that, a
        connection torn down mid-request would drop SUSPENDED coroutines and
        leak their stacks.
        """
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref key in keys:
            try:
                _free_streaming_stream(self._streams[key].ptr())
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[Byte, _]) raises:
        """Feed inbound TCP bytes. Dispatches H2 events, drains responses."""
        var data_list = List[Byte]()
        for ref byte in data:
            data_list.append(byte)
        var events = self._conn.receive_data(data_list)
        self._dispatch_events(events)
        self._drain_responses()
        self._flush_outbound()

    def drain(mut self) -> List[Byte]:
        """Drain queued outbound TCP bytes for the transport to write. Delegates to drain_into."""
        var out = List[Byte]()
        self.drain_into(out)
        return out^

    def drain_into(mut self, mut sink: List[Byte]):
        """Append queued outbound bytes into sink and clear the buffer in place,
        preserving its backing allocation across drains."""
        sink.extend(Span(self._outbuf))
        self._outbuf.clear()

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
        mut self, ctx_ptr: Pointer[H2StreamingCtx, MutUntrackedOrigin]
    ):
        """Cancel + close the stream's coroutine, destroy the H2StreamingCtx,
        and return the
        ctx slot to the per-connection pool. The pool's release() decides
        whether to keep the slot for reuse (under capacity) or free it
        (beyond capacity), so this restores the freelist that earlier
        revisions silently bypassed by freeing ctx_ptr directly.
        ALWAYS call _streams.pop(sid) BEFORE invoking this method.

        Args:
            ctx_ptr: Pointer to the stream context to tear down.
        """
        _release_coro(ctx_ptr)
        ctx_ptr.unsafe_deinit_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self):
        """Move pending outbound bytes from H2Connection into our buffer."""
        self._conn.data_to_send_into(self._outbuf)

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
        if not ctx_ptr[].coro_addr.is_some():
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
        for ref evt_ref in events:
            var evt = H2Event(copy=evt_ref)
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
        an H2StreamingCtx plus its H2StreamingCoro (on a stack borrowed from
        the per-connection StackPool), register in
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

        ctx_ptr.unsafe_write(ctx^)

        # Spawn the coroutine on a pooled stack. Its typed state IS ctx_ptr,
        # so the body reaches the context with yld.state()[] — no untyped
        # user_data pointer and no bitcast.
        #
        # The coroutine is a linear type and cannot live in a Dict, so it is
        # boxed in its own heap slot that the ctx owns. If either the slot
        # allocation or the coroutine construction fails, the already-written
        # ctx would otherwise be orphaned (it is not yet in self._streams and
        # nothing else holds its pointer), so unwind it here before re-raising.
        var coro_heap = _heap_alloc[H2StreamingCoro](1)
        try:
            coro_heap.unsafe_write(
                H2StreamingCoro(self._handler_fn, ctx_ptr, self._coro_pool)
            )
        except e:
            coro_heap.unsafe_free()
            ctx_ptr.unsafe_deinit_pointee()
            self._ctx_pool.release(ctx_ptr)
            raise e^
        ctx_ptr[].coro_addr = PtrBox[H2StreamingCoro](coro_heap)

        # Insert BEFORE first resume so _drain_responses can find the stream
        self._streams[stream_id] = PtrBox[H2StreamingCtx](ctx_ptr)

        # First resume: runs handler until first suspend or completion
        self._resume_stream(stream_id)

    def _on_trailers(mut self, evt: H2Event) raises:
        """TRAILERS_RECEIVED: push as BodyFrame.trailers into body_frame_ring,
        resume coroutine."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        var trailer_headers = headers_from_h2(evt.headers)
        ctx.body_frame_ring.append(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.unsafe_write(ctx^)
        self._resume_stream(sid)

    def _on_data(mut self, evt: H2Event) raises:
        """DATA_RECEIVED: push data into body_frame_ring, resume coroutine.
        Also acknowledge received bytes for H2 flow control."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.unsafe_take_pointee()
        if len(evt.data) > 0:
            var data_copy = List[Byte](copy=evt.data)
            ctx.body_frame_ring.append(BodyFrame.data(data_copy^))
        ctx_ptr.unsafe_write(ctx^)
        # Acknowledge flow control bytes
        try:
            self._conn.acknowledge_received_data(evt.flow_controlled_length, evt.stream_id)
        except:
            pass
        if evt.stream_ended:
            var ctx2 = ctx_ptr.unsafe_take_pointee()
            if not ctx2.request_ended:
                ctx2.request_ended = True
                ctx2.recv_body._set_end()
            ctx_ptr.unsafe_write(ctx2^)
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
        var ctx = ctx_ptr.unsafe_take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.unsafe_write(ctx^)
        self._resume_stream(sid)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """STREAM_RESET: pop the stream, then tear it down.

        `_free_streaming_stream` sets ctx.cancelled and drains the coroutine
        to DONE with `cancel()` before closing it, so a handler suspended
        mid-body unwinds instead of leaving a SUSPENDED coroutine that
        `close()` would refuse.

        Args:
            evt: The STREAM_RESET event naming the stream to abort.
        """
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        _ = self._streams.pop(sid)  # pop BEFORE free
        self._free_streaming_stream(ctx_ptr)

    def _on_goaway(mut self, evt: H2Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_TERMINATED: tear down ALL streams.

        Each stream is popped before being freed; `_free_streaming_stream`
        cancels and drains its coroutine to DONE before closing it.

        Args:
            evt: The GOAWAY / CONNECTION_TERMINATED event (unused; the whole
                connection is going away).
        """
        var keys = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            keys.append(key)
        for ref key in keys:
            var sid = key
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
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
        var stream_ids = List[Int](capacity=len(self._streams))
        for key in self._streams.keys():
            stream_ids.append(key)
        for ref sid_ref in stream_ids:
            var sid = sid_ref
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.unsafe_take_pointee()
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.unsafe_write(ctx^)
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
            var pending_data = List[List[Byte]]()
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
                                UInt32(sid), List[Byte](), end_stream=True
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
                        pending_data = List[List[Byte]]()
                    ctx.response_ended = True
                    made_progress = True
                    break
                elif f.is_trailers():
                    for ref pd in pending_data:
                        try:
                            self._conn.send_data(
                                UInt32(sid), pd.copy(), end_stream=False
                            )
                        except:
                            pass
                    pending_data = List[List[Byte]]()
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
            for ref pd in pending_data:
                try:
                    self._conn.send_data(
                        UInt32(sid), pd.copy(), end_stream=False
                    )
                except:
                    pass
            ctx_ptr.unsafe_write(ctx^)
            if made_progress:
                self._maybe_cleanup_stream(sid)
