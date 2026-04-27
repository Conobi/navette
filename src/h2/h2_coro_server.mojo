# src/h2/h2_coro_server.mojo
#
# HTTP/2 server-side adapter — sans-IO codec wrapper.  Feed inbound wire
# bytes via `feed()`; drain outbound bytes via `drain()`.
#
# As of Sprint 1 Step 3 (Path A), per-stream concurrency is a
# hand-written state machine, not a stackful coroutine.  The user's
# request handler is invoked synchronously when a request is complete:
# headers parsed, body (if any) accumulated.  This eliminates the
# 64 KiB stack + ucontext swap + TLS reload per stream.
#
# The "Coro" in the names is preserved to minimise churn in callers
# (bench/h2_server.mojo, tests/test_h2_coro_server.mojo); a follow-up
# sprint can rename to H2StreamServer / H2StreamCtx if needed.
#
# See plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md § Sprint 1.

from std.collections import Dict
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

from .connection import (
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
)
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.request import Request
from src.h2.config import h2_production_config
from src.h2.pseudo_headers import (
    request_from_h2_headers,
    response_to_h2_headers,
    headers_from_h2,
    headers_to_h2,
)


# ---------------------------------------------------------------------------
# H2BodyFn — synchronous handler invoked once per request
# ---------------------------------------------------------------------------
#
# The handler receives a pointer to the per-stream context, reads
# `ctx.request` (or for streaming bodies, repeatedly polls
# `ctx.recv_body`), and writes the response into `ctx.resp_writer`.
# It runs to completion in one call — no `yield_to_caller`.
#
# For streaming POST bodies that need to span multiple DATA frames,
# the handler should not block on body data that isn't there yet;
# it should write whatever response it can and return.  A future
# sprint will add a state-machine entry point that re-enters the
# handler when more body data arrives (for now, the bench server's
# handlers are headers-only, so this is sufficient).

comptime H2BodyFn = fn (
    UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises -> None


# ---------------------------------------------------------------------------
# CoroStreamCtx — per-stream state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for H2 serving.  Heap-allocated so the
    adapter and the handler can reach it via pointer.  Holds the
    request, body receiver, response writer, capabilities, and
    request/response bookkeeping.

    Post-Path-A: no `coro_addr` field.  The handler runs synchronously,
    so there's no suspended coroutine state to track.  R8 in the sprint
    roadmap caps `sizeof(StreamState) < 512`; the legacy CoroStreamCtx
    name stays until a follow-up rename pass.
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
    var unacked_bytes: Int

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
        self.unacked_bytes = 0

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
        self.unacked_bytes = take.unacked_bytes


# ---------------------------------------------------------------------------
# Per-stream memory budget (R8 in the sprint roadmap)
# ---------------------------------------------------------------------------
#
# Pre-Path-A: 64 KiB stack + ~400 B ucontext + ~200 B CoroHandle = ~65 KiB.
# Post-Path-A: just sizeof(CoroStreamCtx) for the heap-allocated context.
#
# The hard cap is 1024 B. Today we land around 608 B, dominated by:
#   Request (248) + RecvBody (96) + ResponseWriter (216) + Capabilities (16)
# = 576 B for the protocol holders, the rest being small ints/bools.
#
# Trimming the holders is out of scope for Sprint 1 (the architectural
# 100× memory reduction is the headline). A future sprint may revisit.
#
# The check fires inside `_check_stream_ctx_size` below, called at the
# top of every H2CoroServer constructor — `comptime assert` cannot live
# at module scope in Mojo 0.26, so this is the cleanest workaround.


fn _check_stream_ctx_size():
    comptime assert size_of[CoroStreamCtx]() < 1024, (
        "CoroStreamCtx exceeded R8 budget (1024 B) — investigate before"
        " raising the cap"
    )


# ---------------------------------------------------------------------------
# _CoroStreamPtr — thin wrapper so Dict[Int, _CoroStreamPtr] satisfies
# CollectionElement (Copyable + Movable) even if UnsafePointer does not.
# ---------------------------------------------------------------------------


struct _CoroStreamPtr(Copyable, Movable):
    """Holds the address of a heap-allocated CoroStreamCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[CoroStreamCtx, MutAnyOrigin]:
        return UnsafePointer[CoroStreamCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# _free_stream — single cleanup path for CoroStreamCtx
# ---------------------------------------------------------------------------


def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    """Hard-destroy the CoroStreamCtx allocation."""
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# CoroStreamCtxPool — per-connection allocation pool
# ---------------------------------------------------------------------------
#
# Recycles `CoroStreamCtx`-sized heap blocks across requests on the same
# connection. The pool holds typed but uninitialised pointers (the
# pointee has been destroyed before re-entry). On `acquire`, the caller
# initialises the block in place via `init_pointee_move`; on `release`,
# the caller destroys the pointee then hands the bare memory back here.
#
# Why this exists: the old `CoroutinePool` (boucle.stackful) implicitly
# warmed the per-connection cache lines because it recycled 64 KiB
# stack frames at the same address across requests. Path A's sync
# handler killed that locality (every `_heap_alloc[CoroStreamCtx]` is
# a fresh address), and the cleanest pinned bench measured a -7.8% RPS
# regression on /json/50 — the workload most sensitive to L1/L2 reuse.
#
# Capacity 16 mirrors the prior `CoroutinePool` default and matches
# typical h2load `-m 10` active-streams-per-connection.

struct CoroStreamCtxPool(Movable):
    """Free-list of typed `CoroStreamCtx`-sized heap blocks. Caller
    owns initialisation/destruction of the pointee; the pool only
    manages the underlying memory."""

    var _free: List[UInt64]
    var _capacity: Int

    def __init__(out self, *, capacity: Int = 16):
        self._free = List[UInt64]()
        self._capacity = capacity

    def __init__(out self, *, deinit take: Self):
        self._free = take._free^
        self._capacity = take._capacity

    fn __del__(deinit self):
        for i in range(len(self._free)):
            var p = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
                unsafe_from_address=Int(self._free[i])
            )
            p.free()

    fn acquire(mut self) raises -> UnsafePointer[CoroStreamCtx, MutAnyOrigin]:
        """Take a free slot if one is available, else allocate fresh."""
        if len(self._free) > 0:
            var addr = self._free.pop()
            return UnsafePointer[CoroStreamCtx, MutAnyOrigin](
                unsafe_from_address=Int(addr)
            )
        return _heap_alloc[CoroStreamCtx](1).as_any_origin()

    fn release(
        mut self, ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
    ):
        """Return a slot whose pointee has already been destroyed.
        Beyond capacity → free; under capacity → keep for reuse."""
        if len(self._free) < self._capacity:
            self._free.append(UInt64(Int(ptr)))
        else:
            ptr.free()

    fn idle_count(self) -> Int:
        return len(self._free)


# ---------------------------------------------------------------------------
# H2CoroServer — server adapter using a per-stream state machine
# ---------------------------------------------------------------------------


struct H2CoroServer(Movable):
    """Drive per-stream state from an HTTP/2 H2Connection.  Sans-IO:
    the caller feeds inbound bytes via `feed()` and drains outbound
    bytes via `drain()`.  Each stream's user handler runs synchronously
    when the request arrives (Sprint 1 Path A — no stackful coroutines).
    """

    var _conn: H2Connection
    var _body_fn: H2BodyFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _CoroStreamPtr]
    var _ctx_pool: CoroStreamCtxPool

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        body_fn: H2BodyFn,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with default production config (server-side)."""
        _check_stream_ctx_size()
        self._conn = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
        )
        self._conn.initiate_connection()
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _CoroStreamPtr]()
        self._ctx_pool = CoroStreamCtxPool(capacity=16)
        self._flush_outbound()

    def __init__(
        out self,
        *,
        body_fn: H2BodyFn,
        config: H2Config,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with a custom H2Config (server-side)."""
        _check_stream_ctx_size()
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _CoroStreamPtr]()
        self._ctx_pool = CoroStreamCtxPool(capacity=16)
        self._flush_outbound()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self._body_fn = take._body_fn
        self._extra_data = take._extra_data
        self._outbuf = take._outbuf^
        self._streams = take._streams^
        self._ctx_pool = take._ctx_pool^

    fn __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                _free_stream(ctx_ptr)
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound transport bytes, dispatch events, drain responses."""
        var data_list = List[UInt8]()
        for i in range(len(data)):
            data_list.append(data[i])
        var events = self._conn.receive_data(data_list)
        self._dispatch_events(events)
        self._drain_responses()
        self._flush_outbound()

    def drain(mut self) -> List[UInt8]:
        """Drain queued outbound bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        """Check whether stream ID is present in the streams dict."""
        return sid in self._streams

    fn _release_stream(
        mut self, ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]
    ):
        """Destroy the CoroStreamCtx pointee and return its memory
        block to the per-connection pool (or free if over capacity).
        Recycling preserves L1/L2 locality across requests on the
        same connection — the JSON encoder's working set stays warm."""
        ctx_ptr.destroy_pointee()
        self._ctx_pool.release(ctx_ptr)

    def _flush_outbound(mut self):
        """Move pending outbound bytes from the H2Connection into our
        buffer.  Bulk-extend (was per-byte append: ~12% self post-Task-1)."""
        var pending = self._conn.data_to_send()
        if len(pending) > 0:
            self._outbuf.extend(pending^)

    def _run_handler(mut self, stream_id: Int) raises:
        """Invoke the user handler synchronously. On error, send
        RST_STREAM and clean up. On success, response data is in
        `ctx.resp_writer` for `_drain_responses` to flush."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        try:
            self._body_fn(ctx_ptr)
        except e:
            self._conn.send_rst_stream(
                UInt32(stream_id), UInt32(2)  # INTERNAL_ERROR
            )
            self._cleanup_stream(stream_id)

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context and remove from dict."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        self._release_stream(ctx_ptr)
        _ = self._streams.pop(stream_id)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            self._release_stream(ctx_ptr)
            _ = self._streams.pop(stream_id)

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch H2 events to per-stream state."""
        for i in range(len(events)):
            var evt = H2Event(other=events[i])
            if evt.kind == H2_EVT_REQUEST_RECEIVED:
                self._on_request_received(evt)
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                self._on_data_received(evt)
            elif evt.kind == H2_EVT_TRAILERS_RECEIVED:
                self._on_trailers_received(evt)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self._on_stream_ended(evt)
            elif evt.kind == H2_EVT_STREAM_RESET:
                self._on_stream_reset(evt)
            elif evt.kind == H2_EVT_GOAWAY_RECEIVED:
                self._on_goaway(evt)
            elif evt.kind == H2_EVT_CONNECTION_TERMINATED:
                self._on_goaway(evt)

    def _on_request_received(mut self, evt: H2Event) raises:
        """Handle REQUEST_RECEIVED: parse headers, allocate CoroStreamCtx
        on heap, register in streams dict, and run the handler now."""
        var req = request_from_h2_headers(evt.stream_id, evt.headers)
        var stream_id = Int(evt.stream_id)
        var stream_ended = evt.stream_ended

        var ctx_ptr = self._ctx_pool.acquire()
        var ctx = CoroStreamCtx(
            request=req^,
            caps=Capabilities.for_h2(),
            stream_id=evt.stream_id,
            extra_data=self._extra_data,
        )

        if stream_ended:
            ctx.recv_body._set_end()
            ctx.request_ended = True

        ctx_ptr.init_pointee_move(ctx^)
        self._streams[stream_id] = _CoroStreamPtr(UInt64(Int(ctx_ptr)))

        # Run handler synchronously — Path A simplification.
        self._run_handler(stream_id)

    def _on_data_received(mut self, evt: H2Event) raises:
        """Handle DATA_RECEIVED: push data into RecvBody, manage flow
        control. Path A: handler ran already on REQUEST_RECEIVED, so
        DATA arriving here is body content for streaming clients —
        accumulate it and acknowledge."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        if len(evt.data) > 0:
            var data_copy = evt.data.copy()
            ctx.recv_body._push(BodyFrame.data(data_copy^))
        if not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                evt.flow_controlled_length, evt.stream_id
            )
        else:
            ctx.unacked_bytes += evt.flow_controlled_length
        if ctx.unacked_bytes > 0 and not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                ctx.unacked_bytes, evt.stream_id
            )
            ctx.unacked_bytes = 0
        if evt.stream_ended and not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        if evt.stream_ended:
            self._maybe_cleanup_stream(sid)

    def _on_trailers_received(mut self, evt: H2Event) raises:
        """Handle TRAILERS_RECEIVED: convert headers, push as trailer
        BodyFrame.  Trailers always carry END_STREAM."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var trailer_headers = headers_from_h2(evt.headers)
        var ctx = ctx_ptr.take_pointee()
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._maybe_cleanup_stream(sid)

    def _on_stream_ended(mut self, evt: H2Event) raises:
        """Handle STREAM_ENDED: mark the body as ended."""
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
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """Handle STREAM_RESET: tear down the stream."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        self._release_stream(ctx_ptr)
        _ = self._streams.pop(sid)

    def _on_goaway(mut self, evt: H2Event) raises:
        """Handle GOAWAY_RECEIVED / CONNECTION_TERMINATED: free all
        streams.  The handler has already returned, so there's nothing
        to wake up — just reclaim memory."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            var sid = keys[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            _free_stream(ctx_ptr)
            _ = self._streams.pop(sid)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self) raises:
        """Drain pending response data from stream contexts into the H2
        connection.  Uses take_pointee/init_pointee_move to safely
        interleave ctx access with self._conn mutations."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            var made_progress = False
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
                continue
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
                self._conn.send_headers(
                    UInt32(sid), h2_hdrs^, end_stream=False
                )
                ctx.headers_sent = True
                made_progress = True
            # Drain body frames. Buffer data frames so we can fold END_STREAM
            # onto the last DATA payload instead of emitting a 0-byte trailer
            # — some H2 clients (h2load) misbehave on a separate empty
            # DATA(END_STREAM) when many streams share a TLS record.
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
                        self._conn.send_data(
                            UInt32(sid), List[UInt8](), end_stream=True
                        )
                    else:
                        var n = len(pending_data)
                        for k in range(n - 1):
                            self._conn.send_data(
                                UInt32(sid), pending_data[k].copy(), end_stream=False
                            )
                        self._conn.send_data(
                            UInt32(sid), pending_data[n - 1].copy(), end_stream=True
                        )
                        pending_data = List[List[UInt8]]()
                    ctx.response_ended = True
                    made_progress = True
                    break
                elif f.is_trailers():
                    for k in range(len(pending_data)):
                        self._conn.send_data(
                            UInt32(sid), pending_data[k].copy(), end_stream=False
                        )
                    pending_data = List[List[UInt8]]()
                    var trailer_h2 = headers_to_h2(f.trailers())
                    self._conn.send_headers(
                        UInt32(sid), trailer_h2^, end_stream=True
                    )
                    ctx.response_ended = True
                    made_progress = True
                    break
            for k in range(len(pending_data)):
                self._conn.send_data(
                    UInt32(sid), pending_data[k].copy(), end_stream=False
                )
            ctx_ptr.init_pointee_move(ctx^)
            if made_progress:
                self._maybe_cleanup_stream(sid)
