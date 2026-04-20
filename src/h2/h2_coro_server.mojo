# src/h2/h2_coro_server.mojo
#
# HTTP/2 server-side coroutine adapter.  Sans-I/O: feed inbound wire bytes,
# drain outbound bytes.  Translates H2Connection events into per-stream
# stackful coroutines (from boucle) instead of callback-based StreamHandler.
# (M2.6 Task 1)

from std.collections import Dict
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.stackful import CoroHandle, CoroYielder, CoroBody

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
# CoroStreamCtx — per-stream shared state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for coroutine-based H2 serving.  Heap-allocated
    so both the adapter and the coroutine body can access it via pointer.
    Contains the request, body receiver, response writer, capabilities,
    and coroutine lifecycle bookkeeping."""

    var request: Request
    var recv_body: RecvBody
    var resp_writer: ResponseWriter
    var caps: Capabilities
    var stream_id: UInt32
    var extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var coro_addr: UInt64  # address of heap-allocated CoroHandle
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
        self.coro_addr = UInt64(0)
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
        self.coro_addr = take.coro_addr
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent
        self.unacked_bytes = take.unacked_bytes

    def coro_ptr(self) -> UnsafePointer[CoroHandle, MutAnyOrigin]:
        """Return pointer to the heap-allocated CoroHandle."""
        return UnsafePointer[CoroHandle, MutAnyOrigin](
            unsafe_from_address=Int(self.coro_addr)
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
# _free_stream — single cleanup path for CoroHandle + CoroStreamCtx
# ---------------------------------------------------------------------------


def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    """Free both the CoroHandle (if allocated) and the CoroStreamCtx heap
    allocations.  Single cleanup path used by __del__, _on_stream_reset,
    and _cleanup_stream."""
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# H2CoroServer — server adapter using per-stream coroutines
# ---------------------------------------------------------------------------


struct H2CoroServer(Movable):
    """Drive per-stream coroutines from an HTTP/2 H2Connection.  Sans-I/O:
    the caller feeds inbound bytes via `feed()` and drains outbound bytes
    via `drain()`.  Each stream gets a stackful coroutine that is resumed
    when events arrive for that stream."""

    var _conn: H2Connection
    var _body_fn: CoroBody
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _CoroStreamPtr]

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        body_fn: CoroBody,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with default production config (server-side)."""
        self._conn = H2Connection(
            client_side=False,
            config=h2_production_config(client_side=False),
        )
        self._conn.initiate_connection()
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _CoroStreamPtr]()
        self._flush_outbound()

    def __init__(
        out self,
        *,
        body_fn: CoroBody,
        config: H2Config,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        """Create with a custom H2Config (server-side)."""
        self._conn = H2Connection(client_side=False, config=config)
        self._conn.initiate_connection()
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _CoroStreamPtr]()
        self._flush_outbound()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self._body_fn = take._body_fn
        self._extra_data = take._extra_data
        self._outbuf = take._outbuf^
        self._streams = take._streams^

    fn __del__(deinit self):
        """Destroy and free all heap-allocated stream contexts. For any
        suspended coroutines, push an error into recv_body so the coroutine
        can unwind cleanly, then destroy."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                # Push error into recv_body so a suspended coroutine sees it
                var ctx = ctx_ptr.take_pointee()
                ctx.recv_body._set_error(
                    StreamError.connection_closed()
                )
                ctx_ptr.init_pointee_move(ctx^)
                # If coroutine is still resumable, resume it so it can
                # observe the error and exit.
                if ctx_ptr[].coro_addr != UInt64(0):
                    var coro_p = ctx_ptr[].coro_ptr()
                    if coro_p[].can_resume():
                        try:
                            coro_p[].resume()
                        except:
                            pass
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

    def resume_stream(mut self, stream_id: Int) raises:
        """Externally resume a stream's coroutine (e.g. after async I/O
        completes).  Drains any response data produced."""
        if not self._has_stream(stream_id):
            return
        self._resume_and_handle_error(stream_id)
        self._drain_responses()
        self._flush_outbound()

    def should_close(self) -> Bool:
        """True when the H2 connection has reached terminal state."""
        return self._conn.is_closed()

    # --- Internal -----------------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        """Check whether stream ID is present in the streams dict."""
        return sid in self._streams

    def _flush_outbound(mut self):
        """Move pending outbound bytes from the H2Connection into our buffer."""
        var pending = self._conn.data_to_send()
        for i in range(len(pending)):
            self._outbuf.append(pending[i])

    def _resume_and_handle_error(mut self, stream_id: Int) raises:
        """Resume a stream's coroutine, catching errors and sending
        RST_STREAM if the coroutine raises."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].coro_addr == UInt64(0):
            return
        var coro_p = ctx_ptr[].coro_ptr()
        if not coro_p[].can_resume():
            return
        try:
            coro_p[].resume()
        except e:
            # Coroutine raised an error — send RST_STREAM with INTERNAL_ERROR
            self._conn.send_rst_stream(
                UInt32(stream_id), UInt32(2)  # INTERNAL_ERROR
            )
            self._cleanup_stream(stream_id)
            return
        # If coroutine is done, check if we need cleanup
        if coro_p[].is_done():
            self._maybe_cleanup_stream(stream_id)

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context and remove from dict."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _free_stream(ctx_ptr)
        _ = self._streams.pop(stream_id)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        # Read through pointer — Bool is trivially copyable
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _free_stream(ctx_ptr)
            _ = self._streams.pop(stream_id)

    # --- Event dispatch -----------------------------------------------------

    def _dispatch_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch H2 events to stream coroutines."""
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
        """Handle REQUEST_RECEIVED: parse headers, allocate CoroStreamCtx on
        heap, create CoroHandle on heap, set coro_addr, first resume."""
        var req = request_from_h2_headers(evt.stream_id, evt.headers)
        var stream_id = Int(evt.stream_id)
        var stream_ended = evt.stream_ended

        # Allocate CoroStreamCtx on the heap
        var ctx_ptr = _heap_alloc[CoroStreamCtx](1).as_any_origin()
        var ctx = CoroStreamCtx(
            request=req^,
            caps=Capabilities.for_h2(),
            stream_id=evt.stream_id,
            extra_data=self._extra_data,
        )

        # If END_STREAM was set on the HEADERS frame, mark body ended
        if stream_ended:
            ctx.recv_body._set_end()
            ctx.request_ended = True

        ctx_ptr.init_pointee_move(ctx^)

        # Allocate CoroHandle on the heap — user_data points to the ctx
        var user_data = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(ctx_ptr)
        )
        var coro_heap = _heap_alloc[CoroHandle](1).as_any_origin()
        var coro = CoroHandle(self._body_fn, user_data)
        coro_heap.init_pointee_move(coro^)

        # Set coro_addr in the ctx
        ctx_ptr[].coro_addr = UInt64(Int(coro_heap))

        # Store in streams dict
        self._streams[stream_id] = _CoroStreamPtr(UInt64(Int(ctx_ptr)))

        # First resume — the coroutine body starts executing
        self._resume_and_handle_error(stream_id)

    def _on_data_received(mut self, evt: H2Event) raises:
        """Handle DATA_RECEIVED: push data into RecvBody, manage flow control,
        resume coroutine.  If END_STREAM, mark body ended."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        # take_pointee to get mut access to recv_body
        var ctx = ctx_ptr.take_pointee()
        # Push data into RecvBody
        if len(evt.data) > 0:
            var data_copy = evt.data.copy()
            ctx.recv_body._push(BodyFrame.data(data_copy^))
        # Flow control: acknowledge unless paused
        if not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                evt.flow_controlled_length, evt.stream_id
            )
        else:
            ctx.unacked_bytes += evt.flow_controlled_length
        # Check if paused state cleared after data push
        if ctx.unacked_bytes > 0 and not ctx.recv_body.is_paused():
            self._conn.acknowledge_received_data(
                ctx.unacked_bytes, evt.stream_id
            )
            ctx.unacked_bytes = 0
        # If END_STREAM was set on the DATA frame, mark body ended
        if evt.stream_ended and not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        # Move back into the heap
        ctx_ptr.init_pointee_move(ctx^)
        # Resume coroutine so it can consume the new data
        self._resume_and_handle_error(sid)
        # Check if both sides are done
        if evt.stream_ended:
            self._maybe_cleanup_stream(sid)

    def _on_trailers_received(mut self, evt: H2Event) raises:
        """Handle TRAILERS_RECEIVED: convert headers, push as trailer BodyFrame.
        Trailers always carry END_STREAM."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var trailer_headers = headers_from_h2(evt.headers)
        # take_pointee to get mut access to recv_body
        var ctx = ctx_ptr.take_pointee()
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        # Trailers always carry END_STREAM — mark body ended
        if not ctx.request_ended:
            ctx.request_ended = True
            ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        # Resume coroutine so it can process trailers
        self._resume_and_handle_error(sid)
        # Trailers carry END_STREAM — check if both sides done
        self._maybe_cleanup_stream(sid)

    def _on_stream_ended(mut self, evt: H2Event) raises:
        """Handle STREAM_ENDED: mark the body as ended, resume coroutine."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        # Read request_ended through the pointer (Bool is trivially copyable)
        if ctx_ptr[].request_ended:
            return  # already ended (e.g. END_STREAM on HEADERS)
        # take_pointee to get mut access to body
        var ctx = ctx_ptr.take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        # Resume coroutine so it sees the end
        self._resume_and_handle_error(sid)
        # Check if both sides done
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """Handle STREAM_RESET: push error into body, resume so coroutine
        can see the error, then clean up."""
        var sid = Int(evt.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(evt.error_code)
        ctx.recv_body._set_error(StreamError(other=err))
        ctx_ptr.init_pointee_move(ctx^)
        # Resume coroutine so it observes the error and can unwind
        if ctx_ptr[].coro_addr != UInt64(0):
            var coro_p = ctx_ptr[].coro_ptr()
            if coro_p[].can_resume():
                try:
                    coro_p[].resume()
                except:
                    pass
        # Clean up — both directions are dead after RST
        _free_stream(ctx_ptr)
        _ = self._streams.pop(sid)

    def _on_goaway(mut self, evt: H2Event) raises:
        """Handle GOAWAY_RECEIVED / CONNECTION_TERMINATED: push connection-closed
        error into all open streams and resume their coroutines."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            var sid = keys[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            ctx.recv_body._set_error(StreamError.connection_closed())
            ctx_ptr.init_pointee_move(ctx^)
            # Resume coroutine so it sees the error
            if ctx_ptr[].coro_addr != UInt64(0):
                var coro_p = ctx_ptr[].coro_ptr()
                if coro_p[].can_resume():
                    try:
                        coro_p[].resume()
                    except:
                        pass
            _free_stream(ctx_ptr)
            _ = self._streams.pop(sid)

    # --- Response draining --------------------------------------------------

    def _drain_responses(mut self) raises:
        """Drain pending response data from stream contexts into the H2
        connection.  Uses take_pointee/init_pointee_move to safely interleave
        ctx access with self._conn mutations."""
        # Snapshot stream IDs to avoid mutating dict while iterating
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            # Use take_pointee to get mut access
            var ctx = ctx_ptr.take_pointee()
            var made_progress = False
            # Skip if response not started
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
                var h2_hdrs = response_to_h2_headers(status^, resp_headers^)
                self._conn.send_headers(
                    UInt32(sid), h2_hdrs^, end_stream=False
                )
                ctx.headers_sent = True
                made_progress = True
            # Drain body frames
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    self._conn.send_data(
                        UInt32(sid), f.data().copy(), end_stream=False
                    )
                    made_progress = True
                elif f.is_end():
                    self._conn.send_data(
                        UInt32(sid), List[UInt8](), end_stream=True
                    )
                    ctx.response_ended = True
                    made_progress = True
                    break
                elif f.is_trailers():
                    var trailer_h2 = headers_to_h2(f.trailers())
                    self._conn.send_headers(
                        UInt32(sid), trailer_h2^, end_stream=True
                    )
                    ctx.response_ended = True
                    made_progress = True
                    break
            # Move back into the heap and maybe cleanup
            ctx_ptr.init_pointee_move(ctx^)
            if made_progress:
                self._maybe_cleanup_stream(sid)
