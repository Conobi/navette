# src/h2/h2_session.mojo
#
# HTTP/2 client session adapter.  Sans-I/O: feed inbound wire bytes,
# drain outbound bytes.  Implements the Session trait for multiplexed
# HTTP/2 client connections.  (M5.5 Task 8)

from std.collections import Dict
from std.collections.deque import Deque
from std.collections.optional import Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from lib.http1.types import Header
from lib.http2.connection import (
    H2Connection,
    H2Config,
    H2Event,
    H2_EVT_RESPONSE_RECEIVED,
    H2_EVT_DATA_RECEIVED,
    H2_EVT_STREAM_ENDED,
    H2_EVT_STREAM_RESET,
    H2_EVT_TRAILERS_RECEIVED,
    H2_NO_ERROR,
)
from src.http.handler import Capabilities, ALPN_H2, StreamError
from src.http.session import Session, RequestHandle
from src.http.request import Request
from src.http.response import Response
from src.http.headers import Headers
from src.http.version import Version
from src.http.status import StatusCode
from src.http.body import BodyFrame
from src.h2.pseudo_headers import request_to_h2_headers
from src.h2.config import h2_production_config


# ---------------------------------------------------------------------------
# _ClientCtx — per-stream client context (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct _ClientCtx(Movable):
    """Per-stream client state that lives on the heap.  Move-only types
    prevent direct Dict storage, so we heap-allocate and store via
    _ClientStreamPtr."""

    var handle_id: UInt64
    var status_code: Int
    var headers: Headers
    var body_data: List[UInt8]
    var complete: Bool
    var errored: Bool
    var error_code: UInt32

    def __init__(out self, *, handle_id: UInt64):
        self.handle_id = handle_id
        self.status_code = -1
        self.headers = Headers()
        self.body_data = List[UInt8]()
        self.complete = False
        self.errored = False
        self.error_code = UInt32(0)

    def __init__(out self, *, deinit take: Self):
        self.handle_id = take.handle_id
        self.status_code = take.status_code
        self.headers = take.headers^
        self.body_data = take.body_data^
        self.complete = take.complete
        self.errored = take.errored
        self.error_code = take.error_code


# ---------------------------------------------------------------------------
# _ClientStreamPtr — thin wrapper so Dict[Int, _ClientStreamPtr] satisfies
# CollectionElement (Copyable + Movable).
# ---------------------------------------------------------------------------


struct _ClientStreamPtr(Copyable, Movable):
    """Holds the address of a heap-allocated _ClientCtx as a UInt64."""

    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[_ClientCtx, MutAnyOrigin]:
        return UnsafePointer[_ClientCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# H2Session — client session adapter
# ---------------------------------------------------------------------------


struct H2Session(Session):
    """HTTP/2 client session.  Sans-I/O: the caller feeds inbound bytes via
    `feed()` and drains outbound bytes via `drain()`.  Supports multiple
    concurrent streams (multiplexed)."""

    var _conn: H2Connection
    var _outbuf: List[UInt8]
    var _next_handle_id: UInt64
    var _stream_ctxs: Dict[Int, _ClientStreamPtr]
    var _handle_to_stream: Dict[Int, Int]

    # --- Constructors -------------------------------------------------------

    def __init__(out self) raises:
        """Create with default production config (client-side)."""
        self._conn = H2Connection(
            client_side=True,
            config=h2_production_config(client_side=True),
        )
        self._conn.initiate_connection()
        self._outbuf = List[UInt8]()
        self._next_handle_id = UInt64(0)
        self._stream_ctxs = Dict[Int, _ClientStreamPtr]()
        self._handle_to_stream = Dict[Int, Int]()
        self._flush_outbound()

    def __init__(out self, *, var config: H2Config) raises:
        """Create with a custom H2Config (client-side)."""
        self._conn = H2Connection(client_side=True, config=config^)
        self._conn.initiate_connection()
        self._outbuf = List[UInt8]()
        self._next_handle_id = UInt64(0)
        self._stream_ctxs = Dict[Int, _ClientStreamPtr]()
        self._handle_to_stream = Dict[Int, Int]()
        self._flush_outbound()

    def __init__(out self, *, deinit take: Self):
        self._conn = take._conn^
        self._outbuf = take._outbuf^
        self._next_handle_id = take._next_handle_id
        self._stream_ctxs = take._stream_ctxs^
        self._handle_to_stream = take._handle_to_stream^

    # --- Session trait API ---------------------------------------------------

    def submit(mut self, var req: Request) raises -> RequestHandle:
        self._next_handle_id += UInt64(1)
        var handle_id = self._next_handle_id
        var stream_id = self._conn.next_stream_id()
        var h2_headers = request_to_h2_headers(req)
        var has_body = req.body.is_buffered() and len(req.body.bytes()) > 0
        var end_stream = not has_body and not req.body.is_stream()
        self._conn.send_headers(stream_id, h2_headers^, end_stream=end_stream)
        if has_body:
            self._conn.send_data(
                stream_id, req.body.bytes().copy(), end_stream=True
            )
        # Flush pending frames to outbuf
        self._flush_outbound()
        # Allocate client context on heap
        var ctx_ptr = _heap_alloc[_ClientCtx](1).as_any_origin()
        var ctx = _ClientCtx(handle_id=handle_id)
        ctx_ptr.init_pointee_move(ctx^)
        self._stream_ctxs[Int(stream_id)] = _ClientStreamPtr(
            UInt64(Int(ctx_ptr))
        )
        self._handle_to_stream[Int(handle_id)] = Int(stream_id)
        return RequestHandle(id=handle_id)

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises:
        # For H2 with multiplexing, events are already processed in feed().
        # The caller drives the transport byte pump externally.
        pass

    def run_one(mut self, mut handle: RequestHandle) raises:
        var hid = Int(handle.id())
        # Look up the stream for this handle
        var stream_id: Int
        try:
            stream_id = self._handle_to_stream[hid]
        except:
            return
        # Look up the per-stream context
        var ctx_wrap: _ClientStreamPtr
        try:
            ctx_wrap = _ClientStreamPtr(other=self._stream_ctxs[stream_id])
        except:
            return
        var ctx_ptr = ctx_wrap.ptr()

        # Handle error-before-response: RST_STREAM arrived before any
        # RESPONSE_RECEIVED, so status_code is still -1.
        if ctx_ptr[].errored and not handle.is_complete():
            handle._set_error(
                StreamError.rst_stream(ctx_ptr[].error_code)
            )
            # Cleanup
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
            try:
                _ = self._stream_ctxs.pop(stream_id)
                _ = self._handle_to_stream.pop(hid)
            except:
                pass
            return

        # Only deliver response when the stream is complete (all data
        # received). This avoids the second-branch data-loss issue where
        # body data arriving after the initial _set_response would be
        # silently dropped.
        if ctx_ptr[].status_code >= 0 and ctx_ptr[].complete and not handle.has_headers():
            var ctx = ctx_ptr.take_pointee()
            var resp = Response(
                status=StatusCode(ctx.status_code),
                reason=String(""),
                version=Version.http_2(),
                headers=ctx.headers^,
                body=List[BodyFrame](),
            )
            if len(ctx.body_data) > 0:
                var body_copy = ctx.body_data^
                resp.body.append(BodyFrame.data(body_copy^))
                ctx.body_data = List[UInt8]()
            ctx.headers = Headers()
            handle._set_response(resp^)
            handle._mark_complete()
            # Cleanup — free heap allocation and remove from Dicts
            ctx_ptr.init_pointee_move(ctx^)
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
            try:
                _ = self._stream_ctxs.pop(stream_id)
                _ = self._handle_to_stream.pop(hid)
            except:
                pass

    def capabilities(self) -> Capabilities:
        return Capabilities.for_h2()

    def alpn(self) -> Int:
        return ALPN_H2

    def close(deinit self) raises:
        """Send GOAWAY if connection is not already closed, then free all
        remaining heap-allocated stream contexts."""
        if not self._conn.is_closed():
            self._conn.send_goaway(UInt32(0), UInt32(H2_NO_ERROR))
        # Free all heap-allocated contexts
        var keys = List[Int]()
        for key in self._stream_ctxs.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var p = self._stream_ctxs[keys[i]].ptr()
                p.destroy_pointee()
                p.free()
            except:
                pass

    # --- Transport bridging API ---------------------------------------------

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Feed inbound transport bytes, dispatch events."""
        var data_list = List[UInt8]()
        for i in range(len(data)):
            data_list.append(data[i])
        var events = self._conn.receive_data(data_list)
        self._dispatch_client_events(events)
        self._flush_outbound()

    def drain(mut self) -> List[UInt8]:
        """Drain queued outbound bytes for the transport to write."""
        var out = self._outbuf^
        self._outbuf = List[UInt8]()
        return out^

    # --- Internal -----------------------------------------------------------

    def _flush_outbound(mut self):
        """Move pending outbound bytes from H2Connection into our buffer."""
        var pending = self._conn.data_to_send()
        for i in range(len(pending)):
            self._outbuf.append(pending[i])

    def _dispatch_client_events(mut self, mut events: List[H2Event]) raises:
        """Dispatch H2 events for client-side processing."""
        for i in range(len(events)):
            var evt = H2Event(other=events[i])
            if evt.kind == H2_EVT_RESPONSE_RECEIVED:
                self._on_response_received(evt)
            elif evt.kind == H2_EVT_DATA_RECEIVED:
                self._on_data_received(evt)
            elif evt.kind == H2_EVT_TRAILERS_RECEIVED:
                self._on_trailers_received(evt)
            elif evt.kind == H2_EVT_STREAM_ENDED:
                self._on_stream_ended(evt)
            elif evt.kind == H2_EVT_STREAM_RESET:
                self._on_stream_reset(evt)

    def _on_response_received(mut self, evt: H2Event) raises:
        """Handle RESPONSE_RECEIVED: extract :status and headers, store on ctx."""
        var sid = Int(evt.stream_id)
        var ctx_ptr: UnsafePointer[_ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._stream_ctxs[sid].ptr()
        except:
            return
        # Parse :status from pseudo-headers and extract regular headers
        var status_code = -1
        var headers = Headers()
        for j in range(len(evt.headers)):
            var name = evt.headers[j].name
            var value = evt.headers[j].value
            if name == ":status":
                status_code = atol(value)
            else:
                headers.add(name, value)
        var ctx = ctx_ptr.take_pointee()
        ctx.status_code = status_code
        ctx.headers = headers^
        if evt.stream_ended:
            ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_data_received(mut self, evt: H2Event) raises:
        """Handle DATA_RECEIVED: append data to ctx, acknowledge for flow control."""
        var sid = Int(evt.stream_id)
        var ctx_ptr: UnsafePointer[_ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._stream_ctxs[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        for j in range(len(evt.data)):
            ctx.body_data.append(evt.data[j])
        ctx_ptr.init_pointee_move(ctx^)
        # Acknowledge received data for flow control
        if evt.flow_controlled_length > 0:
            self._conn.acknowledge_received_data(
                evt.flow_controlled_length, evt.stream_id
            )
        if evt.stream_ended:
            var ctx2 = ctx_ptr.take_pointee()
            ctx2.complete = True
            ctx_ptr.init_pointee_move(ctx2^)

    def _on_trailers_received(mut self, evt: H2Event) raises:
        """Handle TRAILERS_RECEIVED: trailers imply stream ended."""
        var sid = Int(evt.stream_id)
        var ctx_ptr: UnsafePointer[_ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._stream_ctxs[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_ended(mut self, evt: H2Event) raises:
        """Handle STREAM_ENDED: mark ctx complete."""
        var sid = Int(evt.stream_id)
        var ctx_ptr: UnsafePointer[_ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._stream_ctxs[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_reset(mut self, evt: H2Event) raises:
        """Handle STREAM_RESET: mark ctx errored."""
        var sid = Int(evt.stream_id)
        var ctx_ptr: UnsafePointer[_ClientCtx, MutAnyOrigin]
        try:
            ctx_ptr = self._stream_ctxs[sid].ptr()
        except:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.errored = True
        ctx.error_code = evt.error_code
        ctx.complete = True
        ctx_ptr.init_pointee_move(ctx^)
