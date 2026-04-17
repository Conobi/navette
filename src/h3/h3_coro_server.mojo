# src/h3/h3_coro_server.mojo
#
# HTTP/3 server-side coroutine adapter. Sans-I/O: feed inbound QUIC datagrams,
# drain outbound datagrams. Translates H3Connection events into per-stream
# stackful coroutines (boucle.stackful) instead of StreamHandler callbacks.
# (M5c)

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.stackful import CoroHandle, CoroYielder, CoroBody

from src.quic.connection import QuicConnection
from src.h3.connection import H3Connection, H3Event
from src.h3.error import H3_REQUEST_CANCELLED
from src.h3.qpack import QpackHeaderField
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request
from src.http.headers import Headers
from src.http.method import Method
from src.http.version import Version
from src.http.body import BodyFrame
from src.http.status import StatusCode


# ---------------------------------------------------------------------------
# CoroStreamCtx — per-stream shared state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for coroutine-based H3 serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.
    No unacked_bytes field — QUIC handles flow control internally."""

    var request:        Request
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var caps:           Capabilities
    var stream_id:      UInt64
    var extra_data:     UnsafePointer[NoneType, MutExternalOrigin]
    var coro_addr:      UInt64   # address of heap-allocated CoroHandle (0 = none)
    var request_ended:  Bool
    var response_ended: Bool
    var headers_sent:   Bool

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
        self.coro_addr = UInt64(0)
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False

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

    def coro_ptr(self) -> UnsafePointer[CoroHandle, MutAnyOrigin]:
        return UnsafePointer[CoroHandle, MutAnyOrigin](
            unsafe_from_address=Int(self.coro_addr)
        )


# ---------------------------------------------------------------------------
# _CoroStreamPtr — thin Copyable+Movable wrapper for Dict storage
# ---------------------------------------------------------------------------


struct _CoroStreamPtr(Copyable, Movable):
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
    """Free both the CoroHandle (if allocated) and the CoroStreamCtx.
    ALWAYS call _streams.pop(sid) BEFORE calling this function."""
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# H3CoroServer — server adapter using per-stream coroutines
# ---------------------------------------------------------------------------


struct H3CoroServer(Movable):
    """Drive per-stream coroutines from an HTTP/3 H3Connection. Sans-I/O:
    caller feeds inbound QUIC datagrams via `feed_datagram` and drains
    outbound datagrams via `drain_datagrams`. Each new request spawns a
    stackful coroutine that is resumed as events arrive."""

    var _h3:         H3Connection
    var _body_fn:    CoroBody
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _streams:    Dict[Int, _CoroStreamPtr]

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        body_fn: CoroBody,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        self._h3 = H3Connection.server(quic^)
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._streams = Dict[Int, _CoroStreamPtr]()

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self._body_fn = take._body_fn
        self._extra_data = take._extra_data
        self._streams = take._streams^

    fn __del__(deinit self):
        """Destroy all heap-allocated stream contexts. Push connection-closed
        error into suspended coroutines so they can unwind cleanly."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                var ctx = ctx_ptr.take_pointee()
                ctx.recv_body._set_error(StreamError.connection_closed())
                ctx_ptr.init_pointee_move(ctx^)
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

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram. Dispatches H3 events and drains
        pending response data."""
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Return outbound QUIC datagrams accumulated since last call."""
        return self._h3.drain_datagrams(now)

    def should_close(self) -> Bool:
        """True when the H3 connection has reached terminal state."""
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Internal: helpers --------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        return sid in self._streams

    def _resume_and_handle_error(mut self, stream_id: Int) raises:
        """Resume a stream's coroutine. On raise, send RST_STREAM and free."""
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
        except:
            try:
                self._h3.reset_stream(UInt64(stream_id), H3_REQUEST_CANCELLED)
            except:
                pass
            self._cleanup_stream(stream_id)
            return
        if coro_p[].is_done():
            self._maybe_cleanup_stream(stream_id)

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context. Pop BEFORE free."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _ = self._streams.pop(stream_id)   # pop FIRST
        _free_stream(ctx_ptr)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(stream_id)   # pop FIRST
            _free_stream(ctx_ptr)

    # --- Internal: event dispatch -------------------------------------------

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

    def _on_request(mut self, ev: H3Event) raises:
        """First HEADERS_RECEIVED: parse pseudo-fields into Request, allocate
        CoroStreamCtx + CoroHandle on heap, insert into _streams, first resume.
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

        var ctx_ptr = _heap_alloc[CoroStreamCtx](1).as_any_origin()
        var ctx = CoroStreamCtx(
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

        # Allocate CoroHandle on heap
        var user_data = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(ctx_ptr)
        )
        var coro_heap = _heap_alloc[CoroHandle](1).as_any_origin()
        var coro = CoroHandle(self._body_fn, user_data)
        coro_heap.init_pointee_move(coro^)
        ctx_ptr[].coro_addr = UInt64(Int(coro_heap))

        # Insert BEFORE first resume so _drain_responses can find the stream
        var sid = Int(ev.stream_id)
        self._streams[sid] = _CoroStreamPtr(UInt64(Int(ctx_ptr)))

        self._resume_and_handle_error(sid)

    def _on_trailers(mut self, ev: H3Event) raises:
        """Second HEADERS_RECEIVED on an open stream = trailers.
        Push as BodyFrame.trailers (skip pseudo-headers). Resume coroutine."""
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
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_and_handle_error(sid)

    def _on_data(mut self, ev: H3Event) raises:
        """DATA_RECEIVED: push data into RecvBody, resume coroutine.
        No flow-control ACK — QUIC handles FC internally."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_and_handle_error(sid)

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
        self._resume_and_handle_error(sid)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET: push error, resume once, pop BEFORE free."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(UInt32(ev.error_code))
        ctx.recv_body._set_error(StreamError(other=err))
        ctx_ptr.init_pointee_move(ctx^)
        if ctx_ptr[].coro_addr != UInt64(0):
            var coro_p = ctx_ptr[].coro_ptr()
            if coro_p[].can_resume():
                try:
                    coro_p[].resume()
                except:
                    pass
        _ = self._streams.pop(sid)   # pop BEFORE free
        _free_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: broadcast error to all open
        streams, resume each once, pop BEFORE free for each."""
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
            if ctx_ptr[].coro_addr != UInt64(0):
                var coro_p = ctx_ptr[].coro_ptr()
                if coro_p[].can_resume():
                    try:
                        coro_p[].resume()
                    except:
                        pass
            _ = self._streams.pop(sid)   # pop BEFORE free
            _free_stream(ctx_ptr)

    # --- Internal: response drain -------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Drain pending response data from stream contexts into H3Connection.
        Snapshot stream IDs first to avoid mutating dict while iterating."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if ctx.response_ended:
                ctx_ptr.init_pointee_move(ctx^)
                self._maybe_cleanup_stream(sid)
                continue
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
                continue
            # Send response headers
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
            # Drain body frames
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
