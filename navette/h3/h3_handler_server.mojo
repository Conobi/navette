# src/h3/h3_handler_server.mojo
#
# H3HandlerServer[H: StreamHandler] — server adapter.
# Drives a StreamHandler from an H3Connection. Sans-I/O.
# Mirrors src/h2/h2_handler_server.mojo patterns.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.quic.connection import QuicConnection
from navette.quic.path_validator import PathKey
from navette.quic.profile import AcceptProfile, monotonic_us, PROFILE_ACCEPT
from navette.h3.connection import H3Connection, H3Event
from navette.h3.early_data_filter_dispatch import (
    apply_early_data_filter, send_425_response, stream_is_zero_rtt,
)
from navette.h3.qpack import QpackHeaderField
from navette.http.handler import (
    StreamHandler,
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
    ALPN_H3,
)
from navette.http.request import Request, RequestBody
from navette.http.headers import Headers
from navette.http.method import Method
from navette.http.version import Version
from navette.http.body import BodyFrame
from navette.tls.early_data_filter import (
    EarlyDataPredicateFn,
    IdempotentOnlyFilter,
)
from navette.util.ptrbox import PtrBox


# ---------------------------------------------------------------------------
# _H3StreamCtx — per-stream context (heap-allocated, Movable)
# ---------------------------------------------------------------------------


struct _H3StreamCtx(Movable):
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var detached:       Bool
    var request_ended:  Bool
    var response_ended: Bool
    var headers_sent:   Bool

    def __init__(out self):
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.detached = False
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False

    def __init__(out self, *, deinit take: Self):
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.detached = take.detached
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent


# ---------------------------------------------------------------------------
# H3HandlerServer
# ---------------------------------------------------------------------------


struct H3HandlerServer[H: StreamHandler](Movable):
    """Drive a StreamHandler from an H3Connection. Sans-I/O."""

    var _h3:      H3Connection
    var handler:  Self.H
    var _streams: Dict[Int, PtrBox[_H3StreamCtx]]
    var profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]]
    # Optional pointer to the RFC 8470 idempotent-only filter owned by
    # the `QuicServerConfig` that birthed this connection. Populated
    # only when 0-RTT is enabled in the config (cycle 3 plumbing
    # mirroring cycle 2's `_early_data_store_ptr`). When None, the
    # filter dispatch helper takes the fail-closed branch for any
    # request that arrives over 0-RTT (defensive: a 0-RTT stream with
    # no filter wired is a config-invariant violation).
    var _early_data_filter_ptr: Optional[
        UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
    ]
    var _early_data_predicate_fn: Optional[EarlyDataPredicateFn]
    """User-supplied 0-RTT predicate fn, propagated from
    `QuicServerConfig._early_data_predicate_fn` via `H3UdpServer`'s
    per-connection construction. Populated only when the policy is
    Predicate. The dispatch helper consults this field in preference
    to `_early_data_filter_ptr` per the truth-table for the predicate
    variant of the 0-RTT policy."""

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        var handler: Self.H,
        profile_ptr: Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]] = None,
        early_data_filter_ptr: Optional[
            UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
        ] = None,
        predicate_fn: Optional[EarlyDataPredicateFn] = None,
    ) raises:
        self._h3 = H3Connection.server(quic^)
        self.handler = handler^
        self._streams = Dict[Int, PtrBox[_H3StreamCtx]]()
        self.profile_ptr = profile_ptr
        # Shape B threading: H3Connection.server/.client have ~15 call sites
        # in src/h3/ and tests/; we set profile_ptr post-construction here
        # rather than threading it through 15 call sites.
        self._h3.profile_ptr = profile_ptr
        self._early_data_filter_ptr = early_data_filter_ptr
        self._early_data_predicate_fn = predicate_fn

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self.handler = take.handler^
        self._streams = take._streams^
        self.profile_ptr = take.profile_ptr
        self._early_data_filter_ptr = take._early_data_filter_ptr
        self._early_data_predicate_fn = take._early_data_predicate_fn

    def __del__(deinit self):
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var p = self._streams[keys[i]].ptr()
                p.destroy_pointee()
                p.free()
            except:
                pass

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)

    def feed_datagram_from_buffer(
        mut self,
        buf: UnsafePointer[UInt8, MutAnyOrigin],
        buf_len: Int,
        now: UInt64,
    ) raises:
        """Feed one inbound QUIC datagram from a mutable buffer (zero-copy)."""
        self._h3.feed_datagram_from_buffer(buf, buf_len, now)

        # Bracket _dispatch_h3_events
        var t_dispatch_start: UInt64 = 0
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                t_dispatch_start = monotonic_us()
        self._dispatch_h3_events(now)
        comptime if PROFILE_ACCEPT:
            if self.profile_ptr is not None:
                self.profile_ptr.value()[].record_h3_dispatch(monotonic_us() - t_dispatch_start)

        # Bracket _drain_responses (only when established)
        if self._h3.is_established():
            var t_drain_resp_start: UInt64 = 0
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    t_drain_resp_start = monotonic_us()
            self._drain_responses(now)
            comptime if PROFILE_ACCEPT:
                if self.profile_ptr is not None:
                    self.profile_ptr.value()[].record_h3_drain_resp(monotonic_us() - t_drain_resp_start)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        return self._h3.drain_datagrams(now)

    def should_close(self) -> Bool:
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Path-validation pass-through (RFC 9000 §8 + §9) ---------------------

    def on_ingress_from(
        mut self, var from_addr: PathKey, datagram_len: Int, now: UInt64
    ) raises:
        """Forward per-datagram path-change + anti-amp credit to the H3 layer."""
        self._h3.on_ingress_from(from_addr^, datagram_len, now)

    def set_current_recv_addr(mut self, var addr: PathKey):
        """Stamp the per-receive source-addr cursor on the QUIC layer."""
        self._h3.set_current_recv_addr(addr^)

    def bootstrap_peer_addr(mut self, var addr: PathKey):
        """Seed `peer_addr` on a freshly-accepted connection."""
        self._h3.bootstrap_peer_addr(addr^)

    def can_send_to(self, target: PathKey, n_bytes: Int) -> Bool:
        """Anti-amp gate (RFC 9000 §8.1) for outbound bytes to `target`."""
        return self._h3.can_send_to(target, n_bytes)

    def record_send_to(mut self, target: PathKey, n_bytes: Int):
        """Credit `n_bytes` to the per-path bytes_sent counter."""
        self._h3.record_send_to(target, n_bytes)

    def peer_addr_copy(self) -> PathKey:
        """Return a copy of the currently-validated peer 4-tuple."""
        return self._h3.peer_addr_copy()

    # --- Internal: event dispatch --------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                self._on_request(ev, now)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)

    def _on_request(mut self, ev: H3Event, now: UInt64) raises:
        """Parse pseudo-headers from QPACK fields, build Request, invoke handler."""
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

        # RFC 8470 0-RTT HTTP filter dispatch. On reject (0-RTT request
        # whose method is non-idempotent OR fail-closed misconfig),
        # synthesise a 425 Too Early and skip the handler. On accept,
        # the helper has already injected `Early-Data: 1` into
        # req_headers.
        var stream_is_zr = stream_is_zero_rtt(self._h3._quic, ev.stream_id)
        var outcome = apply_early_data_filter(
            method_str,
            path_str,
            stream_is_zr,
            self._early_data_filter_ptr,
            self._early_data_predicate_fn,
            req_headers,
            self.profile_ptr,
        )
        if outcome.should_send_425():
            send_425_response(ev.stream_id, self._h3)
            return

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var body = RecvBody()
        var resp = ResponseWriter()

        try:
            self.handler.on_request(req^, body, resp, Capabilities.for_h3(is_early_data=stream_is_zr))
        except:
            pass

        var detached = body._state == 3

        var ctx_ptr = _heap_alloc[_H3StreamCtx](1).as_any_origin()
        var ctx = _H3StreamCtx()
        ctx.recv_body = body^
        ctx.resp_writer = resp^
        ctx.detached = detached
        ctx_ptr.init_pointee_move(ctx^)
        self._streams[Int(ev.stream_id)] = PtrBox[_H3StreamCtx](ctx_ptr)

    def _on_data(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        if not ctx.detached:
            try:
                self.handler.on_body_available(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        if ctx.request_ended:
            ctx_ptr.init_pointee_move(ctx^)
            return
        ctx.request_ended = True
        ctx.recv_body._set_end()
        if not ctx.detached:
            try:
                self.handler.on_request_end(ctx.recv_body, ctx.resp_writer)
            except:
                pass
        ctx_ptr.init_pointee_move(ctx^)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        var sid = Int(ev.stream_id)
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(UInt32(ev.error_code))
        self.handler.on_reset(err)
        _ = self._streams.pop(sid)
        ctx_ptr.free()

    # --- Internal: response drain --------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """For each open stream: send response headers then body frames."""
        var sids = List[Int]()
        for key in self._streams.keys():
            sids.append(key)
        for i in range(len(sids)):
            var sid = sids[i]
            if sid not in self._streams:
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if ctx.response_ended:
                ctx_ptr.init_pointee_move(ctx^)
                self._maybe_cleanup(sid)
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
                # Build QPACK fields: :status first, then headers
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
            self._maybe_cleanup(sid)

    def _maybe_cleanup(mut self, sid: Int) raises:
        """Free stream context if both sides are done."""
        if sid not in self._streams:
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(sid)
            ctx_ptr.destroy_pointee()
            ctx_ptr.free()
