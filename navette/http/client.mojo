# src/http/client.mojo
#
# HttpClient — sans-I/O unified HTTP client (M6a §6).

from std.collections import Dict
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.http.alt_svc import Origin
from navette.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1, SLOT_H2, SLOT_H3
from navette.http.session import RequestHandle
from navette.http.body import BodyFrame
from navette.http.handler import StreamError
from navette.http.request import Request, RequestBody
from navette.http.response import Response
from navette.http.method import Method
from navette.http.headers import Headers
from navette.http.url import ParsedUrl, parse_url


def _is_redirect(status_code: UInt16) -> Bool:
    """Check if a status code is a redirect (301/302/307/308)."""
    return (
        status_code == UInt16(301) or status_code == UInt16(302)
        or status_code == UInt16(307) or status_code == UInt16(308)
    )


def _is_idempotent(method: Method) -> Bool:
    """Check if a method is idempotent (safe to retry).

    Delegates to Method.is_idempotent() which covers GET, HEAD,
    OPTIONS, TRACE, QUERY, PUT, DELETE per RFC 9110 + RFC 10008.
    """
    return method.is_idempotent()


def _str_starts_with(s: String, prefix: String) -> Bool:
    """Check if string starts with prefix (manual implementation)."""
    var s_bytes = s.as_bytes()
    var p_bytes = prefix.as_bytes()
    if len(p_bytes) > len(s_bytes):
        return False
    for i in range(len(p_bytes)):
        if s_bytes[i] != p_bytes[i]:
            return False
    return True


@fieldwise_init
struct _Route(Copyable, Movable):
    """Where a client handle lives: its slot and the session's own handle id."""

    var slot_addr: Int
    var session_id: UInt64


struct HttpClient(Movable):
    """Sans-I/O unified HTTP client with connection pooling.

    Handles carry client-wide ids, never reused, routed to (slot, session
    handle id); sessions number their handles independently. Each origin
    holds at most one live session: closed ones are evicted on `submit`
    and `attach_session`, and attaching behind a live one raises.
    """

    var _pool: Dict[Origin, List[SessionSlotPtr]]
    var _routes: Dict[Int, _Route]
    var _next_id: UInt64
    var _idle_timeout_ms: UInt64
    var _max_redirects: Int
    var _retry_idempotent: Bool

    def __init__(
        out self,
        *,
        idle_timeout_ms: UInt64 = UInt64(90_000),
        max_redirects: Int = 10,
        retry_idempotent: Bool = True,
    ):
        self._pool = Dict[Origin, List[SessionSlotPtr]]()
        self._routes = Dict[Int, _Route]()
        self._next_id = UInt64(0)
        self._idle_timeout_ms = idle_timeout_ms
        self._max_redirects = max_redirects
        self._retry_idempotent = retry_idempotent

    def __deinit__(deinit self):
        """Free all heap-allocated session slots."""
        for kv in self._pool.items():
            ref slots = kv.value
            for ref slot in slots:
                var p = slot.ptr()
                p.unsafe_deinit_pointee()
                p.unsafe_free()

    @staticmethod
    def default() -> Self:
        return Self()

    @staticmethod
    def with_config(
        idle_timeout_ms: UInt64 = UInt64(90_000),
        max_redirects: Int = 10,
        retry_idempotent: Bool = True,
    ) -> Self:
        return Self(
            idle_timeout_ms=idle_timeout_ms,
            max_redirects=max_redirects,
            retry_idempotent=retry_idempotent,
        )

    # --- Pool management ---

    def attach_session(mut self, var origin: Origin, var slot: SessionSlot) raises:
        """Insert the origin's session after evicting closed ones.

        Raises if the origin still has a live session: one slot per origin,
        since `submit` and the transport API only reach the first.
        """
        self._evict_closed(origin)
        if origin in self._pool and len(self._pool[origin]) > 0:
            raise Error("HttpClient: origin already has a live connection; detach it first")

        var ptr = _heap_alloc[SessionSlot](1)
        ptr.unsafe_write(slot^)
        var slot_ptr = SessionSlotPtr(UInt64(Int(ptr)))
        if origin not in self._pool:
            var slots = List[SessionSlotPtr]()
            slots.append(slot_ptr^)
            self._pool[origin^] = slots^
        else:
            self._pool[origin^].append(slot_ptr^)

    def close_idle(mut self, now: UInt64):
        """Evict sessions idle longer than timeout."""
        var origins = List[Origin]()
        for kv in self._pool.items():
            origins.append(Origin(copy=kv.key))
        for ref origin in origins:
            try:
                ref slots = self._pool[origin]
                var keep = List[SessionSlotPtr]()
                # Routes are dropped after the walk: `_drop_routes` mutates
                # `self` while `slots` still borrows `self._pool`.
                var dropped = List[Int]()
                for ref slot in slots:
                    var p = slot.ptr()
                    if p[].is_idle() and (now - p[].idle_since) > self._idle_timeout_ms:
                        dropped.append(Int(slot.addr))
                        p.unsafe_deinit_pointee()
                        p.unsafe_free()
                    else:
                        keep.append(SessionSlotPtr(copy=slot))
                self._pool[Origin(copy=origin)] = keep^
                for addr in dropped:
                    self._drop_routes(addr)
            except:
                pass

    def _drop_routes(mut self, slot_addr: Int):
        """Forget every handle routed to a slot leaving the pool.

        Those handles error with `connection_closed` on their next `run_one`
        (an unknown id is never reused, so no tombstone is kept); poll them
        before evicting or detaching to keep a response already received.
        """
        var hids = List[Int]()
        for kv in self._routes.items():
            if kv.value.slot_addr == slot_addr:
                hids.append(kv.key)
        for hid in hids:
            try:
                _ = self._routes.pop(hid)
            except:
                pass

    def _evict_closed(mut self, origin: Origin):
        """Free `origin`'s closed slots so the caller attaches a fresh one."""
        try:
            ref slots = self._pool[origin]
            var keep = List[SessionSlotPtr]()
            # Routes are dropped after the walk: `_drop_routes` mutates
            # `self` while `slots` still borrows `self._pool`.
            var dropped = List[Int]()
            for ref slot in slots:
                var p = slot.ptr()
                if not p[].is_closed():
                    keep.append(SessionSlotPtr(copy=slot))
                    continue
                dropped.append(Int(slot.addr))
                p.unsafe_deinit_pointee()
                p.unsafe_free()
            self._pool[Origin(copy=origin)] = keep^
            for addr in dropped:
                self._drop_routes(addr)
        except:
            pass

    def close_all(deinit self):
        """Consume client, freeing all pooled sessions."""
        # __del__ handles the actual cleanup
        pass

    # --- Low-level API ---
    # NOTE: submit/run_one take an Origin parameter because Request.target is
    # only a path (not a full URL). Convenience methods handle URL→Origin
    # resolution internally. M6c's HttpCoroClient will also resolve internally.

    def submit(mut self, var origin: Origin, var req: Request) raises -> RequestHandle:
        """Submit request to the origin's first pooled slot, after evicting
        closed ones.

        Only the first slot is used because the transport API
        (`HttpCoroClient.feed`/`drain`/...) only reaches the first slot; a
        busy H1 slot raises before writing anything.
        """
        self._evict_closed(origin)
        if origin not in self._pool:
            raise Error("HttpClient: no available connection for origin")
        ref slots = self._pool[origin^]
        if len(slots) == 0:
            raise Error("HttpClient: no available connection for origin")
        var p = slots[0].ptr()
        var handle = p[].submit(req^)
        self._next_id += UInt64(1)
        self._routes[Int(self._next_id)] = _Route(
            slot_addr=Int(slots[0].addr), session_id=handle.id()
        )
        handle._id = self._next_id
        return handle^

    def feed_body(mut self, handle: RequestHandle, var frame: BodyFrame) raises:
        """Send a frame of `handle`'s streamed request body.

        Raises if this client no longer routes `handle` (finished, or its
        slot was evicted or detached): there is no request left to feed. An
        H2 stream whose response completes before its body ends is left
        half-closed (no RST_STREAM is sent).
        """
        var route = self._routes.find(Int(handle.id()))
        if not route:
            raise Error("HttpClient.feed_body: unknown or finished handle")
        var p = Pointer[SessionSlot, MutUntrackedOrigin](
            unsafe_from_address=route.value().slot_addr
        )
        p[].feed_body(route.value().session_id, frame^)

    def run_one(mut self, var origin: Origin, mut handle: RequestHandle) raises:
        """Advance a handle on the slot that owns it; a no-op once complete.

        `handle` must come from this client's `submit` (ids are only unique
        per client). One whose slot was evicted or detached errors with
        `connection_closed`.
        Marks an H1 slot idle when its response completes.
        """
        if handle.is_complete():
            return
        var client_id = handle.id()
        var route = self._routes.find(Int(client_id))
        if not route:
            handle._set_error(StreamError.connection_closed())
            return
        var p = Pointer[SessionSlot, MutUntrackedOrigin](
            unsafe_from_address=route.value().slot_addr
        )
        handle._id = route.value().session_id
        try:
            p[].run_one(handle)
        except e:
            handle._id = client_id
            raise e^
        handle._id = client_id
        if handle.is_complete():
            if p[].capabilities().alpn == 0:
                p[].mark_idle(UInt64(1))
            _ = self._routes.pop(Int(client_id))

    # --- Convenience API ---

    def _build_request(
        self, var method: Method, var parsed: ParsedUrl, var body_bytes: List[Byte]
    ) -> Request:
        """Build a Request from parsed URL components + optional body."""
        var hdrs = Headers()
        hdrs.add("Host", parsed.host)
        var body: RequestBody
        if len(body_bytes) > 0:
            body = RequestBody.buffered(body_bytes^)
        else:
            body = RequestBody.empty()
        return Request(
            method=method^,
            target=parsed.path,
            headers=hdrs^,
            body=body^,
        )

    def build_redirect_request(self, var original: Request, status_code: UInt16, location: String) raises -> Request:
        """Build a follow-up request for a redirect response.

        301/302: rewrite to GET, drop body.
        307/308: preserve method + body (raises if stream body).
        Drops Authorization header (cross-origin safety)."""
        var code = Int(status_code)
        var new_method: Method
        var new_body: RequestBody
        if code == 301 or code == 302:
            new_method = Method.get()
            new_body = RequestBody.empty()
        else:
            # 307/308: preserve method + body
            if original.body.is_stream():
                raise Error("HttpClient: cannot follow 307/308 redirect with stream body")
            new_method = Method(copy=original.method)
            if original.body.is_buffered():
                new_body = original.body._clone_buffered()
            else:
                new_body = RequestBody.empty()
        # Parse location (may be relative path or absolute URL)
        var target: String
        if _str_starts_with(location, "http://") or _str_starts_with(location, "https://"):
            var parsed = parse_url(location)
            target = parsed.path
        else:
            target = location
        # Build new headers — drop Authorization for security
        var hdrs = Headers(copy=original.headers)
        hdrs.remove("authorization")
        return Request(method=new_method^, target=target, headers=hdrs^, body=new_body^)

    def get(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.get(), parsed^, List[Byte]())
        return self.submit(origin^, req^)

    def post(mut self, url: String, var body: List[Byte]) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.post(), parsed^, body^)
        return self.submit(origin^, req^)

    def put(mut self, url: String, var body: List[Byte]) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.put(), parsed^, body^)
        return self.submit(origin^, req^)

    def delete(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.delete(), parsed^, List[Byte]())
        return self.submit(origin^, req^)

    def head(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.head(), parsed^, List[Byte]())
        return self.submit(origin^, req^)

    def query(mut self, url: String, var body: List[Byte]) raises -> RequestHandle:
        """Submit a QUERY request (RFC 10008).

        QUERY is a safe, idempotent, body-carrying method. The body
        typically carries query parameters (e.g. JSON); Content-Type
        is the caller's responsibility per RFC 10008.
        """
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.query(), parsed^, body^)
        return self.submit(origin^, req^)
