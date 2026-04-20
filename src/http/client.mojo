# src/http/client.mojo
#
# HttpClient — sans-I/O unified HTTP client (M6a §6).

from std.collections import Dict
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.http.alt_svc import Origin
from src.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1, SLOT_H2, SLOT_H3
from src.http.session import RequestHandle
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.method import Method
from src.http.headers import Headers
from src.http.url import ParsedUrl, parse_url


def _is_redirect(status_code: UInt16) -> Bool:
    """Check if a status code is a redirect (301/302/307/308)."""
    return (
        status_code == UInt16(301) or status_code == UInt16(302)
        or status_code == UInt16(307) or status_code == UInt16(308)
    )


def _is_idempotent(method: Method) -> Bool:
    """Check if a method is idempotent (safe to retry)."""
    var m = String(method)
    return m == "GET" or m == "HEAD" or m == "OPTIONS" or m == "PUT" or m == "DELETE"


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


struct HttpClient(Movable):
    """Sans-I/O unified HTTP client with connection pooling."""

    var _pool: Dict[Origin, List[SessionSlotPtr]]
    var _handle_slot: Dict[Int, Int]  # handle_id → slot addr (for run_one routing)
    var _max_conns_h1: Int
    var _max_conns_mux: Int
    var _idle_timeout_ms: UInt64
    var _max_redirects: Int
    var _retry_idempotent: Bool

    def __init__(
        out self,
        *,
        max_conns_h1: Int = 6,
        max_conns_mux: Int = 1,
        idle_timeout_ms: UInt64 = UInt64(90_000),
        max_redirects: Int = 10,
        retry_idempotent: Bool = True,
    ):
        self._pool = Dict[Origin, List[SessionSlotPtr]]()
        self._handle_slot = Dict[Int, Int]()
        self._max_conns_h1 = max_conns_h1
        self._max_conns_mux = max_conns_mux
        self._idle_timeout_ms = idle_timeout_ms
        self._max_redirects = max_redirects
        self._retry_idempotent = retry_idempotent

    def __init__(out self, *, deinit take: Self):
        self._pool = take._pool^
        self._handle_slot = take._handle_slot^
        self._max_conns_h1 = take._max_conns_h1
        self._max_conns_mux = take._max_conns_mux
        self._idle_timeout_ms = take._idle_timeout_ms
        self._max_redirects = take._max_redirects
        self._retry_idempotent = take._retry_idempotent

    fn __del__(deinit self):
        """Free all heap-allocated session slots."""
        for kv in self._pool.items():
            ref slots = kv.value
            for i in range(len(slots)):
                var p = slots[i].ptr()
                p.destroy_pointee()
                p.free()

    @staticmethod
    def default() -> Self:
        return Self()

    @staticmethod
    def with_config(
        max_conns_h1: Int = 6,
        max_conns_mux: Int = 1,
        idle_timeout_ms: UInt64 = UInt64(90_000),
        max_redirects: Int = 10,
        retry_idempotent: Bool = True,
    ) -> Self:
        return Self(
            max_conns_h1=max_conns_h1,
            max_conns_mux=max_conns_mux,
            idle_timeout_ms=idle_timeout_ms,
            max_redirects=max_redirects,
            retry_idempotent=retry_idempotent,
        )

    # --- Pool management ---

    def attach_session(mut self, var origin: Origin, var slot: SessionSlot) raises:
        """Insert a session. Raises if per-host limit exceeded."""
        var max_conns = self._max_conns_h1
        if slot.kind == SLOT_H2 or slot.kind == SLOT_H3:
            max_conns = self._max_conns_mux

        if origin in self._pool:
            ref existing = self._pool[origin]
            if len(existing) >= max_conns:
                raise Error("HttpClient: max connections reached for origin")

        var ptr = _heap_alloc[SessionSlot](1).as_any_origin()
        ptr.init_pointee_move(slot^)
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
            origins.append(Origin(other=kv.key))
        for oi in range(len(origins)):
            try:
                ref slots = self._pool[origins[oi]]
                var keep = List[SessionSlotPtr]()
                for i in range(len(slots)):
                    var p = slots[i].ptr()
                    if p[].is_idle() and (now - p[].idle_since) > self._idle_timeout_ms:
                        p.destroy_pointee()
                        p.free()
                    else:
                        keep.append(SessionSlotPtr(other=slots[i]))
                self._pool[Origin(other=origins[oi])] = keep^
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
        """Submit request to a pooled session for origin.
        Prefers idle slots; for H1 (non-multiplexed) avoids active slots."""
        if origin not in self._pool:
            raise Error("HttpClient: no available connection for origin")
        ref slots = self._pool[origin^]
        if len(slots) == 0:
            raise Error("HttpClient: no available connection for origin")
        # Prefer an idle slot (important for H1 which can't multiplex)
        for i in range(len(slots)):
            if slots[i].ptr()[].is_idle():
                slots[i].ptr()[].mark_active()
                var handle = slots[i].ptr()[].submit(req^)
                self._handle_slot[Int(handle.id())] = Int(slots[i].addr)
                return handle^
        # No idle slot — use first slot (H2/H3 can multiplex; H1 will raise
        # internally if it already has an in-flight request)
        var p = slots[0].ptr()
        var handle = p[].submit(req^)
        self._handle_slot[Int(handle.id())] = Int(slots[0].addr)
        return handle^

    def run_one(mut self, var origin: Origin, mut handle: RequestHandle) raises:
        """Advance a handle on the session that owns it.
        Auto-marks the slot idle when H1 response completes."""
        var hid = Int(handle.id())
        # Route to the correct slot via handle mapping
        if hid in self._handle_slot:
            var addr = self._handle_slot[hid]
            var p = UnsafePointer[SessionSlot, MutAnyOrigin](
                unsafe_from_address=addr
            )
            p[].run_one(handle)
            # Auto mark idle when H1 response completes (H1 is not multiplexed)
            if handle.is_complete() and p[].capabilities().alpn == 0:
                p[].mark_idle(UInt64(1))
            if handle.is_complete():
                _ = self._handle_slot.pop(hid)
            return
        # Fallback: use first slot (legacy path)
        if origin not in self._pool:
            raise Error("HttpClient: no connection for origin")
        ref slots = self._pool[origin^]
        if len(slots) == 0:
            raise Error("HttpClient: no connection for origin")
        var p = slots[0].ptr()
        p[].run_one(handle)

    # --- Convenience API ---

    def _build_request(
        self, var method: Method, var parsed: ParsedUrl, var body_bytes: List[UInt8]
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
            new_method = Method(other=original.method)
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
        var hdrs = Headers(other=original.headers)
        hdrs.remove("authorization")
        return Request(method=new_method^, target=target, headers=hdrs^, body=new_body^)

    def get(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.get(), parsed^, List[UInt8]())
        return self.submit(origin^, req^)

    def post(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.post(), parsed^, body^)
        return self.submit(origin^, req^)

    def put(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.put(), parsed^, body^)
        return self.submit(origin^, req^)

    def delete(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.delete(), parsed^, List[UInt8]())
        return self.submit(origin^, req^)

    def head(mut self, url: String) raises -> RequestHandle:
        var parsed = parse_url(url)
        var origin = parsed.to_origin()
        var req = self._build_request(Method.head(), parsed^, List[UInt8]())
        return self.submit(origin^, req^)
