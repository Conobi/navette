# src/http/coro_client.mojo
#
# HttpCoroClient — coroutine-based HTTP client adapter (M6c §11).
# Sans-I/O: caller drives byte pump via feed/drain.
# Wraps HttpClient with Alt-Svc integration and content decoding hooks.

from std.collections.optional import Optional
from std.memory import Span

from src.http.alt_svc import Origin, AltSvcCache, AltSvcEntry, parse_alt_svc
from src.http.client import HttpClient
from src.http.session_slot import SessionSlot, SessionSlotPtr, SLOT_H1, SLOT_H2, SLOT_H3
from src.http.session import RequestHandle
from src.http.request import Request, RequestBody
from src.http.response import Response
from src.http.method import Method
from src.http.headers import Headers
from src.http.url import ParsedUrl, parse_url


struct HttpCoroClient(Movable):
    """Coroutine-friendly HTTP client wrapping HttpClient.

    Sans-I/O: caller drives the byte pump externally via feed/drain.
    Adds Alt-Svc caching on top of HttpClient's pool management.

    Usage:
      1. attach_session(origin, slot) — inject a connected session
      2. get/post/request — submit request, get handle
      3. drain(origin) → bytes to send to network
      4. network recv → feed(data, origin)
      5. run_one(origin, handle) — advance until complete
      6. handle.take_response() → Response
    """

    var _client: HttpClient
    var _alt_svc: AltSvcCache

    def __init__(
        out self,
        *,
        max_conns_h1: Int = 6,
        max_conns_mux: Int = 1,
        idle_timeout_ms: UInt64 = UInt64(90_000),
    ):
        self._client = HttpClient.with_config(
            max_conns_h1=max_conns_h1,
            max_conns_mux=max_conns_mux,
            idle_timeout_ms=idle_timeout_ms,
        )
        self._alt_svc = AltSvcCache()

    def __init__(out self, *, deinit take: Self):
        self._client = take._client^
        self._alt_svc = take._alt_svc^

    # --- Session management ---

    def attach_session(mut self, var origin: Origin, var slot: SessionSlot) raises:
        """Inject a connected session into the pool."""
        self._client.attach_session(origin^, slot^)

    # --- Transport API (caller drives I/O) ---

    def feed(mut self, data: Span[UInt8, _], origin: Origin) raises:
        """Feed inbound bytes from network for the given origin."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                slots[0].ptr()[].feed(data)

    def drain(mut self, origin: Origin) raises -> List[UInt8]:
        """Drain outbound bytes to send to network."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            if len(slots) > 0:
                return slots[0].ptr()[].drain()
        return List[UInt8]()

    # --- Request API ---

    def get(mut self, url: String) raises -> RequestHandle:
        """Submit a GET request."""
        return self._client.get(url)

    def post(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        """Submit a POST request."""
        return self._client.post(url, body^)

    def put(mut self, url: String, var body: List[UInt8]) raises -> RequestHandle:
        """Submit a PUT request."""
        return self._client.put(url, body^)

    def delete(mut self, url: String) raises -> RequestHandle:
        """Submit a DELETE request."""
        return self._client.delete(url)

    def head(mut self, url: String) raises -> RequestHandle:
        """Submit a HEAD request."""
        return self._client.head(url)

    def run_one(mut self, var origin: Origin, mut handle: RequestHandle) raises:
        """Advance a request handle after feeding response bytes."""
        self._client.run_one(origin^, handle)

    # --- Alt-Svc integration ---

    def update_alt_svc(mut self, var origin: Origin, resp: Response, now: UInt) raises:
        """Parse Alt-Svc header from response and cache entries."""
        if resp.headers.has("alt-svc"):
            var value = resp.headers.get("alt-svc")
            if len(value) > 0:
                var entries = parse_alt_svc(value)
                self._alt_svc.insert(origin^, entries^, now)

    def lookup_alt_svc(self, origin: Origin, now: UInt) raises -> List[AltSvcEntry]:
        """Check if an upgraded protocol is available for this origin."""
        return self._alt_svc.lookup(origin, now)

    # --- Pool inspection (for testing) ---

    def has_connection(self, origin: Origin) raises -> Bool:
        """Check if a session is pooled for origin."""
        if origin in self._client._pool:
            ref slots = self._client._pool[origin]
            return len(slots) > 0
        return False
