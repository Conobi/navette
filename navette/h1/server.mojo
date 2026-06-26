# src/h1/server.mojo
#
# ServerConnection: typed wrapper over H1Connection.
# Exposes only the server-side API (no send_request, no next_response).

from std.collections.optional import Optional
from std.memory import Span

from navette.http.method import Method
from navette.http.status import StatusCode
from navette.http.headers import Headers
from navette.http.request import Request
from navette.http.response import Response
from navette.h1.config import ParseConfig
from navette.h1.connection import H1Connection


struct ServerConnection(Movable):
    """HTTP/1.1 server connection. Receives requests, sends responses."""

    var _inner: H1Connection

    def __init__(out self, var config: ParseConfig):
        """Build a fresh server connection in the IDLE phase."""
        self._inner = H1Connection(config^)

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._inner = take._inner^

    # --- Inbound API (server reads requests) ---

    @always_inline
    def receive_data(mut self, data: Span[UInt8, _]) raises:
        self._inner.receive_data(data)

    @always_inline
    def next_request(mut self) -> Optional[Request]:
        return self._inner.next_request()

    # --- Outbound API (server sends responses) ---

    @always_inline
    def send_response(mut self, var response: Response):
        self._inner.send_response(response^)

    @always_inline
    def send_informational(mut self, var status: StatusCode, var headers: Headers):
        self._inner.send_informational(status^, headers^)

    @always_inline
    def drain(mut self) -> List[UInt8]:
        return self._inner.drain()

    @always_inline
    def drain_into(mut self, mut sink: List[UInt8]):
        self._inner.drain_into(sink)

    # --- State queries ---

    @always_inline
    def should_close(self) -> Bool:
        return self._inner.should_close()

    @always_inline
    def is_keep_alive(self) -> Bool:
        return self._inner.is_keep_alive()

    @always_inline
    def wants_read(self) -> Bool:
        return self._inner.wants_read()

    @always_inline
    def wants_write(self) -> Bool:
        return self._inner.wants_write()


# Re-export the runtime adapter so callers can `from navette.h1.server import H1HandlerServer`.
from navette.h1.handler_server import H1HandlerServer
