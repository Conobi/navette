# src/h1/client.mojo
#
# ClientConnection: typed wrapper over H1Connection.
# Exposes only the client-side API (no send_response, no next_request).

from std.collections.optional import Optional
from std.memory import Span

from mojo_net.http.method import Method
from mojo_net.http.request import Request
from mojo_net.http.response import Response
from mojo_net.h1.config import ParseConfig
from mojo_net.h1.connection import H1Connection


struct ClientConnection(Movable):
    """HTTP/1.1 client connection. Sends requests, receives responses."""

    var _inner: H1Connection

    def __init__(out self, var config: ParseConfig):
        """Build a fresh client connection in the IDLE phase."""
        self._inner = H1Connection(config^)

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self._inner = take._inner^

    # --- Outbound API (client sends requests) ---

    def send_request(mut self, var request: Request) raises:
        self._inner.send_request(request^)

    def drain(mut self) -> List[UInt8]:
        return self._inner.drain()

    # --- Inbound API (client reads responses) ---

    def receive_data(mut self, data: Span[UInt8, _]) raises:
        self._inner.receive_data(data)

    def next_response(mut self, var request_method: Method) -> Optional[Response]:
        return self._inner.next_response(request_method^)

    # --- State queries ---

    def should_close(self) -> Bool:
        return self._inner.should_close()

    def is_keep_alive(self) -> Bool:
        return self._inner.is_keep_alive()

    def wants_read(self) -> Bool:
        return self._inner.wants_read()

    def wants_write(self) -> Bool:
        return self._inner.wants_write()


# Re-export the Session implementation.
from mojo_net.h1.h1_session import H1Session
