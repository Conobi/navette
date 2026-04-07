# src/h1/server.mojo
#
# ServerConnection: typed wrapper over H1Connection.
# Exposes only the server-side API (no send_request, no next_response).

from std.collections.optional import Optional
from std.memory import Span

from src.http.method import Method
from src.http.status import StatusCode
from src.http.headers import Headers
from src.http.request import Request
from src.http.response import Response
from src.h1.config import ParseConfig
from src.h1.connection import H1Connection


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

    def receive_data(mut self, data: Span[UInt8, _]) raises:
        self._inner.receive_data(data)

    def next_request(mut self) -> Optional[Request]:
        return self._inner.next_request()

    # --- Outbound API (server sends responses) ---

    def send_response(mut self, var response: Response):
        self._inner.send_response(response^)

    def send_informational(mut self, var status: StatusCode, var headers: Headers):
        self._inner.send_informational(status^, headers^)

    def drain(mut self) -> List[UInt8]:
        return self._inner.drain()

    # --- State queries ---

    def should_close(self) -> Bool:
        return self._inner.should_close()

    def is_keep_alive(self) -> Bool:
        return self._inner.is_keep_alive()

    def wants_read(self) -> Bool:
        return self._inner.wants_read()

    def wants_write(self) -> Bool:
        return self._inner.wants_write()
