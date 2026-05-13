# src/http/response.mojo
#
# HTTP response (RFC 9110).
# Pure data — no socket, no connection reference.

from .status import StatusCode
from .version import Version
from .headers import Headers
from .body import BodyFrame


struct Response(Movable):
    """HTTP response message.

    Fields:
      status  HTTP status code (e.g., 200, 404).
      reason  Reason phrase (empty is valid; SP always emitted per RFC 9112).
      version HTTP version (defaults to HTTP/1.1).
      headers Header fields (no pseudo-headers).
      body    List of body frames (Data or Trailers).
    """
    var status: StatusCode
    var reason: String
    var version: Version
    var headers: Headers
    var body: List[BodyFrame]

    def __init__(
        out self,
        var status: StatusCode,
        reason: String = "",
        var version: Version = Version.http_1_1(),
        var headers: Headers = Headers(),
        var body: List[BodyFrame] = List[BodyFrame](),
    ):
        """Construct a Response with the given fields."""
        self.status = status^
        self.reason = reason
        self.version = version^
        self.headers = headers^
        self.body = body^

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.status = take.status^
        self.reason = take.reason^
        self.version = take.version^
        self.headers = take.headers^
        self.body = take.body^
