# src/http/request.mojo
#
# HTTP request (RFC 9110).
# Pure data — no socket, no connection reference.

from .method import Method
from .version import Version
from .headers import Headers
from .body import BodyFrame


struct Request(Movable):
    """HTTP request message.

    Fields:
      method  HTTP method (GET, POST, etc.).
      target  Request-target (e.g., "/index.html").
      version HTTP version (defaults to HTTP/1.1).
      headers Header fields (no pseudo-headers).
      body    List of body frames (Data or Trailers).
    """
    var method: Method
    var target: String
    var version: Version
    var headers: Headers
    var body: List[BodyFrame]

    def __init__(
        out self,
        var method: Method,
        target: String,
        var version: Version = Version.http_1_1(),
        var headers: Headers = Headers(),
        var body: List[BodyFrame] = List[BodyFrame](),
    ):
        """Construct a Request with the given fields."""
        self.method = method^
        self.target = target
        self.version = version^
        self.headers = headers^
        self.body = body^

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.method = take.method^
        self.target = take.target^
        self.version = take.version^
        self.headers = take.headers^
        self.body = take.body^
