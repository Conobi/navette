# src/http/alt_svc.mojo
#
# RFC 7838 Alt-Svc header (M2.5b §7.2). Ships parsing, the entry struct,
# and an in-memory AltSvcCache keyed by Origin that M6's HttpClient will
# consult during connection establishment.

from std.collections.dict import Dict, KeyElement


struct Origin(KeyElement):
    """Origin key for the Alt-Svc cache: (scheme, host, port)."""

    var scheme: String   # "https" or "http"
    var host: String
    var port: UInt16

    def __init__(out self, *, scheme: String, host: String, port: UInt16):
        self.scheme = scheme
        self.host = host
        self.port = port

    def __init__(out self, *, other: Self):
        self.scheme = other.scheme.copy()
        self.host = other.host.copy()
        self.port = other.port

    def __init__(out self, *, deinit take: Self):
        self.scheme = take.scheme^
        self.host = take.host^
        self.port = take.port

    def __hash__(self) -> UInt64:
        return hash(self.scheme) ^ hash(self.host) ^ UInt64(self.port)

    def __eq__(self, rhs: Self) -> Bool:
        return (
            self.scheme == rhs.scheme
            and self.host == rhs.host
            and self.port == rhs.port
        )

    def __ne__(self, rhs: Self) -> Bool:
        return not (self == rhs)
