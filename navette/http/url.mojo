# src/http/url.mojo
#
# Minimal URL parser for HttpClient (M6a §7).
# Extracts scheme, host, port, path from URLs.

from navette.http.alt_svc import Origin


struct ParsedUrl(Movable):
    var scheme: String
    var host: String
    var port: UInt16
    var path: String

    def __init__(out self, *, scheme: String, host: String, port: UInt16, path: String):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path

    def __init__(out self, *, deinit take: Self):
        self.scheme = take.scheme^
        self.host = take.host^
        self.port = take.port
        self.path = take.path^

    def to_origin(self) -> Origin:
        return Origin(scheme=self.scheme, host=self.host, port=self.port)


def parse_url(url: String) raises -> ParsedUrl:
    """Parse scheme://[host][:port][/path] into components.

    Path includes query and fragment raw. Raises on missing scheme."""
    var bytes = url.as_bytes()
    var n = len(bytes)

    # Find "://"
    var scheme_end = -1
    var i = 0
    while i < n - 2:
        if bytes[i] == UInt8(58) and bytes[i + 1] == UInt8(47) and bytes[i + 2] == UInt8(47):
            scheme_end = i
            break
        i += 1
    if scheme_end < 0:
        raise Error("parse_url: missing '://' in URL: " + url)

    # Extract scheme
    var scheme = String()
    i = 0
    while i < scheme_end:
        scheme += chr(Int(bytes[i]))
        i += 1

    # After "://" starts the authority
    var auth_start = scheme_end + 3
    if auth_start >= n:
        raise Error("parse_url: empty authority in URL: " + url)

    # Find end of authority (first '/' after auth_start, or end)
    var path_start = n  # no path means we use "/"
    i = auth_start

    # Handle IPv6 bracket — skip past ']' before looking for '/'
    if i < n and bytes[i] == UInt8(91):  # '['
        while i < n and bytes[i] != UInt8(93):  # ']'
            i += 1
        if i < n:
            i += 1  # skip ']'

    while i < n:
        if bytes[i] == UInt8(47):  # '/'
            path_start = i
            break
        i += 1

    # Extract authority string
    var authority = String()
    i = auth_start
    while i < path_start:
        authority += chr(Int(bytes[i]))
        i += 1

    # Extract path (everything from first '/' onward)
    var path: String
    if path_start < n:
        path = String()
        i = path_start
        while i < n:
            path += chr(Int(bytes[i]))
            i += 1
    else:
        path = String("/")

    # Parse authority into host:port
    # IPv6: [host]:port
    var host: String
    var port: UInt16
    var auth_bytes = authority.as_bytes()
    var an = len(auth_bytes)

    if an > 0 and auth_bytes[0] == UInt8(91):  # IPv6
        # Find closing ']'
        var bracket_end = -1
        var ai = 1
        while ai < an:
            if auth_bytes[ai] == UInt8(93):
                bracket_end = ai
                break
            ai += 1
        if bracket_end < 0:
            raise Error("parse_url: unclosed '[' in IPv6 address")
        # Extract host (between brackets)
        host = String()
        ai = 1
        while ai < bracket_end:
            host += chr(Int(auth_bytes[ai]))
            ai += 1
        # Check for :port after ']'
        if bracket_end + 1 < an and auth_bytes[bracket_end + 1] == UInt8(58):
            var port_str = String()
            ai = bracket_end + 2
            while ai < an:
                port_str += chr(Int(auth_bytes[ai]))
                ai += 1
            port = UInt16(atol(port_str))
        else:
            port = _default_port(scheme)
    else:
        # Regular host — find last ':' for port
        var last_colon = -1
        var ai = 0
        while ai < an:
            if auth_bytes[ai] == UInt8(58):
                last_colon = ai
            ai += 1
        if last_colon >= 0:
            host = String()
            ai = 0
            while ai < last_colon:
                host += chr(Int(auth_bytes[ai]))
                ai += 1
            var port_str = String()
            ai = last_colon + 1
            while ai < an:
                port_str += chr(Int(auth_bytes[ai]))
                ai += 1
            if len(port_str) > 0:
                port = UInt16(atol(port_str))
            else:
                port = _default_port(scheme)
        else:
            host = authority
            port = _default_port(scheme)

    return ParsedUrl(scheme=scheme^, host=host^, port=port, path=path^)


def _default_port(scheme: String) -> UInt16:
    if scheme == "https":
        return UInt16(443)
    return UInt16(80)
