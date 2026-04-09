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


struct AltSvcEntry(Copyable, Movable):
    """One alternative service advertisement from an Alt-Svc header."""

    var protocol: String       # e.g. "h3", "h2", "h2c", "http/1.1"
    var host: String           # empty = same as origin
    var port: UInt16
    var max_age_secs: UInt     # RFC 7838 §3 — default 24h per RFC
    var persist: Bool          # "persist=1" parameter

    def __init__(
        out self,
        *,
        protocol: String,
        host: String,
        port: UInt16,
        max_age_secs: UInt,
        persist: Bool,
    ):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.max_age_secs = max_age_secs
        self.persist = persist

    def __init__(out self, *, other: Self):
        self.protocol = other.protocol.copy()
        self.host = other.host.copy()
        self.port = other.port
        self.max_age_secs = other.max_age_secs
        self.persist = other.persist

    def __init__(out self, *, deinit take: Self):
        self.protocol = take.protocol^
        self.host = take.host^
        self.port = take.port
        self.max_age_secs = take.max_age_secs
        self.persist = take.persist


# ---------------------------------------------------------------------------
# RFC 7838 §3 default max-age (24 hours).
comptime _DEFAULT_MAX_AGE_SECS = UInt(86400)


def _strip_ws(s: String) -> String:
    """Strip leading and trailing SP (0x20) and TAB (0x09) from s."""
    var bytes = s.as_bytes()
    var n = len(bytes)
    var B_SP  = UInt8(32)
    var B_TAB = UInt8(9)
    var start = 0
    while start < n and (bytes[start] == B_SP or bytes[start] == B_TAB):
        start += 1
    var end = n
    while end > start and (bytes[end - 1] == B_SP or bytes[end - 1] == B_TAB):
        end -= 1
    var result = String()
    var i = start
    while i < end:
        result += chr(Int(bytes[i]))
        i += 1
    return result^


def _split_top_level(s: String, sep: UInt8) -> List[String]:
    """Split s on the byte sep, skipping occurrences inside double-quoted
    segments.  Returns at least one element (the whole string) even when
    sep is absent."""
    var result = List[String]()
    var bytes = s.as_bytes()
    var n = len(bytes)
    var B_QUOTE = UInt8(34)   # '"'
    var in_quotes = False
    var seg_start = 0
    var i = 0
    while i < n:
        var b = bytes[i]
        if b == B_QUOTE:
            in_quotes = not in_quotes
        elif b == sep and not in_quotes:
            var seg = String()
            var j = seg_start
            while j < i:
                seg += chr(Int(bytes[j]))
                j += 1
            result.append(seg^)
            seg_start = i + 1
        i += 1
    # Append the final (or only) segment.
    var seg = String()
    var j = seg_start
    while j < n:
        seg += chr(Int(bytes[j]))
        j += 1
    result.append(seg^)
    return result^


def _parse_one_entry(entry: String) raises -> AltSvcEntry:
    """Parse one Alt-Svc entry: `protocol="[host]:port"[; params...]`.

    Raises on malformed input."""
    var s = _strip_ws(entry)
    var bytes = s.as_bytes()
    var n = len(bytes)
    var B_EQ    = UInt8(61)   # '='
    var B_QUOTE = UInt8(34)   # '"'
    var B_COLON = UInt8(58)   # ':'

    # Locate the first '=' separating protocol from the quoted host:port.
    var eq_pos = -1
    var i = 0
    while i < n:
        if bytes[i] == B_EQ:
            eq_pos = i
            break
        i += 1
    if eq_pos < 0:
        raise Error("parse_alt_svc: missing '=' in entry: " + s)

    # Build protocol string (left side of '=').
    var protocol = String()
    var pi = 0
    while pi < eq_pos:
        protocol += chr(Int(bytes[pi]))
        pi += 1
    protocol = _strip_ws(protocol)

    # Right side must start (after optional whitespace) with '"'.
    var after_eq = eq_pos + 1
    while after_eq < n and (bytes[after_eq] == UInt8(32) or bytes[after_eq] == UInt8(9)):
        after_eq += 1
    if after_eq >= n or bytes[after_eq] != B_QUOTE:
        raise Error("parse_alt_svc: expected '\"' after '=' in: " + s)

    # Scan for the closing '"'.
    var host_port_start = after_eq + 1
    var close_quote = -1
    var ci = host_port_start
    while ci < n:
        if bytes[ci] == B_QUOTE:
            close_quote = ci
            break
        ci += 1
    if close_quote < 0:
        raise Error("parse_alt_svc: unclosed '\"' in entry: " + s)

    # Find the last ':' inside the quoted segment to split host from port.
    var last_colon = -1
    var li = host_port_start
    while li < close_quote:
        if bytes[li] == B_COLON:
            last_colon = li
        li += 1
    if last_colon < 0:
        raise Error("parse_alt_svc: missing ':' in host:port for: " + s)

    # Build host string (may be empty when the colon is the first byte).
    var host = String()
    var hi = host_port_start
    while hi < last_colon:
        host += chr(Int(bytes[hi]))
        hi += 1

    # Build port string and convert to integer.
    var port_str = String()
    var psi = last_colon + 1
    while psi < close_quote:
        port_str += chr(Int(bytes[psi]))
        psi += 1
    if len(port_str) == 0:
        raise Error("parse_alt_svc: empty port in: " + s)
    var port = UInt16(atol(port_str))

    # Defaults for optional parameters.
    var max_age = _DEFAULT_MAX_AGE_SECS
    var persist = False

    # Collect the parameter string (everything after the closing '"').
    var rest = String()
    var ri = close_quote + 1
    while ri < n:
        rest += chr(Int(bytes[ri]))
        ri += 1

    # Split parameters on ';' (never appear inside quotes at this level).
    var params = _split_top_level(rest, UInt8(59))   # ';'
    var pidx = 0
    while pidx < len(params):
        var param = _strip_ws(params[pidx])
        pidx += 1
        if len(param) == 0:
            continue
        var pbytes = param.as_bytes()
        var pn = len(pbytes)
        # Find '=' inside param.
        var peq = -1
        var pei = 0
        while pei < pn:
            if pbytes[pei] == B_EQ:
                peq = pei
                break
            pei += 1
        if peq < 0:
            continue   # token without value; ignore
        # Build param name and value.
        var pname = String()
        var pni = 0
        while pni < peq:
            pname += chr(Int(pbytes[pni]))
            pni += 1
        pname = _strip_ws(pname)
        var pval = String()
        var pvi = peq + 1
        while pvi < pn:
            pval += chr(Int(pbytes[pvi]))
            pvi += 1
        pval = _strip_ws(pval)
        if pname == String("ma"):
            max_age = UInt(atol(pval))
        elif pname == String("persist"):
            persist = atol(pval) != 0

    return AltSvcEntry(
        protocol=protocol^,
        host=host^,
        port=port,
        max_age_secs=max_age,
        persist=persist,
    )


struct AltSvcCache(Movable):
    """In-memory cache of Alt-Svc advertisements, keyed by Origin. Used by
    M6's HttpClient during connection establishment to decide whether to
    upgrade an HTTP/1.1 connection to H2 or H3. Not thread-safe — callers
    that need concurrent access wrap it in a mutex at the M6 layer."""

    var _entries: Dict[Origin, List[AltSvcEntry]]
    var _received_at: Dict[Origin, UInt]   # when insert() was called

    def __init__(out self):
        self._entries = Dict[Origin, List[AltSvcEntry]]()
        self._received_at = Dict[Origin, UInt]()

    def __init__(out self, *, deinit take: Self):
        self._entries = take._entries^
        self._received_at = take._received_at^

    def insert(
        mut self,
        var origin: Origin,
        var entries: List[AltSvcEntry],
        received_at: UInt,
    ):
        """Replace any existing entries for `origin` with the supplied list.
        `received_at` is the wall-clock time (seconds since some epoch the
        caller controls) when the Alt-Svc header was received; lookup uses
        it together with each entry's max_age_secs to compute expiry."""
        self._entries[Origin(other=origin)] = entries^
        self._received_at[origin^] = received_at

    def lookup(self, origin: Origin, now: UInt) raises -> List[AltSvcEntry]:
        """Return all non-expired entries for `origin`. Returns an empty
        list if the origin is unknown or every entry has expired."""
        var out = List[AltSvcEntry]()
        if origin not in self._entries:
            return out^
        var received_at = self._received_at[origin]
        ref entries = self._entries[origin]
        for i in range(len(entries)):
            if received_at + entries[i].max_age_secs > now:
                out.append(AltSvcEntry(other=entries[i]))
        return out^

    def clear(mut self, origin: Origin) raises:
        """Drop all entries for `origin`, regardless of expiry."""
        if origin in self._entries:
            _ = self._entries.pop(Origin(other=origin))
            _ = self._received_at.pop(Origin(other=origin))

    def clear_expired(mut self, now: UInt) raises:
        """Prune origins for which every entry has expired at `now`."""
        var to_drop = List[Origin]()
        for kv in self._entries.items():
            var origin_copy = Origin(other=kv.key)
            var received_at = self._received_at[kv.key]
            var any_live = False
            ref entries = kv.value
            for i in range(len(entries)):
                if received_at + entries[i].max_age_secs > now:
                    any_live = True
                    break
            if not any_live:
                to_drop.append(origin_copy^)
        for j in range(len(to_drop)):
            _ = self._entries.pop(Origin(other=to_drop[j]))
            _ = self._received_at.pop(Origin(other=to_drop[j]))


def parse_alt_svc(value: String) raises -> List[AltSvcEntry]:
    """Parse an Alt-Svc header value into a list of AltSvcEntry records.
    The special value `clear` returns an empty list (RFC 7838 §3).

    Each entry is of the form `alpn="[host]:port"[; ma=N][; persist=1]`.
    The `host` component may be empty (meaning "same as the origin host");
    the port is always required.

    Raises on malformed input: missing `=`, missing quotes, missing port,
    non-integer `ma` / `persist` values."""
    var s = _strip_ws(value)
    if s == String("clear") or len(s) == 0:
        return List[AltSvcEntry]()
    var entry_strs = _split_top_level(s, UInt8(44))   # ','
    var out = List[AltSvcEntry]()
    var idx = 0
    while idx < len(entry_strs):
        var e = _parse_one_entry(entry_strs[idx])
        out.append(e^)
        idx += 1
    return out^
