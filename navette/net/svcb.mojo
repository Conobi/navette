"""svcb.mojo — DNS HTTPS/SVCB (RFC 9460 type-65) discovery over UDP/53.

`resolve_https_rr(host, *, timeout_ms)` queries the system resolver for the type-65
HTTPS resource record, parses the `alpn` SvcParam, and returns the preferred ServiceMode
record as an `HttpsRecord` — or `None` on *any* failure (SVCB-optional, RFC 9460 §3:
no record, NXDOMAIN/SERVFAIL, timeout, truncation we can't resolve, or a malformed
record all fall through to `None`, never a raise to the caller). EDNS0 (a 1232-byte UDP
buffer, DNS Flag Day 2020) plus a TCP/53 fallback handle truncation. A random 16-bit
transaction id (`getrandom`), a connected-socket ephemeral source port, and strict answer
validation provide transport-level anti-spoof resistance. The record is a hint, not a
trust anchor (RFC 9460 §9.5) — the eventual QUIC/TLS handshake authenticates the endpoint.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.collections.optional import Optional
from std.io.file import FileHandle

from navette.util.owned_alloc import Owned
from navette.net.resolver import ResolvedAddr, resolve_host
from navette.runtime.socket_helpers import udp_connect, tcp_connect

from boucle.net.ip import IpAddrV4


# ── wire constants ─────────────────────────────────────────────────────────
comptime _QTYPE_HTTPS: Int = 65
comptime _QCLASS_IN: Int = 1
comptime _EDNS_UDP_SIZE: Int = 1232          # 0x04D0, DNS Flag Day 2020
comptime _B_DOT: UInt8 = 46                  # '.'
comptime _DEFAULT_NS: String = "127.0.0.53"  # systemd-resolved stub
comptime _NAME_MAX: Int = 255                # RFC 1035 §3.1
comptime _MAX_TCP_FRAME: Int = 65535         # cap a dribbling TCP length (DoS guard)

# clock / socket-option FFI constants
comptime _CLOCK_MONOTONIC: Int32 = 1
comptime _SOL_SOCKET: Int32 = 1
comptime _SO_RCVTIMEO: Int32 = 20
comptime _MSG_NOSIGNAL: Int32 = 0x4000

# datagram classification (anti-spoof recv loop)
comptime _ANS_INVALID: Int = 0     # spoof/stray/garbled → discard, keep reading
comptime _ANS_NONE: Int = 1        # valid answer, no usable record → None
comptime _ANS_RECORD: Int = 2      # valid answer carrying a ServiceMode record
comptime _ANS_TRUNCATED: Int = 3   # valid header with TC=1 → TCP/53 fallback


struct HttpsRecord(Copyable, Movable):
    """The projection of one ServiceMode HTTPS RR that requette consumes.

    No `port` field: the `port` SvcParam is a non-goal for this increment;
    the seeded port is always the origin port.
    """

    var alpns: List[String]   # ALPN tokens from the `alpn` SvcParam (key 1)
    var ttl: UInt             # the RR-header TTL (raw; requette clamps it)
    var target: String        # TargetName; "" when "." (same-origin, RFC 9460 §2.5)
    var priority: UInt16      # SvcPriority (>0 for ServiceMode)

    def __init__(
        out self, *, var alpns: List[String], ttl: UInt,
        var target: String, priority: UInt16,
    ):
        # keyword-only (`*`) to match navette house style (Origin/AltSvcEntry);
        # this is the contract slice 2's tests construct against.
        self.alpns = alpns^
        self.ttl = ttl
        self.target = target^
        self.priority = priority

    def __init__(out self, *, other: Self):
        self.alpns = other.alpns.copy()
        self.ttl = other.ttl
        self.target = other.target.copy()
        self.priority = other.priority

    def __init__(out self, *, deinit take: Self):
        self.alpns = take.alpns^
        self.ttl = take.ttl
        self.target = take.target^
        self.priority = take.priority


struct _Name(Copyable, Movable):
    """Decompressed name + the offset just past the name in the linear stream."""

    var value: String
    var next_off: Int

    def __init__(out self, var value: String, next_off: Int):
        self.value = value^
        self.next_off = next_off

    def __init__(out self, *, other: Self):
        self.value = other.value.copy()
        self.next_off = other.next_off

    def __init__(out self, *, deinit take: Self):
        self.value = take.value^
        self.next_off = take.next_off


struct _Answer(Copyable, Movable):
    """A classified datagram: a kind tag + an optional parsed record."""

    var kind: Int
    var record: Optional[HttpsRecord]

    def __init__(out self, kind: Int, var record: Optional[HttpsRecord]):
        self.kind = kind
        self.record = record^

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.record = other.record.copy()

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.record = take.record^


def _read_file(path: String) raises -> List[UInt8]:
    """Read up to 8 KiB from a file into a byte list. Raises if unreadable.

    The cap defends against symlinked or pathological files being slurped whole;
    8 KiB is ample for any real resolv.conf.
    """
    var fh = FileHandle(path, "r")
    return fh.read_bytes(8192)


def _is_ipv4_literal(s: String) -> Bool:
    """True iff `s` parses as a dotted IPv4 literal (IPv6 → False)."""
    return Bool(IpAddrV4.parse(s))


def _parse_resolv_conf(data: List[UInt8]) -> String:
    """Return the first `nameserver <ipv4>` value, else "".

    Skips blank lines and `#`/`;` comments; matches the case-sensitive token
    `nameserver`; ignores nameserver values that are not dotted-IPv4 literals
    (IPv6 nameservers and `options` are out of scope for the MVP).
    """
    var n = len(data)
    var i = 0
    while i < n:
        # slice one line [ls, le)
        var ls = i
        while i < n and data[i] != UInt8(0x0A):
            i += 1
        var le = i
        # strip a trailing CR so CRLF files parse identically to LF files
        if le > ls and data[le - 1] == UInt8(0x0D):
            le -= 1
        i += 1
        # strip leading SP/TAB
        var p = ls
        while p < le and (data[p] == UInt8(0x20) or data[p] == UInt8(0x09)):
            p += 1
        if p >= le or data[p] == UInt8(0x23) or data[p] == UInt8(0x3B):
            continue  # blank, '#', or ';'
        # read token 1
        var t1s = p
        while p < le and data[p] != UInt8(0x20) and data[p] != UInt8(0x09):
            p += 1
        var t1 = String()
        for k in range(t1s, p):
            t1 += chr(Int(data[k]))
        if t1 != String("nameserver"):
            continue
        # skip ws, read token 2 (candidate IP)
        while p < le and (data[p] == UInt8(0x20) or data[p] == UInt8(0x09)):
            p += 1
        var t2s = p
        while p < le and data[p] != UInt8(0x20) and data[p] != UInt8(0x09):
            p += 1
        var ip = String()
        for k in range(t2s, p):
            ip += chr(Int(data[k]))
        if _is_ipv4_literal(ip):
            return ip^
    return String("")


def _first_nameserver(path: String = "/etc/resolv.conf") -> String:
    """Return the resolver IP for DNS queries.

    Reads `path` (default `/etc/resolv.conf`), returns the first IPv4
    `nameserver` value found, or `127.0.0.53` (systemd-resolved stub) when the
    file is missing, unreadable, or contains no IPv4 nameserver entry.
    The `path` parameter exists primarily for testing; callers without a
    specific path rely on the default.
    """
    try:
        var data = _read_file(path)
        var ip = _parse_resolv_conf(data)
        if ip.byte_length() > 0:
            return ip^
    except:
        pass
    return String(_DEFAULT_NS)


def _encode_qname(host: String) -> List[UInt8]:
    """Encode `host` as a DNS label sequence terminated by a zero octet.

    Empty labels (leading/trailing/`..`) are dropped, so `"example.com"` and
    `"example.com."` encode identically.  Each non-empty label is prefixed with
    its byte length per RFC 1035 §3.1.
    """
    var out = List[UInt8]()
    var b = host.as_bytes()
    var n = len(b)
    var i = 0
    while i < n:
        var j = i
        while j < n and b[j] != _B_DOT:
            j += 1
        var label_len = j - i
        if label_len > 0:
            out.append(UInt8(label_len))
            for k in range(i, j):
                out.append(b[k])
        i = j + 1
    out.append(UInt8(0))
    return out^


def _build_query(host: String, txn_id: UInt16) -> List[UInt8]:
    """Build a type-65 HTTPS-RR query with a single EDNS0 OPT RR.

    `txn_id` is injected (the anti-spoof random id is generated separately) so
    the byte layout is deterministically testable.  Header: RD=1, all other
    flags 0, QDCOUNT=1, ANCOUNT=NSCOUNT=0, ARCOUNT=1.  OPT RR: root name
    (0x00), TYPE=41, CLASS=1232 (UDP payload size per DNS Flag Day 2020),
    TTL=0 (extended-RCODE 0 / EDNS version 0 / DO=0), RDLEN=0.
    """
    var m = List[UInt8]()
    m.append(UInt8((Int(txn_id) >> 8) & 0xFF))
    m.append(UInt8(Int(txn_id) & 0xFF))
    m.append(UInt8(0x01)); m.append(UInt8(0x00))   # flags: RD=1
    m.append(UInt8(0x00)); m.append(UInt8(0x01))   # QDCOUNT=1
    m.append(UInt8(0x00)); m.append(UInt8(0x00))   # ANCOUNT=0
    m.append(UInt8(0x00)); m.append(UInt8(0x00))   # NSCOUNT=0
    m.append(UInt8(0x00)); m.append(UInt8(0x01))   # ARCOUNT=1
    var qn = _encode_qname(host)
    for i in range(len(qn)):
        m.append(qn[i])
    m.append(UInt8(0x00)); m.append(UInt8(_QTYPE_HTTPS))  # QTYPE=65
    m.append(UInt8(0x00)); m.append(UInt8(_QCLASS_IN))    # QCLASS=IN
    # EDNS0 OPT RR (additional section)
    m.append(UInt8(0x00))                                 # root name
    m.append(UInt8(0x00)); m.append(UInt8(41))            # TYPE=41 (OPT)
    m.append(UInt8((_EDNS_UDP_SIZE >> 8) & 0xFF))         # CLASS hi (1232)
    m.append(UInt8(_EDNS_UDP_SIZE & 0xFF))                # CLASS lo
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # TTL hi (DO=0)
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # TTL lo
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # RDLEN=0
    return m^


def _read_u16(m: List[UInt8], off: Int) raises -> UInt16:
    """Read a big-endian u16 at `off`. Raises if it would over-read."""
    if off < 0 or off + 1 >= len(m):
        raise "svcb: u16 out of bounds"
    return (UInt16(m[off]) << 8) | UInt16(m[off + 1])


def _decode_name(m: List[UInt8], start: Int) raises -> _Name:
    """Decompress an RFC 1035 §4.1.4 domain name starting at `start`.

    Returns the dotted name plus `next_off` — the offset just past the name in
    the linear stream (for a compressed name, just past the *first* pointer).
    Two guards make this DoS-proof: every compression pointer must target a
    **strictly lower** offset than its own position (rejects equal/forward
    pointers, terminating pure-pointer chains), and the assembled name is
    capped at 255 octets (terminating label-bearing loops). Any violation
    raises — the caller treats it as a malformed RR, never a hang or over-read.
    """
    var name = String()
    var pos = start
    var next_after = -1
    var jumped = False
    var total = 0
    while True:
        if pos < 0 or pos >= len(m):
            raise "svcb: name out of bounds"
        var b = Int(m[pos])
        if b == 0:
            if not jumped:
                next_after = pos + 1
            break
        if (b & 0xC0) == 0xC0:
            if pos + 1 >= len(m):
                raise "svcb: truncated name pointer"
            var ptr = ((b & 0x3F) << 8) | Int(m[pos + 1])
            if not jumped:
                next_after = pos + 2
            if ptr >= pos:
                raise "svcb: non-decreasing name pointer"
            pos = ptr
            jumped = True
            continue
        if (b & 0xC0) != 0:
            raise "svcb: bad label flags"
        var label_end = pos + 1 + b
        if label_end > len(m):
            raise "svcb: label out of bounds"
        if name.byte_length() > 0:
            name += "."
        for k in range(pos + 1, label_end):
            name += chr(Int(m[k]))
        total += b + 1
        if total > _NAME_MAX:
            raise "svcb: name exceeds 255 octets"
        pos = label_end
    return _Name(name^, next_after)


def _parse_alpn(m: List[UInt8], start: Int, end: Int) raises -> List[String]:
    """Parse the `alpn` (key 1) SvcParam value: a run of length-prefixed tokens.

    Each token is `len(u8) value[len]`. Raises if a token overruns the value
    bounds — the caller skips the offending RR.
    """
    var out = List[String]()
    var p = start
    while p < end:
        var tlen = Int(m[p])
        p += 1
        if p + tlen > end:
            raise "svcb: alpn token overruns value"
        var tok = String()
        for k in range(p, p + tlen):
            tok += chr(Int(m[k]))
        out.append(tok^)
        p += tlen
    return out^


def resolve_https_rr(
    host: String, *, timeout_ms: UInt = 2000,
) raises -> Optional[HttpsRecord]:
    """Stub — the UDP query path is wired in a later step."""
    return None
