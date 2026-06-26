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

    Each token is `len(u8) value[len]`. Per RFC 9460 §7.1.1, every alpn-id
    MUST be non-empty; zero-length tokens are silently skipped so that a record
    whose `alpn` contains only empty tokens yields an empty list and correctly
    fails the non-empty-alpn selection gate in the caller.
    Raises if a token overruns the value bounds — the caller skips the
    offending RR.
    """
    var out = List[String]()
    var p = start
    while p < end:
        var tlen = Int(m[p])
        p += 1
        if p + tlen > end:
            raise "svcb: alpn token overruns value"
        if tlen == 0:
            continue   # RFC 9460 §7.1.1: each alpn-id MUST be non-empty; skip
        var tok = String()
        for k in range(p, p + tlen):
            tok += chr(Int(m[k]))
        out.append(tok^)
        p += tlen
    return out^


def _parse_https_answer(m: List[UInt8], qid: UInt16, host: String) -> _Answer:
    """Classify + parse a datagram; never raises (any failure -> _ANS_INVALID)."""
    try:
        return _parse_https_answer_inner(m, qid, host)
    except:
        return _Answer(_ANS_INVALID, None)


def _parse_https_answer_inner(
    m: List[UInt8], qid: UInt16, host: String,
) raises -> _Answer:
    """Validate the header/question, then select the preferred ServiceMode RR.

    Validation order (anti-spoof first, then status, then content):
      1. txn-id, QR=1 (response bit), QDCOUNT==1, echoed QNAME (case-insensitive), QTYPE/QCLASS
         -> mismatch = `_ANS_INVALID` (discard, keep reading).
      2. TC=1 -> `_ANS_TRUNCATED` (TCP/53 fallback).
      3. rcode != 0 -> `_ANS_NONE` (legitimate negative answer).
      4. scan ANCOUNT RRs; return the smallest-SvcPriority (>0) ServiceMode RR
         with a non-empty `alpn` as `_ANS_RECORD`, else `_ANS_NONE`. AliasMode
         (priority 0) is skipped; a malformed RR stops the scan with the
         best-so-far result (never fatal).
    """
    if len(m) < 12:
        return _Answer(_ANS_INVALID, None)
    if _read_u16(m, 0) != qid:
        return _Answer(_ANS_INVALID, None)
    if (Int(m[2]) & 0x80) == 0:
        return _Answer(_ANS_INVALID, None)  # QR=0 means query, not response (RFC 1035 §4.1.1)
    var qd = Int(_read_u16(m, 4))
    var an = Int(_read_u16(m, 6))
    if qd != 1:
        return _Answer(_ANS_INVALID, None)
    var qn = _decode_name(m, 12)
    var qoff = qn.next_off
    if qn.value.lower() != host.lower():
        return _Answer(_ANS_INVALID, None)
    if Int(_read_u16(m, qoff)) != _QTYPE_HTTPS or Int(_read_u16(m, qoff + 2)) != _QCLASS_IN:
        return _Answer(_ANS_INVALID, None)
    # valid response to *our* query
    if (Int(m[2]) & 0x02) != 0:
        return _Answer(_ANS_TRUNCATED, None)
    if (Int(m[3]) & 0x0F) != 0:
        return _Answer(_ANS_NONE, None)
    var off = qoff + 4
    var have = False
    var best_prio = 0x10000
    var best_alpns = List[String]()
    var best_ttl = UInt(0)
    var best_target = String()
    for _i in range(an):
        var ok = True
        try:
            var nm = _decode_name(m, off)
            var p = nm.next_off
            var rtype = Int(_read_u16(m, p))
            # TTL spans bytes p+4..p+7; use _read_u16 so any truncation raises
            # (direct indexing panics rather than raises under ASSERT=all).
            var ttl_hi = UInt(_read_u16(m, p + 4))
            var ttl_lo = UInt(_read_u16(m, p + 6))
            var ttl = (ttl_hi << 16) | ttl_lo
            var rdlen = Int(_read_u16(m, p + 8))
            var rdstart = p + 10
            var rdend = rdstart + rdlen
            if rdend > len(m):
                ok = False
            else:
                if rtype == _QTYPE_HTTPS:
                    var prio = Int(_read_u16(m, rdstart))
                    if prio != 0:                       # skip AliasMode
                        var tn = _decode_name(m, rdstart + 2)
                        var sp = tn.next_off
                        var alpns = List[String]()
                        while sp + 4 <= rdend:
                            var key = Int(_read_u16(m, sp))
                            var vlen = Int(_read_u16(m, sp + 2))
                            var vstart = sp + 4
                            if vstart + vlen > rdend:
                                break                   # malformed TLV -> stop this RR
                            if key == 1:
                                alpns = _parse_alpn(m, vstart, vstart + vlen)
                            sp = vstart + vlen
                        if len(alpns) > 0 and prio < best_prio:
                            have = True
                            best_prio = prio
                            best_alpns = alpns^
                            best_ttl = ttl
                            best_target = tn.value
                off = rdend
        except:
            ok = False
        if not ok:
            break
    if have:
        var rec = HttpsRecord(
            alpns=best_alpns^, ttl=best_ttl,
            target=best_target^, priority=UInt16(best_prio),
        )
        return _Answer(_ANS_RECORD, Optional(rec^))
    return _Answer(_ANS_NONE, None)


def _monotonic_ms() -> UInt64:
    """CLOCK_MONOTONIC milliseconds (for the recv-loop deadline)."""
    var ts_buf = Owned[UInt8](16)
    var ts = ts_buf.ptr()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts)
    var sec = Int(ts.bitcast[Int64]()[])
    var nsec_ptr = UnsafePointer[Int64, MutAnyOrigin](unsafe_from_address=Int(ts) + 8)
    var nsec = Int(nsec_ptr[])
    return UInt64(sec * 1000 + nsec // 1_000_000)


def _set_rcvtimeo(fd: Int32, ms: Int) raises:
    """SO_RCVTIMEO on `fd` (millisecond timeval). Mirrors socket_helpers."""
    var tv_buf = Owned[UInt8](16)
    var tv = tv_buf.ptr()
    for i in range(16):
        tv[i] = UInt8(0)
    var sec_ptr = tv.bitcast[Int64]()
    sec_ptr[] = Int64(ms // 1000)
    var usec_ptr = UnsafePointer[Int64, MutAnyOrigin](unsafe_from_address=Int(tv) + 8)
    usec_ptr[] = Int64((ms % 1000) * 1000)
    var rc = external_call["setsockopt", Int32](
        fd, _SOL_SOCKET, _SO_RCVTIMEO, tv, Int32(16)
    )
    if rc < 0:
        raise "svcb: setsockopt(SO_RCVTIMEO) failed"


def _send_dgram(fd: Int32, data: List[UInt8]) raises -> Int:
    """Send one datagram (MSG_NOSIGNAL). Returns the send rc."""
    var n = len(data)
    var buf_owned = Owned[UInt8](n)
    var buf = buf_owned.ptr()
    for i in range(n):
        buf[i] = data[i]
    return external_call["send", Int](fd, buf, n, _MSG_NOSIGNAL)


def _recv_dgram(fd: Int32, max_n: Int) raises -> List[UInt8]:
    """Receive one datagram. Empty list on timeout/EAGAIN (rc <= 0)."""
    var buf_owned = Owned[UInt8](max_n)
    var buf = buf_owned.ptr()
    var rc = external_call["recv", Int](fd, buf, max_n, Int32(0))
    var out = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            out.append(buf[i])
    return out^


def _send_all_tcp(fd: Int32, data: List[UInt8]) raises -> Int:
    """Send every byte of `data` over TCP. Returns the total bytes sent.

    Returns fewer than `len(data)` bytes only when `send(2)` returns <= 0
    (connection reset, broken pipe), in which case the caller treats the
    short count as a failure and returns `None`.
    """
    var sent = 0
    var n = len(data)
    while sent < n:
        var m = n - sent
        var buf_owned = Owned[UInt8](m)
        var buf = buf_owned.ptr()
        for i in range(m):
            buf[i] = data[sent + i]
        var rc = external_call["send", Int](fd, buf, m, _MSG_NOSIGNAL)
        if rc <= 0:
            return sent
        sent += rc
    return sent


def _recv_n(fd: Int32, want: Int, timeout_ms: UInt) raises -> List[UInt8]:
    """Read exactly `want` bytes, bounded by a monotonic deadline.

    `want` is pre-capped by the caller (<= _MAX_TCP_FRAME); the deadline
    bounds a dribbling resolver — together they bound the buffer so a
    malicious advertised length cannot grow it without limit.  Returns
    fewer than `want` bytes on EOF, error, or deadline expiry.
    """
    var out = List[UInt8]()
    var deadline = _monotonic_ms() + UInt64(timeout_ms)
    while len(out) < want and _monotonic_ms() < deadline:
        var rem = want - len(out)
        var buf_owned = Owned[UInt8](rem)
        var buf = buf_owned.ptr()
        var rc = external_call["recv", Int](fd, buf, rem, Int32(0))
        if rc <= 0:
            break
        for i in range(rc):
            out.append(buf[i])
    return out^


def _query_tcp(
    addr: ResolvedAddr, host: String, txn_id: UInt16, timeout_ms: UInt,
) raises -> Optional[HttpsRecord]:
    """Re-issue the same query (incl. EDNS0 OPT) over TCP/53, length-framed.

    Sends a 2-byte big-endian length prefix followed by the query wire bytes;
    reads a 2-byte length prefix then that many body bytes (per RFC 1035 §4.2.2).
    The declared frame length is capped at `_MAX_TCP_FRAME` — a resolver claiming
    0xFFFF and dribbling cannot grow an unbounded buffer or hang: the frame-length
    cap prevents the allocation, and the `_recv_n` deadline bounds the read time.
    A still-truncated answer, a length over the cap, or any I/O failure yields
    `None` — never a raise to the caller, never a hang.
    """
    var q = _build_query(host, txn_id)
    var sock = tcp_connect(addr, connect_timeout_ms=UInt64(timeout_ms))
    var fd = sock.raw()
    _set_rcvtimeo(fd, Int(timeout_ms))
    var framed = List[UInt8]()
    framed.append(UInt8((len(q) >> 8) & 0xFF))
    framed.append(UInt8(len(q) & 0xFF))
    for i in range(len(q)):
        framed.append(q[i])
    var result = Optional[HttpsRecord](None)
    if _send_all_tcp(fd, framed) == len(framed):
        var hdr = _recv_n(fd, 2, timeout_ms)
        if len(hdr) == 2:
            var mlen = (Int(hdr[0]) << 8) | Int(hdr[1])
            if mlen > 0 and mlen <= _MAX_TCP_FRAME:
                var body = _recv_n(fd, mlen, timeout_ms)
                if len(body) == mlen:
                    var ans = _parse_https_answer(body, txn_id, host)
                    if ans.kind == _ANS_RECORD:
                        result = ans.record.copy()
    _ = sock.raw()                            # NLL keepalive
    return result^


def _query_udp(
    addr: ResolvedAddr, host: String, txn_id: UInt16, timeout_ms: UInt,
) raises -> Optional[HttpsRecord]:
    """Query the type-65 RR over a *connected* UDP socket with anti-spoof recv.

    The connected socket gives a random ephemeral source port and lets the
    kernel drop off-path datagrams. We loop reading datagrams until one
    validates or the deadline expires — a stray/spoofed/garbled datagram is
    discarded (not fatal). A TC=1 answer delegates to `_query_tcp`.
    """
    var q = _build_query(host, txn_id)
    var sock = udp_connect(addr)
    var fd = sock.raw()
    _set_rcvtimeo(fd, Int(timeout_ms))
    var result = Optional[HttpsRecord](None)
    var need_tcp = False
    if _send_dgram(fd, q) > 0:
        var deadline = _monotonic_ms() + UInt64(timeout_ms)
        while _monotonic_ms() < deadline:
            var dg = _recv_dgram(fd, 65536)
            if len(dg) == 0:
                continue                      # timeout slice / empty → keep waiting
            var ans = _parse_https_answer(dg, txn_id, host)
            if ans.kind == _ANS_INVALID:
                continue                      # spoof/stray → keep reading
            if ans.kind == _ANS_TRUNCATED:
                need_tcp = True
                break
            if ans.kind == _ANS_RECORD:
                result = ans.record.copy()
                break
            break                             # _ANS_NONE: valid, no record
    _ = sock.raw()                            # NLL: hold the socket past the loop
    if need_tcp:
        return _query_tcp(addr, host, txn_id, timeout_ms)
    return result^


def _random_txn_id() -> UInt16:
    """A random 16-bit DNS transaction id via getrandom(2) (anti-spoof)."""
    var buf = Owned[UInt8](2)
    var p = buf.ptr()
    p[0] = UInt8(0); p[1] = UInt8(0)
    _ = external_call["getrandom", Int](p, UInt64(2), UInt32(0))
    return (UInt16(p[0]) << 8) | UInt16(p[1])


def resolve_https_rr(
    host: String, *, timeout_ms: UInt = 2000,
) -> Optional[HttpsRecord]:
    """Resolve the HTTPS RR (type 65) for `host`; return the preferred record.

    SVCB-optional (RFC 9460 §3): every failure mode — unreadable
    resolv.conf, resolver-address failure, socket error, timeout, truncation
    we can't resolve, malformed record — yields `None`, never a raise to the
    caller. The result is a hint (RFC 9460 §9.5); TLS authenticates the endpoint.
    """
    try:
        var ns = _first_nameserver()
        var addrs = resolve_host(ns, 53)
        if len(addrs) == 0:
            return None
        var txn_id = _random_txn_id()
        return _query_udp(addrs[0], host, txn_id, timeout_ms)
    except:
        return None
