"""_dns_wire.mojo — shared DNS wire-format, socket I/O, and clock helpers.

Extracted from `svcb.mojo` so both the HTTPS-RR (type-65) resolver and the
bounded A/AAAA resolver can share the same primitives without duplication.
Internal module — no public API guarantees.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.io.file import FileHandle

from navette.util.owned_alloc import Owned

from boucle.net.ip import IpAddrV4


# ── wire constants ─────────────────────────────────────────────────────────
comptime _QCLASS_IN: Int = 1
comptime _EDNS_UDP_SIZE: Int = 1232          # 0x04D0, DNS Flag Day 2020
comptime _B_DOT: UInt8 = 46                  # '.'
comptime _DEFAULT_NS: String = "127.0.0.53"  # systemd-resolved stub
comptime _NAME_MAX: Int = 255                # RFC 1035 Section 3.1
comptime _MAX_TCP_FRAME: Int = 65535         # cap a dribbling TCP length (DoS guard)

# clock / socket-option FFI constants
comptime _CLOCK_MONOTONIC: Int32 = 1
comptime _SOL_SOCKET: Int32 = 1
comptime _SO_RCVTIMEO: Int32 = 20
comptime _MSG_NOSIGNAL: Int32 = 0x4000

# datagram classification (anti-spoof recv loop)
comptime _ANS_INVALID: Int = 0     # spoof/stray/garbled -- discard, keep reading
comptime _ANS_NONE: Int = 1        # valid answer, no usable record -- None
comptime _ANS_RECORD: Int = 2      # valid answer carrying a ServiceMode record
comptime _ANS_TRUNCATED: Int = 3   # valid header with TC=1 -- TCP/53 fallback


# ── _Name struct ───────────────────────────────────────────────────────────


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


# ── _Deadline struct ───────────────────────────────────────────────────────


struct _Deadline(Copyable, Movable):
    """Monotonic-clock deadline for bounded DNS operations."""

    var _expires_ms: UInt64

    def __init__(out self, *, _expires_ms: UInt64):
        self._expires_ms = _expires_ms

    def __init__(out self, *, other: Self):
        self._expires_ms = other._expires_ms

    def __init__(out self, *, deinit take: Self):
        self._expires_ms = take._expires_ms

    @staticmethod
    def from_timeout_ms(ms: UInt) -> Self:
        """Create a deadline that expires `ms` milliseconds from now."""
        return Self(_expires_ms=_monotonic_ms() + UInt64(ms))

    @staticmethod
    def none() -> Self:
        """Create a sentinel deadline that never expires."""
        return Self(_expires_ms=UInt64.MAX)

    def remaining_ms(self) -> UInt64:
        """Milliseconds until expiry, floored at 0."""
        var now = _monotonic_ms()
        if now >= self._expires_ms:
            return UInt64(0)
        return self._expires_ms - now

    def is_expired(self) -> Bool:
        """True iff the deadline has passed."""
        return _monotonic_ms() >= self._expires_ms

    def is_set(self) -> Bool:
        """True iff this is a real deadline (not the `none` sentinel)."""
        return self._expires_ms != UInt64.MAX

    def absolute_ms(self) -> UInt64:
        """Return the raw absolute expiry for passing to `_recv_n`."""
        return self._expires_ms


# ── file / resolv.conf helpers ─────────────────────────────────────────────


def _read_file(path: String) raises -> List[UInt8]:
    """Read up to 8 KiB from a file into a byte list. Raises if unreadable.

    The cap defends against symlinked or pathological files being slurped whole;
    8 KiB is ample for any real resolv.conf.
    """
    var fh = FileHandle(path, "r")
    return fh.read_bytes(8192)


def _is_ipv4_literal(s: String) -> Bool:
    """True iff `s` parses as a dotted IPv4 literal (IPv6 -> False)."""
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


# ── wire-format primitives ─────────────────────────────────────────────────


def _encode_qname(host: String) -> List[UInt8]:
    """Encode `host` as a DNS label sequence terminated by a zero octet.

    Empty labels (leading/trailing/`..`) are dropped, so `"example.com"` and
    `"example.com."` encode identically.  Each non-empty label is prefixed with
    its byte length per RFC 1035 Section 3.1.
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


def _read_u16(m: List[UInt8], off: Int) raises -> UInt16:
    """Read a big-endian u16 at `off`. Raises if it would over-read."""
    if off < 0 or off + 1 >= len(m):
        raise "_dns_wire: u16 out of bounds"
    return (UInt16(m[off]) << 8) | UInt16(m[off + 1])


def _decode_name(m: List[UInt8], start: Int) raises -> _Name:
    """Decompress an RFC 1035 Section 4.1.4 domain name starting at `start`.

    Returns the dotted name plus `next_off` -- the offset just past the name in
    the linear stream (for a compressed name, just past the *first* pointer).
    Two guards make this DoS-proof: every compression pointer must target a
    **strictly lower** offset than its own position (rejects equal/forward
    pointers, terminating pure-pointer chains), and the assembled name is
    capped at 255 octets (terminating label-bearing loops). Any violation
    raises -- the caller treats it as a malformed RR, never a hang or over-read.
    """
    var name = String()
    var pos = start
    var next_after = -1
    var jumped = False
    var total = 0
    var jumps = 0    # indirection-hop counter; capped at 128 (RFC 1035 Section 4.1.4)
    while True:
        if pos < 0 or pos >= len(m):
            raise "_dns_wire: name out of bounds"
        var b = Int(m[pos])
        if b == 0:
            if not jumped:
                next_after = pos + 1
            break
        if (b & 0xC0) == 0xC0:
            if pos + 1 >= len(m):
                raise "_dns_wire: truncated name pointer"
            var ptr = ((b & 0x3F) << 8) | Int(m[pos + 1])
            if not jumped:
                next_after = pos + 2
            if ptr >= pos:
                raise "_dns_wire: non-decreasing name pointer"
            jumps += 1
            if jumps > 128:
                raise "_dns_wire: compression pointer chain too long"
            pos = ptr
            jumped = True
            continue
        if (b & 0xC0) != 0:
            raise "_dns_wire: bad label flags"
        var label_end = pos + 1 + b
        if label_end > len(m):
            raise "_dns_wire: label out of bounds"
        if name.byte_length() > 0:
            name += "."
        for k in range(pos + 1, label_end):
            name += chr(Int(m[k]))
        total += b + 1
        if total > _NAME_MAX:
            raise "_dns_wire: name exceeds 255 octets"
        pos = label_end
    return _Name(name^, next_after)


def _build_query(host: String, txn_id: UInt16, qtype: Int = 65) -> List[UInt8]:
    """Build a DNS query with a single EDNS0 OPT RR.

    `qtype` selects the record type: 65 (HTTPS-RR), 1 (A), or 28 (AAAA).
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
    m.append(UInt8((qtype >> 8) & 0xFF)); m.append(UInt8(qtype & 0xFF))
    m.append(UInt8(0x00)); m.append(UInt8(_QCLASS_IN))
    # EDNS0 OPT RR (additional section)
    m.append(UInt8(0x00))                                 # root name
    m.append(UInt8(0x00)); m.append(UInt8(41))            # TYPE=41 (OPT)
    m.append(UInt8((_EDNS_UDP_SIZE >> 8) & 0xFF))         # CLASS hi (1232)
    m.append(UInt8(_EDNS_UDP_SIZE & 0xFF))                # CLASS lo
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # TTL hi (DO=0)
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # TTL lo
    m.append(UInt8(0x00)); m.append(UInt8(0x00))          # RDLEN=0
    return m^


def _random_txn_id() -> UInt16:
    """A random 16-bit DNS transaction id via getrandom(2) (anti-spoof)."""
    var buf = Owned[UInt8](2)
    var p = buf.ptr()
    p[0] = UInt8(0); p[1] = UInt8(0)
    _ = external_call["getrandom", Int](p, UInt64(2), UInt32(0))
    return (UInt16(p[0]) << 8) | UInt16(p[1])


# ── clock helpers ──────────────────────────────────────────────────────────


def _monotonic_ms() -> UInt64:
    """CLOCK_MONOTONIC milliseconds (for the recv-loop deadline)."""
    var ts_buf = Owned[UInt8](16)
    var ts = ts_buf.ptr()
    _ = external_call["clock_gettime", Int32](_CLOCK_MONOTONIC, ts)
    var sec = Int(ts.bitcast[Int64]()[])
    var nsec_ptr = UnsafePointer[Int64, MutAnyOrigin](unsafe_from_address=Int(ts) + 8)
    var nsec = Int(nsec_ptr[])
    return UInt64(sec * 1000 + nsec // 1_000_000)


# ── socket I/O helpers ─────────────────────────────────────────────────────


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
        raise "_dns_wire: setsockopt(SO_RCVTIMEO) failed"


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


def _recv_n(fd: Int32, want: Int, deadline: UInt64) raises -> List[UInt8]:
    """Read exactly `want` bytes, bounded by an absolute monotonic deadline.

    `want` is pre-capped by the caller (<= _MAX_TCP_FRAME); the deadline
    bounds a dribbling resolver -- together they bound the buffer so a
    malicious advertised length cannot grow it without limit.  `deadline`
    is an absolute `_monotonic_ms()` timestamp so the caller's single
    total-operation deadline is honoured here rather than a fresh per-call
    timeout.  Returns fewer than `want` bytes on EOF, error, or expiry.
    """
    var out = List[UInt8]()
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
