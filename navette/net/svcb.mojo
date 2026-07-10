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

from std.collections.optional import Optional

from navette.net.resolver import ResolvedAddr, resolve_host
from navette.runtime.socket_helpers import udp_connect, tcp_connect

from navette.net._dns_wire import (
    _QCLASS_IN, _MAX_TCP_FRAME,
    _ANS_INVALID, _ANS_NONE, _ANS_RECORD, _ANS_TRUNCATED,
    _parse_resolv_conf, _first_nameserver,
    _encode_qname, _read_u16, _decode_name, _build_query, _random_txn_id,
    _monotonic_ms,
    _set_rcvtimeo, _send_dgram, _recv_dgram, _send_all_tcp, _recv_n,
)


# ── wire constants ─────────────────────────────────────────────────────────
comptime _QTYPE_HTTPS: Int = 65


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


def _query_tcp(
    addr: ResolvedAddr, host: String, txn_id: UInt16, deadline: UInt64,
) raises -> Optional[HttpsRecord]:
    """Re-issue the same query (incl. EDNS0 OPT) over TCP/53, length-framed.

    Sends a 2-byte big-endian length prefix followed by the query wire bytes;
    reads a 2-byte length prefix then that many body bytes (per RFC 1035 §4.2.2).
    The declared frame length is capped at `_MAX_TCP_FRAME` — a resolver claiming
    0xFFFF and dribbling cannot grow an unbounded buffer or hang: the frame-length
    cap prevents the allocation, and the `_recv_n` deadline bounds the read time.

    `deadline` is an absolute monotonic timestamp shared with the UDP phase so
    that connect + length-read + body-read together cannot exceed the caller's
    single total-operation budget.  Each blocking step uses `remaining` computed
    from `deadline - _monotonic_ms()` rather than a fresh per-phase timeout.
    A still-truncated answer, a length over the cap, or any I/O failure yields
    `None` — never a raise to the caller, never a hang.
    """
    var q = _build_query(host, txn_id)
    # Compute remaining budget; bail early if deadline already passed.
    var now = _monotonic_ms()
    if deadline <= now:
        return Optional[HttpsRecord](None)
    var rem_connect = Int(deadline - now)
    var sock = tcp_connect(addr, connect_timeout_ms=UInt64(rem_connect))
    var fd = sock.raw()
    now = _monotonic_ms()
    # SO_RCVTIMEO accepts 0 as "no timeout"; clamp to 1 ms minimum so a just-
    # expired deadline does not inadvertently disable the receive timeout.
    var rem_rcv = Int(deadline - now) if deadline > now else 1
    _set_rcvtimeo(fd, rem_rcv)
    var framed = List[UInt8]()
    framed.append(UInt8((len(q) >> 8) & 0xFF))
    framed.append(UInt8(len(q) & 0xFF))
    for i in range(len(q)):
        framed.append(q[i])
    var result = Optional[HttpsRecord](None)
    if _send_all_tcp(fd, framed) == len(framed):
        var hdr = _recv_n(fd, 2, deadline)
        if len(hdr) == 2:
            var mlen = (Int(hdr[0]) << 8) | Int(hdr[1])
            if mlen > 0 and mlen <= _MAX_TCP_FRAME:
                var body = _recv_n(fd, mlen, deadline)
                if len(body) == mlen:
                    var ans = _parse_https_answer(body, txn_id, host)
                    if ans.kind == _ANS_RECORD:
                        result = ans.record.copy()
    _ = sock.raw()                            # NLL keepalive
    return result^


def _query_udp(
    addr: ResolvedAddr, host: String, txn_id: UInt16, deadline: UInt64,
) raises -> Optional[HttpsRecord]:
    """Query the type-65 RR over a *connected* UDP socket with anti-spoof recv.

    The connected socket gives a random ephemeral source port and lets the
    kernel drop off-path datagrams. We loop reading datagrams until one
    validates or the deadline expires — a stray/spoofed/garbled datagram is
    discarded (not fatal). A TC=1 answer delegates to `_query_tcp`.

    `deadline` is an absolute monotonic timestamp (from `_monotonic_ms()`) that
    serves as the single total-operation budget for *both* the UDP receive loop
    and any subsequent TCP fallback.  SO_RCVTIMEO is set to the time remaining
    at socket-open rather than a fresh per-phase value.
    """
    var q = _build_query(host, txn_id)
    var sock = udp_connect(addr)
    var fd = sock.raw()
    var now = _monotonic_ms()
    # SO_RCVTIMEO 0 = no timeout; clamp to 1 ms so an already-expired deadline
    # still produces a bounded recv rather than blocking indefinitely.
    _set_rcvtimeo(fd, Int(deadline - now) if deadline > now else 1)
    var result = Optional[HttpsRecord](None)
    var need_tcp = False
    if _send_dgram(fd, q) > 0:
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
        return _query_tcp(addr, host, txn_id, deadline)
    return result^


def resolve_https_rr(
    host: String, *, timeout_ms: UInt = 2000,
) -> Optional[HttpsRecord]:
    """Resolve the HTTPS RR (type 65) for `host`; return the preferred record.

    SVCB-optional (RFC 9460 §3): every failure mode — unreadable
    resolv.conf, resolver-address failure, socket error, timeout, truncation
    we can't resolve, malformed record — yields `None`, never a raise to the
    caller. The result is a hint (RFC 9460 §9.5); TLS authenticates the endpoint.

    `timeout_ms` is a true wall-clock bound on the entire operation: a single
    absolute monotonic deadline is computed at entry and threaded through the
    UDP receive loop and any TCP/53 fallback, so all phases share one budget
    rather than each phase receiving a fresh `timeout_ms`-length allowance.
    """
    try:
        var ns = _first_nameserver()
        var addrs = resolve_host(ns, 53)
        if len(addrs) == 0:
            return None
        var txn_id = _random_txn_id()
        var deadline = _monotonic_ms() + UInt64(timeout_ms)
        return _query_udp(addrs[0], host, txn_id, deadline)
    except:
        return None
