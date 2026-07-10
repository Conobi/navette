"""Bounded A/AAAA DNS resolver with fast-path detection.

``resolve_host_bounded(host, port, *, timeout_ms)`` resolves a hostname to A
and AAAA records using the system's configured nameserver (from
``/etc/resolv.conf``), with a hard wall-clock deadline on the entire operation.
Three fast paths avoid network I/O entirely:

* **IPv4 literals** -- detected via ``IpAddrV4.parse``, returned as a single
  ``ResolvedAddr`` immediately.
* **IPv6 literals** -- bare (``::1``) or bracketed (``[::1]``), parsed into 8
  UInt16 segments and returned immediately.
* **localhost** -- returns the hardcoded pair ``[::1, 127.0.0.1]`` without any
  DNS query.

For real hostnames the resolver sends parallel A (type 1) and AAAA (type 28)
queries over a connected UDP/53 socket with distinct anti-spoof transaction ids
(``getrandom``), then collects both answers in a single recv loop bounded by
the deadline.  Truncated answers (TC=1) trigger a TCP/53 fallback per query
type.  Results are merged AAAA-first (prefer IPv6), with the caller's port
stamped on every returned address.

Every failure -- timeout, rcode error, no records, unreadable resolv.conf --
raises to the caller.  This is intentional: unlike the SVCB resolver (which is
SVCB-optional and returns ``None`` on failure), the A/AAAA resolver is on the
critical path and must surface errors.
"""

from std.collections.optional import Optional

from boucle.net.addr import SocketAddrV4, SocketAddrV6
from boucle.net.ip import IpAddrV4

from navette.net.resolver import ResolvedAddr, resolve_host
from navette.runtime.socket_helpers import udp_connect, tcp_connect

from navette.net._dns_wire import (
    _QCLASS_IN, _MAX_TCP_FRAME,
    _Deadline,
    _first_nameserver,
    _read_u16, _decode_name, _build_query, _random_txn_id,
    _set_rcvtimeo, _send_dgram, _recv_dgram, _send_all_tcp, _recv_n,
)


# ── wire constants ────────────────────────────────────────────────────────
comptime _QTYPE_A: Int = 1
comptime _QTYPE_AAAA: Int = 28


# ── string helpers ────────────────────────────────────────────────────────


def _hex_val(b: UInt8) -> Int:
    """Convert a hex-digit byte to 0--15, or -1 for non-hex characters."""
    var v = Int(b)
    if v >= 0x30 and v <= 0x39:
        return v - 0x30
    if v >= 0x41 and v <= 0x46:
        return v - 0x41 + 10
    if v >= 0x61 and v <= 0x66:
        return v - 0x61 + 10
    return -1


def _strip_brackets(host: String) -> String:
    """Strip leading ``[`` and trailing ``]`` from a bracketed IPv6 literal.

    If the host is not bracketed, returns an unchanged copy.
    """
    var b = host.as_bytes()
    var n = len(b)
    var start = 0
    var end = n
    if n >= 2 and b[0] == UInt8(0x5B) and b[n - 1] == UInt8(0x5D):
        start = 1
        end = n - 1
    var out = String()
    for i in range(start, end):
        out += chr(Int(b[i]))
    return out^


def _has_colon(s: String) -> Bool:
    """True if ``s`` contains at least one colon (IPv6 indicator)."""
    var b = s.as_bytes()
    for i in range(len(b)):
        if b[i] == UInt8(0x3A):
            return True
    return False


def _parse_ipv6_segments(s: String) -> Optional[List[UInt16]]:
    """Parse an IPv6 address string into 8 UInt16 network-order segments.

    Handles full notation (8 colon-separated hex groups) and abbreviated
    notation with a single ``::`` expansion.  Returns ``None`` for any
    invalid input -- malformed hex, wrong group count, or multiple ``::``
    occurrences.
    """
    var b = s.as_bytes()
    var n = len(b)
    if n == 0:
        return Optional[List[UInt16]](None)

    # Locate ``::`` (at most one allowed).
    var dcolon = -1
    for i in range(n - 1):
        if b[i] == UInt8(0x3A) and b[i + 1] == UInt8(0x3A):
            if dcolon >= 0:
                return Optional[List[UInt16]](None)
            dcolon = i

    if dcolon < 0:
        # No ``::`` -- must be exactly 8 colon-separated hex groups.
        var segs = List[UInt16]()
        var val = 0
        var digits = 0
        for i in range(n):
            if b[i] == UInt8(0x3A):
                if digits == 0:
                    return Optional[List[UInt16]](None)
                segs.append(UInt16(val))
                val = 0
                digits = 0
            else:
                var d = _hex_val(b[i])
                if d < 0:
                    return Optional[List[UInt16]](None)
                val = val * 16 + d
                digits += 1
                if val > 0xFFFF or digits > 4:
                    return Optional[List[UInt16]](None)
        if digits == 0:
            return Optional[List[UInt16]](None)
        segs.append(UInt16(val))
        if len(segs) != 8:
            return Optional[List[UInt16]](None)
        return Optional(segs^)

    # With ``::`` -- parse left and right groups, fill zeros between them.
    var left = List[UInt16]()
    if dcolon > 0:
        var val = 0
        var digits = 0
        for i in range(dcolon):
            if b[i] == UInt8(0x3A):
                if digits == 0:
                    return Optional[List[UInt16]](None)
                left.append(UInt16(val))
                val = 0
                digits = 0
            else:
                var d = _hex_val(b[i])
                if d < 0:
                    return Optional[List[UInt16]](None)
                val = val * 16 + d
                digits += 1
                if val > 0xFFFF or digits > 4:
                    return Optional[List[UInt16]](None)
        if digits == 0:
            return Optional[List[UInt16]](None)
        left.append(UInt16(val))

    var right = List[UInt16]()
    var rstart = dcolon + 2
    if rstart < n:
        var val = 0
        var digits = 0
        for i in range(rstart, n):
            if b[i] == UInt8(0x3A):
                if digits == 0:
                    return Optional[List[UInt16]](None)
                right.append(UInt16(val))
                val = 0
                digits = 0
            else:
                var d = _hex_val(b[i])
                if d < 0:
                    return Optional[List[UInt16]](None)
                val = val * 16 + d
                digits += 1
                if val > 0xFFFF or digits > 4:
                    return Optional[List[UInt16]](None)
        if digits == 0:
            return Optional[List[UInt16]](None)
        right.append(UInt16(val))

    var total = len(left) + len(right)
    if total > 7:
        return Optional[List[UInt16]](None)

    var result = List[UInt16](capacity=8)
    for i in range(len(left)):
        result.append(left[i])
    var zeros = 8 - total
    for _ in range(zeros):
        result.append(UInt16(0))
    for i in range(len(right)):
        result.append(right[i])

    return Optional(result^)


# ── answer parsing ────────────────────────────────────────────────────────


def _parse_a_aaaa_answer(
    m: List[UInt8], qid: UInt16, host: String, expected_qtype: Int,
) -> List[ResolvedAddr]:
    """Parse an A or AAAA DNS answer; returns an empty list on any failure.

    Non-raising wrapper around ``_parse_a_aaaa_answer_inner`` so the recv
    loop can treat parse failures as "no records" rather than aborting.
    """
    try:
        return _parse_a_aaaa_answer_inner(m, qid, host, expected_qtype)
    except:
        return List[ResolvedAddr]()


def _parse_a_aaaa_answer_inner(
    m: List[UInt8], qid: UInt16, host: String, expected_qtype: Int,
) raises -> List[ResolvedAddr]:
    """Validate header/question and extract A or AAAA address records.

    Validation order (defense-in-depth, mirrors the recv loop's quick
    checks):

      1. Minimum length (12-byte header).
      2. Transaction-id match (anti-spoof).
      3. QR=1 (response bit).
      4. QDCOUNT == 1.
      5. Echoed QNAME (case-insensitive).
      6. QTYPE matches ``expected_qtype``; QCLASS == IN.
      7. rcode == 0 (no error).

    Then scans ANCOUNT answer RRs, collecting TYPE-1 (A, 4-byte RDATA)
    or TYPE-28 (AAAA, 16-byte RDATA) records that match
    ``expected_qtype``.  CNAME (type 5) and other RR types are silently
    skipped.  Malformed RRs stop the scan with best-so-far results
    (never fatal).  All addresses are returned with port=0; the caller
    stamps the real port in the merge step.
    """
    if len(m) < 12:
        raise "resolver_bounded: answer too short"
    if _read_u16(m, 0) != qid:
        raise "resolver_bounded: txn-id mismatch"
    if (Int(m[2]) & 0x80) == 0:
        raise "resolver_bounded: not a response (QR=0)"
    if Int(_read_u16(m, 4)) != 1:
        raise "resolver_bounded: QDCOUNT != 1"

    # Decode and validate the echoed question.
    var qn = _decode_name(m, 12)
    var qoff = qn.next_off
    if qn.value.lower() != host.lower():
        raise "resolver_bounded: QNAME mismatch"
    if Int(_read_u16(m, qoff)) != expected_qtype:
        raise "resolver_bounded: QTYPE mismatch"
    if Int(_read_u16(m, qoff + 2)) != _QCLASS_IN:
        raise "resolver_bounded: QCLASS != IN"

    # rcode (lower 4 bits of byte 3).
    if (Int(m[3]) & 0x0F) != 0:
        raise "resolver_bounded: rcode=" + String(Int(m[3]) & 0x0F)

    # Scan answer RRs.
    var ancount = Int(_read_u16(m, 6))
    var off = qoff + 4
    var results = List[ResolvedAddr]()

    for _i in range(ancount):
        try:
            var nm = _decode_name(m, off)
            var p = nm.next_off
            if p + 10 > len(m):
                break
            var rtype = Int(_read_u16(m, p))
            # Skip CLASS (p+2) and TTL (p+4..p+7); just read RDLENGTH.
            var rdlen = Int(_read_u16(m, p + 8))
            var rdstart = p + 10
            var rdend = rdstart + rdlen
            if rdend > len(m):
                break

            if rtype == 5:
                # CNAME -- skip.
                off = rdend
                continue

            if rtype == expected_qtype and Int(_read_u16(m, p + 2)) == _QCLASS_IN:
                if rtype == _QTYPE_A and rdlen == 4:
                    results.append(ResolvedAddr.from_v4(SocketAddrV4(
                        m[rdstart], m[rdstart + 1],
                        m[rdstart + 2], m[rdstart + 3],
                        port=UInt16(0),
                    )))
                elif rtype == _QTYPE_AAAA and rdlen == 16:
                    var s0 = (UInt16(m[rdstart]) << 8) | UInt16(m[rdstart + 1])
                    var s1 = (UInt16(m[rdstart + 2]) << 8) | UInt16(m[rdstart + 3])
                    var s2 = (UInt16(m[rdstart + 4]) << 8) | UInt16(m[rdstart + 5])
                    var s3 = (UInt16(m[rdstart + 6]) << 8) | UInt16(m[rdstart + 7])
                    var s4 = (UInt16(m[rdstart + 8]) << 8) | UInt16(m[rdstart + 9])
                    var s5 = (UInt16(m[rdstart + 10]) << 8) | UInt16(m[rdstart + 11])
                    var s6 = (UInt16(m[rdstart + 12]) << 8) | UInt16(m[rdstart + 13])
                    var s7 = (UInt16(m[rdstart + 14]) << 8) | UInt16(m[rdstart + 15])
                    results.append(ResolvedAddr.from_v6(SocketAddrV6(
                        s0, s1, s2, s3, s4, s5, s6, s7,
                        port=UInt16(0),
                    )))

            off = rdend
        except:
            break

    return results^


# ── TCP fallback ──────────────────────────────────────────────────────────


def _query_a_aaaa_tcp(
    addr: ResolvedAddr, host: String, txn_id: UInt16,
    qtype: Int, deadline: _Deadline,
) raises -> List[ResolvedAddr]:
    """Re-issue an A or AAAA query over TCP/53, length-framed.

    Called when the UDP answer has TC=1 (truncated).  Sends a 2-byte
    big-endian length prefix followed by the query wire bytes (per
    RFC 1035 Section 4.2.2), then reads the length-framed response.
    ``deadline`` is the same absolute monotonic timestamp shared with the
    UDP phase so the total operation budget is honoured.

    Socket-level failures (socket creation, connect timeout) propagate as
    raises to the caller; parse failures and malformed responses return an
    empty list.
    """
    var q = _build_query(host, txn_id, qtype)
    var rem = deadline.remaining_ms()
    if rem == UInt64(0):
        return List[ResolvedAddr]()
    var sock = tcp_connect(addr, connect_timeout_ms=rem)
    var fd = sock.raw()
    rem = deadline.remaining_ms()
    _set_rcvtimeo(fd, Int(rem) if rem > UInt64(0) else 1)
    # Length-frame the query.
    var framed = List[UInt8]()
    framed.append(UInt8((len(q) >> 8) & 0xFF))
    framed.append(UInt8(len(q) & 0xFF))
    for i in range(len(q)):
        framed.append(q[i])
    var result = List[ResolvedAddr]()
    if _send_all_tcp(fd, framed) == len(framed):
        var hdr = _recv_n(fd, 2, deadline.absolute_ms())
        if len(hdr) == 2:
            var mlen = (Int(hdr[0]) << 8) | Int(hdr[1])
            if mlen > 0 and mlen <= _MAX_TCP_FRAME:
                var body = _recv_n(fd, mlen, deadline.absolute_ms())
                if len(body) == mlen:
                    result = _parse_a_aaaa_answer(body, txn_id, host, qtype)
    _ = sock.raw()                        # NLL keepalive
    return result^


# ── public API ────────────────────────────────────────────────────────────


def resolve_host_bounded(
    host: String, port: Int, *, timeout_ms: UInt = 5000,
) raises -> List[ResolvedAddr]:
    """Resolve ``host`` to A/AAAA records with a hard wall-clock deadline.

    Fast paths avoid DNS entirely for IPv4/IPv6 literals and ``localhost``.
    For real hostnames, sends parallel A and AAAA queries over UDP/53 with
    distinct anti-spoof transaction ids, collects both answers in a single
    recv loop, falls back to TCP/53 on truncation, and merges results
    AAAA-first (prefer IPv6) with the caller's ``port`` stamped on every
    returned address.

    Raises on empty host, timeout, DNS errors, and zero records -- unlike
    the SVCB resolver, the A/AAAA resolver is on the critical path and
    must surface every failure.
    """
    # ── empty host ────────────────────────────────────────────────
    if host.byte_length() == 0:
        raise "resolve_host_bounded: empty host"

    # ── IPv4 literal fast-path ────────────────────────────────────
    var dotted = IpAddrV4.parse(host)
    if dotted:
        var ip = dotted.value()
        var sa = SocketAddrV4(
            ip.octets[0], ip.octets[1], ip.octets[2], ip.octets[3],
            port=UInt16(port),
        )
        var out = List[ResolvedAddr](capacity=1)
        out.append(ResolvedAddr.from_v4(sa))
        return out^

    # ── IPv6 literal fast-path ────────────────────────────────────
    var stripped = _strip_brackets(host)
    if _has_colon(stripped):
        var segs = _parse_ipv6_segments(stripped)
        if segs:
            ref s = segs.value()
            var sa = SocketAddrV6(
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                port=UInt16(port),
            )
            var out = List[ResolvedAddr](capacity=1)
            out.append(ResolvedAddr.from_v6(sa))
            return out^

    # ── localhost fast-path ───────────────────────────────────────
    if host.lower() == String("localhost"):
        var out = List[ResolvedAddr](capacity=2)
        out.append(ResolvedAddr.from_v6(
            SocketAddrV6(0, 0, 0, 0, 0, 0, 0, 1, port=UInt16(port)),
        ))
        out.append(ResolvedAddr.from_v4(
            SocketAddrV4(127, 0, 0, 1, port=UInt16(port)),
        ))
        return out^

    # ── real DNS resolution ───────────────────────────────────────
    var deadline = _Deadline.from_timeout_ms(timeout_ms)

    var ns = _first_nameserver()
    var ns_addrs = resolve_host(ns, 53)
    if len(ns_addrs) == 0:
        raise "resolve_host_bounded: no nameserver addresses"

    var sock = udp_connect(ns_addrs[0])
    var fd = sock.raw()
    var rem = Int(deadline.remaining_ms())
    _set_rcvtimeo(fd, rem if rem > 0 else 1)

    # Two distinct anti-spoof transaction ids.
    var txn_a = _random_txn_id()
    var txn_aaaa = _random_txn_id()
    while txn_aaaa == txn_a:
        txn_aaaa = _random_txn_id()

    # Send both queries on the same UDP socket.
    var q_a = _build_query(host, txn_a, _QTYPE_A)
    var q_aaaa = _build_query(host, txn_aaaa, _QTYPE_AAAA)
    _ = _send_dgram(fd, q_a)
    _ = _send_dgram(fd, q_aaaa)

    # ── recv loop: collect both A and AAAA answers ────────────────
    var got_a = False
    var got_aaaa = False
    var results_a = List[ResolvedAddr]()
    var results_aaaa = List[ResolvedAddr]()
    var need_tcp_a = False
    var need_tcp_aaaa = False
    var rcode_err = String("")

    while not deadline.is_expired() and (not got_a or not got_aaaa):
        var loop_rem = Int(deadline.remaining_ms())
        _set_rcvtimeo(fd, loop_rem if loop_rem > 0 else 1)
        var dg = _recv_dgram(fd, 65536)
        if len(dg) == 0:
            continue                              # timeout slice / empty
        if len(dg) < 12:
            continue                              # garbled

        # Identify which query this response belongs to.
        var rxn = (UInt16(dg[0]) << 8) | UInt16(dg[1])
        var is_a = not got_a and rxn == txn_a
        var is_aaaa = not got_aaaa and rxn == txn_aaaa
        if not is_a and not is_aaaa:
            continue                              # spoofed/stray

        # QR must be 1 (response).
        if (Int(dg[2]) & 0x80) == 0:
            continue

        # TC=1 -> mark for TCP fallback.
        if (Int(dg[2]) & 0x02) != 0:
            if is_a:
                need_tcp_a = True
                got_a = True
            else:
                need_tcp_aaaa = True
                got_aaaa = True
            continue

        # Non-zero rcode -> legitimate negative answer; done for this type.
        var rcode = Int(dg[3]) & 0x0F
        if rcode != 0:
            if rcode_err.byte_length() == 0:
                rcode_err = String("resolve_host_bounded(") + host + "): rcode=" + String(rcode)
            if is_a:
                got_a = True
            else:
                got_aaaa = True
            continue

        # Parse the answer body.
        if is_a:
            results_a = _parse_a_aaaa_answer(dg, txn_a, host, _QTYPE_A)
            got_a = True
        else:
            results_aaaa = _parse_a_aaaa_answer(dg, txn_aaaa, host, _QTYPE_AAAA)
            got_aaaa = True

    _ = sock.raw()                                # NLL keepalive past recv loop

    # ── TCP fallback for truncated answers ────────────────────────
    if need_tcp_a and not deadline.is_expired():
        try:
            results_a = _query_a_aaaa_tcp(
                ns_addrs[0], host, txn_a, _QTYPE_A, deadline,
            )
        except:
            pass                                  # TCP failure -> no A records

    if need_tcp_aaaa and not deadline.is_expired():
        try:
            results_aaaa = _query_a_aaaa_tcp(
                ns_addrs[0], host, txn_aaaa, _QTYPE_AAAA, deadline,
            )
        except:
            pass                                  # TCP failure -> no AAAA records

    # ── merge: AAAA first (prefer IPv6), then A ──────────────────
    var out = List[ResolvedAddr]()
    for i in range(len(results_aaaa)):
        var segs = results_aaaa[i].v6.ip.segments
        out.append(ResolvedAddr.from_v6(SocketAddrV6(
            segs[0], segs[1], segs[2], segs[3],
            segs[4], segs[5], segs[6], segs[7],
            port=UInt16(port),
        )))
    for i in range(len(results_a)):
        var oct = results_a[i].v4.ip.octets
        out.append(ResolvedAddr.from_v4(SocketAddrV4(
            oct[0], oct[1], oct[2], oct[3],
            port=UInt16(port),
        )))

    if len(out) == 0:
        if deadline.is_expired():
            raise "resolve_host_bounded(" + host + "): timeout"
        if rcode_err.byte_length() > 0:
            raise rcode_err
        raise "resolve_host_bounded(" + host + "): no A/AAAA records"

    return out^
