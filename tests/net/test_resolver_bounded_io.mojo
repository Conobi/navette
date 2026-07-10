"""test_resolver_bounded_io.mojo — bounded resolver over real sockets via a forked fake DNS server."""

from std.ffi import external_call
from std.testing import assert_equal, assert_true

from navette.util.owned_alloc import Owned
from navette.net.resolver import resolve_host, ResolvedAddr
from navette.net._dns_wire import (
    _encode_qname, _build_query, _send_dgram, _recv_dgram,
    _set_rcvtimeo, _monotonic_ms,
)
from navette.net.resolver_bounded import _parse_a_aaaa_answer
from navette.runtime.socket_helpers import udp_connect


# ── socket binding helpers ────────────────────────────────────────────────


struct _Bound(Copyable, Movable):
    """A pair of bound UDP + TCP file descriptors sharing the same loopback port."""

    var udp_fd: Int32
    var tcp_fd: Int32
    var port: Int

    def __init__(out self, udp_fd: Int32, tcp_fd: Int32, port: Int):
        self.udp_fd = udp_fd
        self.tcp_fd = tcp_fd
        self.port = port

    def __init__(out self, *, other: Self):
        self.udp_fd = other.udp_fd
        self.tcp_fd = other.tcp_fd
        self.port = other.port

    def __init__(out self, *, deinit take: Self):
        self.udp_fd = take.udp_fd
        self.tcp_fd = take.tcp_fd
        self.port = take.port


def _loopback_sockaddr(port: Int) -> Owned[UInt8]:
    """Build a sockaddr_in for 127.0.0.1:port (16 bytes, AF_INET)."""
    var a = Owned[UInt8](16)
    var p = a.ptr()
    for i in range(16):
        p[i] = UInt8(0)
    p[0] = UInt8(2)                          # AF_INET (LE)
    p[2] = UInt8((port >> 8) & 0xFF)         # port (BE)
    p[3] = UInt8(port & 0xFF)
    p[4] = UInt8(127); p[5] = UInt8(0); p[6] = UInt8(0); p[7] = UInt8(1)
    return a^


def _bind_loopback() raises -> _Bound:
    """Bind a UDP socket on 127.0.0.1:0, then a TCP listener on the same port."""
    var ufd = external_call["socket", Int32](Int32(2), Int32(2), Int32(0))  # DGRAM
    if ufd < 0:
        raise "socket(udp) failed"
    var ua = _loopback_sockaddr(0)
    if external_call["bind", Int32](ufd, ua.ptr(), Int32(16)) < 0:
        raise "bind(udp) failed"
    # read the bound port
    var na = Owned[UInt8](16)
    var nl = Owned[Int32](1)
    nl.ptr()[0] = Int32(16)
    _ = external_call["getsockname", Int32](ufd, na.ptr(), nl.ptr())
    var port = Int(na.ptr()[2]) * 256 + Int(na.ptr()[3])
    var tfd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))  # STREAM
    if tfd < 0:
        raise "socket(tcp) failed"
    var ov = Owned[Int32](1)
    ov.ptr()[0] = Int32(1)
    _ = external_call["setsockopt", Int32](tfd, Int32(1), Int32(2), ov.ptr(), Int32(4))
    var ta = _loopback_sockaddr(port)
    if external_call["bind", Int32](tfd, ta.ptr(), Int32(16)) < 0:
        raise "bind(tcp) failed"
    _ = external_call["listen", Int32](tfd, Int32(1))
    return _Bound(ufd, tfd, port)


# ── process helpers ───────────────────────────────────────────────────────


def _fork() -> Int32:
    """Fork the current process; returns 0 in the child, pid in the parent."""
    return external_call["fork", Int32]()


def _waitpid(pid: Int32):
    """Block until the child process exits."""
    var st = Owned[Int32](1)
    _ = external_call["waitpid", Int32](pid, st.ptr(), Int32(0))


def _kill(pid: Int32):
    """Send SIGKILL to a child process."""
    _ = external_call["kill", Int32](pid, Int32(9))


def _close_stdio():
    """Close stdin/stdout/stderr so the test runner's pipe is not inherited."""
    _ = external_call["close", Int32](Int32(0))
    _ = external_call["close", Int32](Int32(1))
    _ = external_call["close", Int32](Int32(2))


# ── DNS response builders ─────────────────────────────────────────────────


def _build_a_answer(
    qid_hi: UInt8, qid_lo: UInt8, host: String, ip_bytes: List[UInt8],
) -> List[UInt8]:
    """Build a minimal DNS A answer: header + question + 1 A RR.

    The response echoes the given transaction id (qid_hi:qid_lo), includes
    the question section for `host` with QTYPE=A/QCLASS=IN, and a single
    answer RR with the 4-byte IPv4 address from `ip_bytes`.
    """
    var a = List[UInt8]()
    # Header (12 bytes)
    a.append(qid_hi); a.append(qid_lo)
    a.append(UInt8(0x80)); a.append(UInt8(0x80))  # QR=1, RA=1, rcode=0
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QDCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # ANCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # NSCOUNT=0
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # ARCOUNT=0
    # Question section: QNAME + QTYPE(A=1) + QCLASS(IN=1)
    var qn = _encode_qname(host)
    for i in range(len(qn)):
        a.append(qn[i])
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QTYPE=A
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QCLASS=IN
    # Answer RR: compressed NAME + TYPE(A) + CLASS(IN) + TTL(60) + RDLEN(4) + RDATA
    a.append(UInt8(0xC0)); a.append(UInt8(0x0C))  # NAME -> offset 12
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # TYPE=A
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # CLASS=IN
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # TTL hi
    a.append(UInt8(0x00)); a.append(UInt8(0x3C))  # TTL lo (60)
    a.append(UInt8(0x00)); a.append(UInt8(0x04))  # RDLENGTH=4
    for i in range(4):
        a.append(ip_bytes[i])
    return a^


def _build_aaaa_answer(
    qid_hi: UInt8, qid_lo: UInt8, host: String, ip_bytes: List[UInt8],
) -> List[UInt8]:
    """Build a minimal DNS AAAA answer: header + question + 1 AAAA RR.

    Same structure as `_build_a_answer` but QTYPE=28 (AAAA) and 16-byte
    RDATA for the IPv6 address.
    """
    var a = List[UInt8]()
    # Header (12 bytes)
    a.append(qid_hi); a.append(qid_lo)
    a.append(UInt8(0x80)); a.append(UInt8(0x80))  # QR=1, RA=1, rcode=0
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QDCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # ANCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # NSCOUNT=0
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # ARCOUNT=0
    # Question section: QNAME + QTYPE(AAAA=28) + QCLASS(IN=1)
    var qn = _encode_qname(host)
    for i in range(len(qn)):
        a.append(qn[i])
    a.append(UInt8(0x00)); a.append(UInt8(0x1C))  # QTYPE=AAAA (28)
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QCLASS=IN
    # Answer RR: compressed NAME + TYPE(AAAA) + CLASS(IN) + TTL(60) + RDLEN(16) + RDATA
    a.append(UInt8(0xC0)); a.append(UInt8(0x0C))  # NAME -> offset 12
    a.append(UInt8(0x00)); a.append(UInt8(0x1C))  # TYPE=AAAA (28)
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # CLASS=IN
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # TTL hi
    a.append(UInt8(0x00)); a.append(UInt8(0x3C))  # TTL lo (60)
    a.append(UInt8(0x00)); a.append(UInt8(0x10))  # RDLENGTH=16
    for i in range(16):
        a.append(ip_bytes[i])
    return a^


def _build_nxdomain_answer(
    qid_hi: UInt8, qid_lo: UInt8, host: String, qtype: Int,
) -> List[UInt8]:
    """Build an NXDOMAIN DNS response (rcode=3, ANCOUNT=0).

    Contains a valid header and echoed question section with the given
    QTYPE, but no answer RRs.  Used to verify that `_parse_a_aaaa_answer`
    correctly rejects non-zero rcodes.
    """
    var a = List[UInt8]()
    # Header (12 bytes) — rcode=3 (NXDOMAIN)
    a.append(qid_hi); a.append(qid_lo)
    a.append(UInt8(0x80)); a.append(UInt8(0x83))  # QR=1, RA=1, rcode=3
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QDCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # ANCOUNT=0
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # NSCOUNT=0
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # ARCOUNT=0
    # Question section: QNAME + QTYPE + QCLASS(IN=1)
    var qn = _encode_qname(host)
    for i in range(len(qn)):
        a.append(qn[i])
    a.append(UInt8((qtype >> 8) & 0xFF))
    a.append(UInt8(qtype & 0xFF))
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QCLASS=IN
    return a^


# ── fake server ───────────────────────────────────────────────────────────


def _serve_a_aaaa_queries(udp_fd: Int32, host: String) raises:
    """Read 2 DNS queries via recvfrom, reply with canned A or AAAA answers.

    Inspects the QTYPE field in each incoming query to determine the
    response type.  Uses canned addresses:
      A:    93.184.216.34
      AAAA: 2606:2800:0220:0001::248e
    """
    var ip4 = List[UInt8]()
    ip4.append(UInt8(93)); ip4.append(UInt8(184))
    ip4.append(UInt8(216)); ip4.append(UInt8(34))

    var ip6 = List[UInt8]()
    ip6.append(UInt8(0x26)); ip6.append(UInt8(0x06))
    ip6.append(UInt8(0x28)); ip6.append(UInt8(0x00))
    ip6.append(UInt8(0x02)); ip6.append(UInt8(0x20))
    ip6.append(UInt8(0x00)); ip6.append(UInt8(0x01))
    ip6.append(UInt8(0x00)); ip6.append(UInt8(0x00))
    ip6.append(UInt8(0x00)); ip6.append(UInt8(0x00))
    ip6.append(UInt8(0x00)); ip6.append(UInt8(0x00))
    ip6.append(UInt8(0x24)); ip6.append(UInt8(0x8E))

    for _round in range(2):
        var rbuf = Owned[UInt8](65536)
        var sa = Owned[UInt8](16)
        var sl = Owned[Int32](1)
        sl.ptr()[0] = Int32(16)
        var n = external_call["recvfrom", Int](
            udp_fd, rbuf.ptr(), 65536, Int32(0), sa.ptr(), sl.ptr()
        )
        if n < 14:
            continue

        # Extract transaction id from the query.
        var qid_hi = rbuf.ptr()[0]
        var qid_lo = rbuf.ptr()[1]

        # Walk the QNAME labels (starting at offset 12) to find QTYPE.
        var pos = 12
        while pos < n:
            var label_len = Int(rbuf.ptr()[pos])
            if label_len == 0:
                pos += 1
                break
            pos += 1 + label_len
        # QTYPE is the 2 bytes right after the QNAME terminator.
        var qtype = 0
        if pos + 1 < n:
            qtype = Int(rbuf.ptr()[pos]) * 256 + Int(rbuf.ptr()[pos + 1])

        # Build the appropriate response.
        var answer: List[UInt8]
        if qtype == 28:
            answer = _build_aaaa_answer(qid_hi, qid_lo, host, ip6)
        else:
            answer = _build_a_answer(qid_hi, qid_lo, host, ip4)

        # Send the response back to the client.
        var obuf = Owned[UInt8](len(answer))
        for i in range(len(answer)):
            obuf.ptr()[i] = answer[i]
        _ = external_call["sendto", Int](
            udp_fd, obuf.ptr(), len(answer), Int32(0), sa.ptr(), Int32(16)
        )


# ── tests ─────────────────────────────────────────────────────────────────


def test_a_aaaa_roundtrip() raises:
    """Fork a fake DNS server, send A+AAAA queries, parse responses."""
    var b = _bind_loopback()
    var pid = _fork()
    if pid == 0:
        _close_stdio()
        try:
            _serve_a_aaaa_queries(b.udp_fd, String("example.com"))
        except:
            pass
        _ = external_call["_exit", Int32](Int32(0))
    # Parent: close TCP fd we don't need.
    _ = external_call["close", Int32](b.tcp_fd)
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var sock = udp_connect(addr[0])
    var fd = sock.raw()
    _set_rcvtimeo(fd, 1500)

    # Send A query with fixed txn-id 0x1111.
    var q_a = _build_query(String("example.com"), UInt16(0x1111), 1)
    _ = _send_dgram(fd, q_a)

    # Send AAAA query with fixed txn-id 0x2222.
    var q_aaaa = _build_query(String("example.com"), UInt16(0x2222), 28)
    _ = _send_dgram(fd, q_aaaa)

    # Receive and parse both responses (order may vary).
    var results_a = List[ResolvedAddr]()
    var results_aaaa = List[ResolvedAddr]()
    var got_a = False
    var got_aaaa = False

    for _attempt in range(4):
        if got_a and got_aaaa:
            break
        var dg = _recv_dgram(fd, 65536)
        if len(dg) < 12:
            continue
        var rxn = (UInt16(dg[0]) << 8) | UInt16(dg[1])
        if rxn == UInt16(0x1111) and not got_a:
            results_a = _parse_a_aaaa_answer(dg, UInt16(0x1111), String("example.com"), 1)
            got_a = True
        elif rxn == UInt16(0x2222) and not got_aaaa:
            results_aaaa = _parse_a_aaaa_answer(dg, UInt16(0x2222), String("example.com"), 28)
            got_aaaa = True

    _ = sock.raw()  # NLL keepalive
    _waitpid(pid)
    _ = external_call["close", Int32](b.udp_fd)

    # Assert A result: 93.184.216.34
    assert_true(got_a, msg="did not receive A response")
    assert_equal(len(results_a), 1)
    assert_true(results_a[0].is_ipv4())
    assert_equal(Int(results_a[0].v4.ip.octets[0]), 93)
    assert_equal(Int(results_a[0].v4.ip.octets[1]), 184)
    assert_equal(Int(results_a[0].v4.ip.octets[2]), 216)
    assert_equal(Int(results_a[0].v4.ip.octets[3]), 34)

    # Assert AAAA result: 2606:2800:0220:0001::248e
    assert_true(got_aaaa, msg="did not receive AAAA response")
    assert_equal(len(results_aaaa), 1)
    assert_true(results_aaaa[0].is_ipv6())
    assert_equal(Int(results_aaaa[0].v6.ip.segments[0]), 0x2606)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[1]), 0x2800)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[2]), 0x0220)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[3]), 0x0001)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[4]), 0x0000)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[5]), 0x0000)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[6]), 0x0000)
    assert_equal(Int(results_aaaa[0].v6.ip.segments[7]), 0x248E)


def test_black_hole_nameserver_bounded() raises:
    """A server that never replies must not block beyond SO_RCVTIMEO."""
    var b = _bind_loopback()
    var pid = _fork()
    if pid == 0:
        _close_stdio()
        # Child: hold the socket open but never read/reply (black hole).
        _ = external_call["usleep", Int32](UInt32(2_000_000))
        _ = external_call["_exit", Int32](Int32(0))
    # Parent: close TCP fd, send a query, expect recv to timeout.
    _ = external_call["close", Int32](b.tcp_fd)
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var sock = udp_connect(addr[0])
    var fd = sock.raw()
    _set_rcvtimeo(fd, 500)

    var q = _build_query(String("example.com"), UInt16(0x3333), 1)
    var t0 = _monotonic_ms()
    _ = _send_dgram(fd, q)
    var dg = _recv_dgram(fd, 65536)
    var elapsed = _monotonic_ms() - t0

    _ = sock.raw()  # NLL keepalive
    _kill(pid)
    _waitpid(pid)
    _ = external_call["close", Int32](b.udp_fd)

    # Recv should return empty (timeout) within a bounded time.
    assert_equal(len(dg), 0)
    assert_true(elapsed < UInt64(1500), msg="recv took too long: black hole not bounded")


def test_nxdomain_answer() raises:
    """An NXDOMAIN response (rcode=3) must produce an empty result list."""
    var msg = _build_nxdomain_answer(UInt8(0x44), UInt8(0x44), String("nohost.invalid"), 1)
    var results = _parse_a_aaaa_answer(msg, UInt16(0x4444), String("nohost.invalid"), 1)
    assert_equal(len(results), 0)


def test_cname_with_a_record() raises:
    """A response with CNAME + terminal A record must extract only the A."""
    # Build a response: ANCOUNT=2, first RR is CNAME (type 5), second is A (type 1).
    var a = List[UInt8]()
    # Header (12 bytes)
    a.append(UInt8(0x55)); a.append(UInt8(0x55))  # txn id 0x5555
    a.append(UInt8(0x80)); a.append(UInt8(0x80))  # QR=1, RA=1, rcode=0
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QDCOUNT=1
    a.append(UInt8(0x00)); a.append(UInt8(0x02))  # ANCOUNT=2
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # NSCOUNT=0
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # ARCOUNT=0

    # Question section: "example.com" QTYPE=A QCLASS=IN
    var qn = _encode_qname(String("example.com"))
    for i in range(len(qn)):
        a.append(qn[i])
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QTYPE=A
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # QCLASS=IN

    # Answer RR 1: CNAME (type 5) pointing to "www.example.com"
    a.append(UInt8(0xC0)); a.append(UInt8(0x0C))  # NAME -> offset 12
    a.append(UInt8(0x00)); a.append(UInt8(0x05))  # TYPE=CNAME
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # CLASS=IN
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # TTL hi
    a.append(UInt8(0x00)); a.append(UInt8(0x3C))  # TTL lo (60)
    # RDATA: _encode_qname("www.example.com") = [3]www[7]example[3]com[0] = 17 bytes
    var cname_target = _encode_qname(String("www.example.com"))
    a.append(UInt8(0x00)); a.append(UInt8(len(cname_target)))  # RDLENGTH
    for i in range(len(cname_target)):
        a.append(cname_target[i])

    # Answer RR 2: A record (type 1) with IP 93.184.216.34
    a.append(UInt8(0xC0)); a.append(UInt8(0x0C))  # NAME -> offset 12
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # TYPE=A
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # CLASS=IN
    a.append(UInt8(0x00)); a.append(UInt8(0x00))  # TTL hi
    a.append(UInt8(0x00)); a.append(UInt8(0x3C))  # TTL lo (60)
    a.append(UInt8(0x00)); a.append(UInt8(0x04))  # RDLENGTH=4
    a.append(UInt8(93)); a.append(UInt8(184))
    a.append(UInt8(216)); a.append(UInt8(34))

    var results = _parse_a_aaaa_answer(a, UInt16(0x5555), String("example.com"), 1)
    # CNAME is skipped; only the terminal A record is extracted.
    assert_equal(len(results), 1)
    assert_true(results[0].is_ipv4())
    assert_equal(Int(results[0].v4.ip.octets[0]), 93)
    assert_equal(Int(results[0].v4.ip.octets[1]), 184)
    assert_equal(Int(results[0].v4.ip.octets[2]), 216)
    assert_equal(Int(results[0].v4.ip.octets[3]), 34)


def main() raises:
    test_a_aaaa_roundtrip()
    test_black_hole_nameserver_bounded()
    test_nxdomain_answer()
    test_cname_with_a_record()
    print("All test_resolver_bounded_io tests passed.")
