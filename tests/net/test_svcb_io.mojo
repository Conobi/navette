"""test_svcb_io.mojo — svcb.mojo over real sockets via a forked fake DNS server."""

from std.ffi import external_call
from std.testing import assert_equal, assert_true

from navette.util.owned_alloc import Owned
from navette.net.resolver import resolve_host
from navette.net._dns_wire import _monotonic_ms
from navette.net.svcb import _query_udp


struct _Bound(Copyable, Movable):
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
    """sockaddr_in for 127.0.0.1:port (16 bytes)."""
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


def _serve_udp_once(udp_fd: Int32, answer: List[UInt8]) raises:
    """recvfrom one query, sendto the canned answer back to the sender."""
    var rbuf = Owned[UInt8](65536)
    var sa = Owned[UInt8](16)
    var sl = Owned[Int32](1)
    sl.ptr()[0] = Int32(16)
    var n = external_call["recvfrom", Int](
        udp_fd, rbuf.ptr(), 65536, Int32(0), sa.ptr(), sl.ptr()
    )
    _ = n
    var obuf = Owned[UInt8](len(answer))
    for i in range(len(answer)):
        obuf.ptr()[i] = answer[i]
    _ = external_call["sendto", Int](
        udp_fd, obuf.ptr(), len(answer), Int32(0), sa.ptr(), Int32(16)
    )


def _fork() -> Int32:
    return external_call["fork", Int32]()


def _waitpid(pid: Int32):
    var st = Owned[Int32](1)
    _ = external_call["waitpid", Int32](pid, st.ptr(), Int32(0))


def _kill(pid: Int32):
    _ = external_call["kill", Int32](pid, Int32(9))


def _canned_h3_answer() -> List[UInt8]:
    # Reuse the question/answer shape: example.com, prio 1, alpn=h3, ttl=60.
    # (Mirror of test_svcb._mk_answer; inlined to keep this file standalone.)
    var a = List[UInt8]()
    a.append(UInt8(0x12)); a.append(UInt8(0x34))
    a.append(UInt8(0x80)); a.append(UInt8(0x80))
    a.append(UInt8(0x00)); a.append(UInt8(0x01))
    a.append(UInt8(0x00)); a.append(UInt8(0x01))
    a.append(UInt8(0x00)); a.append(UInt8(0x00))
    a.append(UInt8(0x00)); a.append(UInt8(0x00))
    var parts = List[String]()
    parts.append(String("example")); parts.append(String("com"))
    for i in range(len(parts)):
        var t = parts[i].as_bytes()
        a.append(UInt8(len(t)))
        for k in range(len(t)):
            a.append(t[k])
    a.append(UInt8(0))
    a.append(UInt8(0x00)); a.append(UInt8(65))
    a.append(UInt8(0x00)); a.append(UInt8(1))
    a.append(UInt8(0xC0)); a.append(UInt8(0x0C))
    a.append(UInt8(0x00)); a.append(UInt8(65))
    a.append(UInt8(0x00)); a.append(UInt8(1))
    a.append(UInt8(0x00)); a.append(UInt8(0x00)); a.append(UInt8(0x00)); a.append(UInt8(0x3C))
    # RDLEN = 10: priority(2) + target "."(1) + key(2) + vlen(2) + alpn-value(3)
    a.append(UInt8(0x00)); a.append(UInt8(10))
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # priority=1
    a.append(UInt8(0x00))                          # target="."
    a.append(UInt8(0x00)); a.append(UInt8(0x01))  # key=1
    a.append(UInt8(0x00)); a.append(UInt8(0x03))  # len=3
    a.append(UInt8(0x02)); a.append(UInt8(0x68)); a.append(UInt8(0x33))  # "h3"
    return a^


def test_udp_roundtrip_returns_record() raises:
    var b = _bind_loopback()
    var pid = _fork()
    if pid == 0:
        # child: close stdio so the test's stdout pipe is not inherited
        _ = external_call["close", Int32](Int32(0))
        _ = external_call["close", Int32](Int32(1))
        _ = external_call["close", Int32](Int32(2))
        # serve one UDP query then exit
        try:
            _serve_udp_once(b.udp_fd, _canned_h3_answer())
        except:
            pass
        _ = external_call["_exit", Int32](Int32(0))
    # parent: close TCP fd we don't need, run the client
    _ = external_call["close", Int32](b.tcp_fd)
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var rec = _query_udp(addr[0], String("example.com"), UInt16(0x1234), _monotonic_ms() + UInt64(1500))
    _waitpid(pid)
    _ = external_call["close", Int32](b.udp_fd)
    assert_true(Bool(rec))
    ref r = rec.value()
    assert_equal(r.alpns[0], String("h3"))


def test_udp_timeout_returns_none() raises:
    # No server replies → the recv loop hits its deadline → None (timeout).
    var b = _bind_loopback()
    _ = external_call["close", Int32](b.tcp_fd)
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var rec = _query_udp(addr[0], String("example.com"), UInt16(0x1234), _monotonic_ms() + UInt64(150))
    _ = external_call["close", Int32](b.udp_fd)
    assert_true(not rec)


def _serve_udp_tc_then_tcp(b: _Bound, tcp_answer: List[UInt8]) raises:
    """Reply TC=1 to the UDP query, then serve the full answer over TCP."""
    # UDP: receive the query and echo it back with TC=1 set.
    var rbuf = Owned[UInt8](65536)
    var sa = Owned[UInt8](16)
    var sl = Owned[Int32](1)
    sl.ptr()[0] = Int32(16)
    var n = external_call["recvfrom", Int](
        b.udp_fd, rbuf.ptr(), 65536, Int32(0), sa.ptr(), sl.ptr()
    )
    _ = n
    # copy the query bytes and force TC=1 (QR=1 | TC=1), RA=1 in flags
    var tc = List[UInt8]()
    for i in range(Int(n)):
        tc.append(rbuf.ptr()[i])
    tc[2] = UInt8(0x80 | 0x02)   # QR=1, TC=1
    tc[3] = UInt8(0x80)          # RA=1, rcode=0
    var ob = Owned[UInt8](len(tc))
    for i in range(len(tc)):
        ob.ptr()[i] = tc[i]
    _ = external_call["sendto", Int](
        b.udp_fd, ob.ptr(), len(tc), Int32(0), sa.ptr(), Int32(16)
    )
    # TCP: accept, read 2-byte length + query, reply with length-framed answer.
    var pa = Owned[UInt8](16)
    var pl = Owned[Int32](1)
    pl.ptr()[0] = Int32(16)
    var cfd = external_call["accept", Int32](b.tcp_fd, pa.ptr(), pl.ptr())
    if cfd < 0:
        raise "accept failed"
    var hdr = Owned[UInt8](2)
    _ = external_call["recv", Int](cfd, hdr.ptr(), 2, Int32(0))
    var qlen = Int(hdr.ptr()[0]) * 256 + Int(hdr.ptr()[1])
    var qb = Owned[UInt8](qlen if qlen > 0 else 1)
    _ = external_call["recv", Int](cfd, qb.ptr(), qlen, Int32(0))
    var framed = List[UInt8]()
    framed.append(UInt8((len(tcp_answer) >> 8) & 0xFF))
    framed.append(UInt8(len(tcp_answer) & 0xFF))
    for i in range(len(tcp_answer)):
        framed.append(tcp_answer[i])
    var fb = Owned[UInt8](len(framed))
    for i in range(len(framed)):
        fb.ptr()[i] = framed[i]
    _ = external_call["send", Int](cfd, fb.ptr(), len(framed), Int32(0x4000))
    _ = external_call["close", Int32](cfd)


def test_tc_bit_triggers_tcp_fallback() raises:
    var b = _bind_loopback()
    var pid = _fork()
    if pid == 0:
        # child: close stdio so the test's stdout pipe is not inherited
        _ = external_call["close", Int32](Int32(0))
        _ = external_call["close", Int32](Int32(1))
        _ = external_call["close", Int32](Int32(2))
        try:
            _serve_udp_tc_then_tcp(b, _canned_h3_answer())
        except:
            pass
        _ = external_call["_exit", Int32](Int32(0))
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var rec = _query_udp(addr[0], String("example.com"), UInt16(0x1234), _monotonic_ms() + UInt64(2000))
    _waitpid(pid)
    _ = external_call["close", Int32](b.udp_fd)
    _ = external_call["close", Int32](b.tcp_fd)
    assert_true(Bool(rec))
    ref r = rec.value()
    assert_equal(r.alpns[0], String("h3"))


def _serve_udp_tc_then_stall_tcp(b: _Bound, hold_us: UInt32 = UInt32(1_000_000)) raises:
    """Reply TC=1 to the UDP query, hold the accepted TCP connection open, then exit.

    After `accept()` the child sleeps for `hold_us` microseconds before calling
    `_exit(0)`, keeping the connection alive without writing any data.  This forces
    the parent's `_recv_n` (waiting for the 2-byte length header) to block until
    SO_RCVTIMEO fires — which, with the shared deadline, is the time remaining from
    the total budget rather than a fresh per-phase allowance.  The sleep is bounded
    so the test runner never hangs regardless of how the parent times out.
    """
    var rbuf = Owned[UInt8](65536)
    var sa = Owned[UInt8](16)
    var sl = Owned[Int32](1)
    sl.ptr()[0] = Int32(16)
    var n = external_call["recvfrom", Int](
        b.udp_fd, rbuf.ptr(), 65536, Int32(0), sa.ptr(), sl.ptr()
    )
    # Echo the query back with TC=1 + QR=1 set.
    var tc = List[UInt8]()
    for i in range(Int(n)):
        tc.append(rbuf.ptr()[i])
    tc[2] = UInt8(0x80 | 0x02)   # QR=1, TC=1
    tc[3] = UInt8(0x80)           # RA=1, rcode=0
    var ob = Owned[UInt8](len(tc))
    for i in range(len(tc)):
        ob.ptr()[i] = tc[i]
    _ = external_call["sendto", Int](
        b.udp_fd, ob.ptr(), len(tc), Int32(0), sa.ptr(), Int32(16)
    )
    # Accept the TCP connection, hold it open without writing so the parent's
    # recv genuinely blocks until its SO_RCVTIMEO deadline fires.
    var pa = Owned[UInt8](16)
    var pl = Owned[Int32](1)
    pl.ptr()[0] = Int32(16)
    _ = external_call["accept", Int32](b.tcp_fd, pa.ptr(), pl.ptr())
    # Sleep for hold_us µs (longer than the test timeout) so the connection
    # stays open and unwritten; the parent must time out via SO_RCVTIMEO, not EOF.
    _ = external_call["usleep", Int32](hold_us)
    _ = external_call["_exit", Int32](Int32(0))


def test_total_deadline_bounds_tcp_stall() raises:
    # TC=1 triggers TCP fallback; the fake TCP server accepts but holds the
    # connection open without writing for 2 × timeout_ms.  The parent's _recv_n
    # genuinely blocks until SO_RCVTIMEO fires (set to the time remaining from the
    # shared deadline), so elapsed ≈ 1 × timeout_ms.  Per-phase code that sets
    # SO_RCVTIMEO to a fresh timeout_ms on each recv — or omits it entirely —
    # would block until the child exits (~2 × timeout_ms), failing the < 1.5 × bound.
    var timeout_ms = UInt64(500)
    var b = _bind_loopback()
    var pid = _fork()
    if pid == 0:
        _ = external_call["close", Int32](Int32(0))
        _ = external_call["close", Int32](Int32(1))
        _ = external_call["close", Int32](Int32(2))
        try:
            # hold_us = 2 × timeout_ms so the child outlasts the parent's deadline,
            # keeping the connection open until SO_RCVTIMEO fires.
            _serve_udp_tc_then_stall_tcp(b, UInt32(1_000_000))
        except:
            pass
        _ = external_call["_exit", Int32](Int32(0))
    var t0 = _monotonic_ms()
    var addr = resolve_host(String("127.0.0.1"), b.port)
    var deadline = t0 + timeout_ms
    var rec = _query_udp(addr[0], String("example.com"), UInt16(0x1234), deadline)
    var elapsed = _monotonic_ms() - t0
    _waitpid(pid)
    _ = external_call["close", Int32](b.udp_fd)
    _ = external_call["close", Int32](b.tcp_fd)
    assert_true(not rec)                          # stalled server → no response
    assert_true(elapsed < timeout_ms * 3 / 2)    # shared deadline: < 1.5 × timeout


def main() raises:
    test_udp_roundtrip_returns_record()
    test_udp_timeout_returns_none()
    test_tc_bit_triggers_tcp_fallback()
    test_total_deadline_bounds_tcp_stall()
    print("All test_svcb_io UDP + TCP tests passed.")
