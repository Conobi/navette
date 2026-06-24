"""TCP/UDP socket helpers returning `OwnedHandle`.

Boucle exposes `Socket.tcp_listener_v6` / `Socket.udp_listener_v6` /
`Socket.tcp_connect` / `Socket.udp_connect` for the same roles — but
those return a `Socket` value, and `Socket` is not yet `Movable` in
Boucle (an out-of-scope follow-up in the public API spec). Consumers
that need to either move the handle into a server struct field
(`H1TcpServer`, `H2TcpServer`, `H3UdpServer`) or return it from a
function (`examples/fetch`'s `_connect_tcp_resolved`) cannot use the
Boucle factories directly until then.

These helpers replicate the syscall sequence that the equivalent
`Socket.*` factories perform (dual-stack `[::]:port`, `SO_REUSEADDR +
SO_REUSEPORT`, `IPV6_V6ONLY=0`, `SOCK_NONBLOCK + SOCK_CLOEXEC`, `bind`
+ `listen` for TCP listeners; blocking `connect(2)` for clients) but
hand back an `OwnedHandle` directly. They use only public symbols
from `boucle.*` (`OwnedHandle`, address types via `ResolvedAddr`).

When `Socket` gains a way to extract its underlying `OwnedHandle`
(either by becoming `Movable` or via a consuming `into_handle()`),
delete this module and switch the consumers to the Boucle factories.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from navette.util.owned_alloc import Owned

from boucle.handle import RawHandle, OwnedHandle

from navette.net.resolver import ResolvedAddr


# Linux socket constants — kept private here so consumers never see
# raw level/optname/protocol pairs.
comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10
comptime _SOCK_STREAM: Int32 = 1
comptime _SOCK_DGRAM: Int32 = 2
comptime _SOCK_NONBLOCK: Int32 = 0x800
comptime _SOCK_CLOEXEC: Int32 = 0x80000

comptime _SOL_SOCKET: Int32 = 1
comptime _SO_REUSEADDR: Int32 = 2
comptime _SO_REUSEPORT: Int32 = 15
comptime _IPPROTO_IPV6: Int32 = 41
comptime _IPV6_V6ONLY: Int32 = 26

comptime _SOCKADDR_IN_SIZE: Int32 = 16
comptime _SOCKADDR_IN6_SIZE: Int32 = 28


def _setsockopt_int(
    fd: RawHandle, level: Int32, optname: Int32, value: Int32,
) raises:
    var optval_buf = Owned[Int32](1)
    var optval = optval_buf.ptr()
    optval[0] = value
    var rc = external_call["setsockopt", Int32](
        fd, level, optname, optval, Int32(4),
    )
    if rc < 0:
        raise (
            "setsockopt failed (level="
            + String(Int(level))
            + " optname="
            + String(Int(optname))
            + ")"
        )


# SO_SNDTIMEO optname on Linux. The kernel honors this on a blocking
# socket *before* `connect(2)` — the blocking connect returns EAGAIN/
# EINPROGRESS once the timeout expires, which we surface to the caller
# as `connect() failed`. Setting it BEFORE connect is the cleanest way
# to bound `tcp_connect` / `udp_connect` without restructuring them
# around an O_NONBLOCK + poll loop.
comptime _SO_SNDTIMEO: Int32 = 21


def _setsockopt_so_sndtimeo(fd: RawHandle, ms: Int) raises:
    """Set SO_SNDTIMEO on `fd` (millisecond resolution, tv_sec + tv_usec).

    Used by `tcp_connect` / `udp_connect` when the caller requests a
    connect-timeout: setting SO_SNDTIMEO on a blocking socket before
    `connect(2)` causes the kernel to abort the connect once the wall
    time elapses, returning -1 instead of blocking indefinitely.
    """
    var tv_buf = Owned[UInt8](16)
    var tv = tv_buf.ptr()
    for i in range(16):
        tv[i] = UInt8(0)
    var sec_ptr = tv.bitcast[Int64]()
    sec_ptr[] = Int64(ms // 1000)
    var usec_ptr = UnsafePointer[Int64, MutAnyOrigin](
        unsafe_from_address=Int(tv) + 8
    )
    usec_ptr[] = Int64((ms % 1000) * 1000)
    var rc = external_call["setsockopt", Int32](
        fd, _SOL_SOCKET, _SO_SNDTIMEO, tv, Int32(16),
    )
    if rc < 0:
        raise "setsockopt(SO_SNDTIMEO) failed: rc=" + String(Int(rc))


def tcp_listener(port: Int, backlog: Int = 1024) raises -> OwnedHandle:
    """Create a dual-stack TCP listening socket bound to `[::]:port`.

    Socket flags: `SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC`.
    Layered options: `SO_REUSEADDR + SO_REUSEPORT + IPV6_V6ONLY=0`.

    Caller owns the returned `OwnedHandle` and is responsible for
    keeping it alive across the io_uring loop's lifetime — typically
    by transferring it into the server struct via `^`.
    """
    var fd = external_call["socket", Int32](
        _AF_INET6,
        _SOCK_STREAM | _SOCK_NONBLOCK | _SOCK_CLOEXEC,
        Int32(0),
    )
    if fd < 0:
        raise "tcp_listener: socket() failed"

    var handle = OwnedHandle(raw=fd)

    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEADDR, Int32(1))
    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEPORT, Int32(1))
    _setsockopt_int(handle.raw(), _IPPROTO_IPV6, _IPV6_V6ONLY, Int32(0))

    # Build sockaddr_in6 for [::]:port — 28 bytes:
    #   family(2) + port(2 big-endian) + flowinfo(4) + addr(16) + scope_id(4).
    var addr_buf = Owned[UInt8](Int(_SOCKADDR_IN6_SIZE))
    var addr = addr_buf.ptr()
    for i in range(Int(_SOCKADDR_IN6_SIZE)):
        addr[i] = 0
    addr[0] = 10  # sin6_family = AF_INET6 (LE u16)
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    var rc = external_call["bind", Int32](
        handle.raw(), addr, _SOCKADDR_IN6_SIZE,
    )
    if rc < 0:
        raise "tcp_listener: bind() failed on port " + String(port)

    var lrc = external_call["listen", Int32](handle.raw(), Int32(backlog))
    if lrc < 0:
        raise "tcp_listener: listen() failed"

    return handle^


def tcp_v4_nonblocking() raises -> OwnedHandle:
    """Create a non-blocking TCP IPv4 socket. Bare fd; no bind/connect.

    Equivalent to `Socket.tcp_v4()` but returns an `OwnedHandle` (rather
    than the non-Movable `Socket`). Use when you need to hand the fd
    to an io_uring submission and own it via RAII in a struct field.
    """
    var fd = external_call["socket", Int32](
        _AF_INET,
        _SOCK_STREAM | _SOCK_NONBLOCK | _SOCK_CLOEXEC,
        Int32(0),
    )
    if fd < 0:
        raise "tcp_v4_nonblocking: socket() failed"
    return OwnedHandle(raw=fd)


def _pack_v4(addr: ResolvedAddr, dst: UnsafePointer[UInt8, MutAnyOrigin]) -> Int32:
    """Pack a `ResolvedAddr` (IPv4) into a `sockaddr_in` byte buffer."""
    # sockaddr_in (16 bytes): family(2 LE) port(2 BE) addr(4) zero(8)
    for i in range(Int(_SOCKADDR_IN_SIZE)):
        dst[i] = UInt8(0)
    dst[0] = UInt8(2)  # AF_INET (LE u16 lo byte)
    var port = Int(addr.v4.port)
    dst[2] = UInt8((port >> 8) & 0xFF)
    dst[3] = UInt8(port & 0xFF)
    var oct = addr.v4.ip.octets
    dst[4] = oct[0]
    dst[5] = oct[1]
    dst[6] = oct[2]
    dst[7] = oct[3]
    return _SOCKADDR_IN_SIZE


def _pack_v6(addr: ResolvedAddr, dst: UnsafePointer[UInt8, MutAnyOrigin]) -> Int32:
    """Pack a `ResolvedAddr` (IPv6) into a `sockaddr_in6` byte buffer."""
    # sockaddr_in6 (28 bytes): family(2 LE) port(2 BE) flowinfo(4) addr(16) scope_id(4)
    for i in range(Int(_SOCKADDR_IN6_SIZE)):
        dst[i] = UInt8(0)
    dst[0] = UInt8(10)  # AF_INET6 (LE u16 lo byte)
    var port = Int(addr.v6.port)
    dst[2] = UInt8((port >> 8) & 0xFF)
    dst[3] = UInt8(port & 0xFF)
    # 8 segments of 16 bits in network (big-endian) order at offset 8.
    var segs = addr.v6.ip.segments
    for i in range(8):
        var s = Int(segs[i])
        dst[8 + 2 * i] = UInt8((s >> 8) & 0xFF)
        dst[8 + 2 * i + 1] = UInt8(s & 0xFF)
    # scope_id at offset 24 (LE u32)
    var scope = Int(addr.v6.scope_id)
    dst[24] = UInt8(scope & 0xFF)
    dst[25] = UInt8((scope >> 8) & 0xFF)
    dst[26] = UInt8((scope >> 16) & 0xFF)
    dst[27] = UInt8((scope >> 24) & 0xFF)
    return _SOCKADDR_IN6_SIZE


def tcp_connect(
    addr: ResolvedAddr, *, connect_timeout_ms: UInt64 = UInt64(0),
) raises -> OwnedHandle:
    """Open a blocking TCP socket and connect it to `addr`.

    Picks `AF_INET` vs `AF_INET6` from the `ResolvedAddr` tag. Socket
    flags: `SOCK_STREAM | SOCK_CLOEXEC` (no `SOCK_NONBLOCK` — callers
    using blocking send/recv get the simpler programming model).

    When `connect_timeout_ms > 0`, sets `SO_SNDTIMEO` on the socket
    before `connect(2)` so a non-routable peer cannot pin the call
    indefinitely. `0` (the default) means "no timeout" for backward
    compatibility.
    """
    var family = _AF_INET if addr.is_ipv4() else _AF_INET6
    var fd = external_call["socket", Int32](
        family, _SOCK_STREAM | _SOCK_CLOEXEC, Int32(0),
    )
    if fd < 0:
        raise "tcp_connect: socket() failed"
    var handle = OwnedHandle(raw=fd)

    if connect_timeout_ms > UInt64(0):
        _setsockopt_so_sndtimeo(handle.raw(), Int(connect_timeout_ms))

    var buf_owner = Owned[UInt8](Int(_SOCKADDR_IN6_SIZE))
    var buf = buf_owner.ptr()
    var n: Int32
    if addr.is_ipv4():
        n = _pack_v4(addr, buf)
    else:
        n = _pack_v6(addr, buf)
    var rc = external_call["connect", Int32](handle.raw(), buf, n)
    if rc < 0:
        raise "tcp_connect: connect() failed: rc=" + String(Int(rc))
    return handle^


def udp_connect(
    addr: ResolvedAddr, *, connect_timeout_ms: UInt64 = UInt64(0),
) raises -> OwnedHandle:
    """Open a blocking UDP socket "connected" to `addr`.

    `connect(2)` on a datagram socket pins the peer address so
    subsequent `send(2)` / `recv(2)` calls skip the per-call addr
    argument and only deliver datagrams from that peer. Picks
    `AF_INET` vs `AF_INET6` from the `ResolvedAddr` tag. Socket
    flags: `SOCK_DGRAM | SOCK_CLOEXEC`.

    When `connect_timeout_ms > 0`, sets `SO_SNDTIMEO` before connect.
    UDP `connect(2)` is normally instantaneous (no handshake) but the
    kwarg is mirrored from `tcp_connect` for API symmetry.
    """
    var family = _AF_INET if addr.is_ipv4() else _AF_INET6
    var fd = external_call["socket", Int32](
        family, _SOCK_DGRAM | _SOCK_CLOEXEC, Int32(0),
    )
    if fd < 0:
        raise "udp_connect: socket() failed"
    var handle = OwnedHandle(raw=fd)

    if connect_timeout_ms > UInt64(0):
        _setsockopt_so_sndtimeo(handle.raw(), Int(connect_timeout_ms))

    var buf_owner = Owned[UInt8](Int(_SOCKADDR_IN6_SIZE))
    var buf = buf_owner.ptr()
    var n: Int32
    if addr.is_ipv4():
        n = _pack_v4(addr, buf)
    else:
        n = _pack_v6(addr, buf)
    var rc = external_call["connect", Int32](handle.raw(), buf, n)
    if rc < 0:
        raise "udp_connect: connect() failed: rc=" + String(Int(rc))
    return handle^


def udp_listener(port: Int) raises -> OwnedHandle:
    """Create a dual-stack UDP socket bound to `[::]:port`.

    Socket flags: `SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC`.
    Layered options: `SO_REUSEADDR + SO_REUSEPORT + IPV6_V6ONLY=0`.
    """
    var fd = external_call["socket", Int32](
        _AF_INET6,
        _SOCK_DGRAM | _SOCK_NONBLOCK | _SOCK_CLOEXEC,
        Int32(0),
    )
    if fd < 0:
        raise "udp_listener: socket() failed"

    var handle = OwnedHandle(raw=fd)

    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEADDR, Int32(1))
    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEPORT, Int32(1))
    _setsockopt_int(handle.raw(), _IPPROTO_IPV6, _IPV6_V6ONLY, Int32(0))

    var addr_buf = Owned[UInt8](Int(_SOCKADDR_IN6_SIZE))
    var addr = addr_buf.ptr()
    for i in range(Int(_SOCKADDR_IN6_SIZE)):
        addr[i] = 0
    addr[0] = 10  # sin6_family = AF_INET6 (LE u16)
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    var rc = external_call["bind", Int32](
        handle.raw(), addr, _SOCKADDR_IN6_SIZE,
    )
    if rc < 0:
        raise "udp_listener: bind() failed on port " + String(port)

    return handle^
