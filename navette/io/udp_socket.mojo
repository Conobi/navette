"""UDP socket factory for H3 / QUIC servers.

Provides `udp_listener(port)` returning an `OwnedHandle` for a UDP
socket configured for an HTTP/3 server: dual-stack IPv6
(`IPV6_V6ONLY=0`), `SO_REUSEADDR` (rebind after crash without
TIME_WAIT delays), `SO_REUSEPORT` (multi-worker safe),
`SOCK_NONBLOCK + SOCK_CLOEXEC`, and bound to `[::]:port`.

# Why an OwnedHandle and not a boucle.Socket?

`boucle.net.socket.Socket` is not yet `Movable`, so it can't be
returned from a factory function. `OwnedHandle` is the underlying
RAII type and IS `Movable`; consumers store it on their server
struct and call `.raw()` to thread the fd into io_uring submissions.

# Ownership

The returned `OwnedHandle` owns the fd; its `__del__` calls
`close(2)` when it goes out of scope. The io_uring loop holds raw
handles in submitted SQEs that outlive a single function call, so
the `OwnedHandle` MUST live at least as long as the loop's
references — store it on the server struct, not in a stack frame
that returns before `tick()` drains its outstanding completions.

Bench's `_setup_udp_socket` returned a bare `Int32` fd and never
wrapped it for RAII. That works because the bench leaks the fd at
process exit, but for a library surface the explicit ownership
story is what callers want.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from boucle.handle import RawHandle, OwnedHandle

from .sockaddr import SockAddr


# Linux socket constants (kept private — wrap them here so callers
# never see raw level/optname/protocol pairs).
comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10
comptime _SOCK_DGRAM: Int32 = 2
comptime _SOCK_NONBLOCK: Int32 = 0x800
comptime _SOCK_CLOEXEC: Int32 = 0x80000

comptime _SOL_SOCKET: Int32 = 1
comptime _SO_REUSEADDR: Int32 = 2
comptime _SO_REUSEPORT: Int32 = 15
comptime _IPPROTO_IPV6: Int32 = 41
comptime _IPV6_V6ONLY: Int32 = 26

comptime _SOCKADDR_IN6_SIZE: Int32 = 28


def _setsockopt_int(fd: RawHandle, level: Int32, optname: Int32, value: Int32) raises:
    """Set an Int32 socket option via `setsockopt(2)`."""
    var optval = _heap_alloc[Int32](1).as_any_origin()
    optval[0] = value
    var rc = external_call["setsockopt", Int32](
        fd, level, optname, optval, Int32(4),
    )
    optval.free()
    if rc < 0:
        raise (
            "setsockopt failed (level="
            + String(Int(level))
            + " optname="
            + String(Int(optname))
            + ")"
        )


def udp_listener(port: Int) raises -> OwnedHandle:
    """Create a dual-stack UDP socket bound to `[::]:port`.

    Socket flags: `SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC`.
    Layered options: `SO_REUSEADDR + SO_REUSEPORT + IPV6_V6ONLY=0`.

    Caller owns the returned `OwnedHandle` and is responsible for
    keeping it alive across the io_uring loop's lifetime — typically
    by storing it on the server struct.
    """
    var fd = external_call["socket", Int32](
        _AF_INET6,
        _SOCK_DGRAM | _SOCK_NONBLOCK | _SOCK_CLOEXEC,
        Int32(0),
    )
    if fd < 0:
        raise "udp_listener: socket() failed"

    # Wrap immediately so any subsequent failure path closes the fd.
    var handle = OwnedHandle(raw=fd)

    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEADDR, Int32(1))
    _setsockopt_int(handle.raw(), _SOL_SOCKET, _SO_REUSEPORT, Int32(1))
    _setsockopt_int(handle.raw(), _IPPROTO_IPV6, _IPV6_V6ONLY, Int32(0))

    # Build sockaddr_in6 for [::]:port — 28 bytes:
    #   family(2) + port(2 big-endian) + flowinfo(4) + addr(16) + scope_id(4).
    var addr = _heap_alloc[UInt8](Int(_SOCKADDR_IN6_SIZE)).as_any_origin()
    for i in range(Int(_SOCKADDR_IN6_SIZE)):
        addr[i] = 0
    # sin6_family = AF_INET6 (little-endian u16)
    addr[0] = 10
    addr[1] = 0
    # sin6_port (big-endian u16)
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    var rc = external_call["bind", Int32](
        handle.raw(), addr, _SOCKADDR_IN6_SIZE,
    )
    addr.free()
    if rc < 0:
        raise "udp_listener: bind() failed on port " + String(port)

    return handle^


def udp_connect(addr: SockAddr) raises -> OwnedHandle:
    """Open a blocking UDP socket "connected" to `addr`.

    `connect(2)` on a datagram socket pins the peer address so
    subsequent `send(2)` / `recv(2)` calls skip the per-call addr
    argument and only deliver datagrams from that peer (unsolicited
    traffic is dropped by the kernel). Picks `AF_INET` vs `AF_INET6`
    from the `SockAddr` tag. Socket flags: `SOCK_DGRAM | SOCK_CLOEXEC`
    (no `SOCK_NONBLOCK` — callers wanting non-blocking I/O set it
    after connect).
    """
    var family = _AF_INET if addr.is_ipv4() else _AF_INET6
    var fd = external_call["socket", Int32](
        family, _SOCK_DGRAM | _SOCK_CLOEXEC, Int32(0),
    )
    if fd < 0:
        raise "udp_connect: socket() failed"
    var handle = OwnedHandle(raw=fd)

    var buf = _heap_alloc[UInt8](Int(_SOCKADDR_IN6_SIZE)).as_any_origin()
    var n = addr.pack(buf)
    var rc = external_call["connect", Int32](handle.raw(), buf, n)
    buf.free()
    if rc < 0:
        raise (
            "udp_connect: connect(" + addr.to_string() + ":"
            + String(addr.port()) + ") failed: rc=" + String(Int(rc))
        )
    return handle^
