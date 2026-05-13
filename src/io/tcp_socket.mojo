"""TCP socket factories for H1 / H2 servers and clients.

* `tcp_listener(port, backlog)` — dual-stack server-side `[::]:port`
  socket: `IPV6_V6ONLY=0`, `SO_REUSEADDR + SO_REUSEPORT`,
  `SOCK_NONBLOCK + SOCK_CLOEXEC`, in LISTEN state. Caller owns the
  returned `OwnedHandle` and threads it into `H1TcpServer` /
  `H2TcpServer`.
* `tcp_connect(addr)` — blocking client-side connect. Picks `AF_INET`
  or `AF_INET6` from the `SockAddr` tag and returns the connected
  `OwnedHandle`. `SOCK_CLOEXEC` only (no `SOCK_NONBLOCK` — callers
  using blocking send/recv get the simpler programming model).

# Ownership

`OwnedHandle.__del__` calls `close(2)` when the handle drops. The
io_uring loop holds raw fd values in submitted SQEs that outlive a
single function call, so the listener MUST live at least as long
as the loop's references. Pass via `^` into the server struct so
its lifetime governs the fd's.

For client use, hold the `OwnedHandle` for the duration of the
request and call `.raw()` at every syscall site — Mojo's NLL will
otherwise drop the handle after the first `.raw()` and close the
fd out from under you (see `examples/fetch/main.mojo`).
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from boucle.handle import RawHandle, OwnedHandle

from .sockaddr import SockAddr


# Linux socket constants (private — wrap them so callers never see
# raw level/optname/protocol pairs).
comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10
comptime _SOCK_STREAM: Int32 = 1
comptime _SOCK_NONBLOCK: Int32 = 0x800
comptime _SOCK_CLOEXEC: Int32 = 0x80000

comptime _SOL_SOCKET: Int32 = 1
comptime _SO_REUSEADDR: Int32 = 2
comptime _SO_REUSEPORT: Int32 = 15
comptime _IPPROTO_IPV6: Int32 = 41
comptime _IPV6_V6ONLY: Int32 = 26

comptime _SOCKADDR_IN6_SIZE: Int32 = 28


fn _setsockopt_int(fd: RawHandle, level: Int32, optname: Int32, value: Int32) raises:
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


fn tcp_listener(port: Int, backlog: Int = 1024) raises -> OwnedHandle:
    """Create a dual-stack TCP listening socket bound to `[::]:port`.

    Socket flags: `SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC`.
    Layered options: `SO_REUSEADDR + SO_REUSEPORT + IPV6_V6ONLY=0`.
    Listen backlog defaults to 1024 (override for high-concurrency
    workloads).

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
    var addr = _heap_alloc[UInt8](Int(_SOCKADDR_IN6_SIZE)).as_any_origin()
    for i in range(Int(_SOCKADDR_IN6_SIZE)):
        addr[i] = 0
    addr[0] = 10  # sin6_family = AF_INET6 (LE u16)
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)

    var rc = external_call["bind", Int32](
        handle.raw(), addr, _SOCKADDR_IN6_SIZE,
    )
    addr.free()
    if rc < 0:
        raise "tcp_listener: bind() failed on port " + String(port)

    var lrc = external_call["listen", Int32](handle.raw(), Int32(backlog))
    if lrc < 0:
        raise "tcp_listener: listen() failed"

    return handle^


fn tcp_connect(addr: SockAddr) raises -> OwnedHandle:
    """Open a blocking TCP socket and connect it to `addr`.

    Picks `AF_INET` vs `AF_INET6` from the `SockAddr` tag. Socket flags
    are `SOCK_STREAM | SOCK_CLOEXEC` only — no `SOCK_NONBLOCK`, so the
    returned fd is suitable for direct blocking `send(2)` / `recv(2)`.
    Callers wanting an io_uring-driven client should set non-blocking
    themselves after connect.
    """
    var family = _AF_INET if addr.is_ipv4() else _AF_INET6
    var fd = external_call["socket", Int32](
        family, _SOCK_STREAM | _SOCK_CLOEXEC, Int32(0),
    )
    if fd < 0:
        raise "tcp_connect: socket() failed"
    var handle = OwnedHandle(raw=fd)

    var buf = _heap_alloc[UInt8](Int(_SOCKADDR_IN6_SIZE)).as_any_origin()
    var n = addr.pack(buf)
    var rc = external_call["connect", Int32](handle.raw(), buf, n)
    buf.free()
    if rc < 0:
        raise (
            "tcp_connect: connect(" + addr.to_string() + ":"
            + String(addr.port()) + ") failed: rc=" + String(Int(rc))
        )
    return handle^
