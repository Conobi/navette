"""TCP socket factory for H1 / H2 servers.

Provides `tcp_listener(port, backlog)` returning an `OwnedHandle` for a
TCP socket configured for an HTTP server: dual-stack IPv6
(`IPV6_V6ONLY=0`), `SO_REUSEADDR + SO_REUSEPORT` (multi-worker
safe), `SOCK_NONBLOCK + SOCK_CLOEXEC`, bound to `[::]:port`, and
already in the LISTEN state.

# Ownership

The returned `OwnedHandle` owns the fd; its `__del__` calls
`close(2)` when the handle goes out of scope. The io_uring loop
holds raw fd values in submitted SQEs that outlive a single
function call, so the listener MUST live at least as long as the
loop's references. Hand the handle to your `H1TcpServer` /
`H2TcpServer` via `__init__` so the server's lifetime governs the
fd's lifetime.

Bench's `bench/h1_server.mojo` / `bench/h2_server.mojo` use
`boucle.net.socket.Socket` directly (which isn't `Movable` so
can't be returned from a factory). This library factory bypasses
`Socket` and uses raw syscalls, mirroring `udp_listener`.
"""

from std.ffi import external_call
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from boucle.handle import RawHandle, OwnedHandle


# Linux socket constants (private — wrap them so callers never see
# raw level/optname/protocol pairs).
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
