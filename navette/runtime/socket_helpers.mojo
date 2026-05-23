"""TCP/UDP listener helpers returning `OwnedHandle`.

Boucle exposes `Socket.tcp_listener_v6` / `Socket.udp_listener_v6` for
the same role — but those return a `Socket` value, and `Socket` is
not yet `Movable` in Boucle (an out-of-scope follow-up in the public
API spec). Navette's server structs (`H1TcpServer`, `H2TcpServer`,
`H3UdpServer`) own an `OwnedHandle` field, so they need a handle that
can be moved by `^` into the struct.

These helpers replicate the syscall sequence that `Socket.tcp_listener_v6`
performs (dual-stack `[::]:port`, `SO_REUSEADDR + SO_REUSEPORT`,
`IPV6_V6ONLY=0`, `SOCK_NONBLOCK + SOCK_CLOEXEC`, `bind` + `listen` for
TCP) but hand back an `OwnedHandle` directly. They use only public
symbols from `boucle.*`.

When `Socket` gains a way to extract its underlying `OwnedHandle`
(either by becoming `Movable` or via a consuming `into_handle()`),
delete this module and switch the consumers to `Socket.tcp_listener_v6`
/ `Socket.udp_listener_v6` directly.
"""

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.handle import RawHandle, OwnedHandle


# Linux socket constants — kept private here so consumers never see
# raw level/optname/protocol pairs.
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

comptime _SOCKADDR_IN6_SIZE: Int32 = 28


def _setsockopt_int(
    fd: RawHandle, level: Int32, optname: Int32, value: Int32,
) raises:
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
        raise "udp_listener: bind() failed on port " + String(port)

    return handle^
