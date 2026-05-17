"""test_io_loopback.mojo — in-process resolve → connect → byte roundtrip.

Exercises the full client-side networking surface from `src/io/` without
needing a separate server process:

  * `tcp_listener(0)` — bind dual-stack `[::]:0`, recover the bound port
    via `getsockname(2)`.
  * `resolve_host("localhost", port)` — `getaddrinfo` returns the
    glibc-preferred address (typically `::1` first via RFC 6724).
  * `tcp_connect(addr)` — connect blocking, dual-stack pick from the
    `SockAddr` family tag.
  * Same-process `accept(2)` (with `O_NONBLOCK` stripped) — proves the
    SYN/ACK actually completes between two `OwnedHandle`s in this proc.
  * Two-way `send(2)` / `recv(2)` roundtrip — proves the bytes flow.

# Why no h1/h2/h3 layer here?

This is a *transport* loopback. The codec layers have their own tests.
What this locks in is the new `src/io/` surface — `SockAddr`,
`Resolver`, `tcp_connect` / `udp_connect` — without dragging in TLS or
HTTP semantics. If `tests/test_h3_udp_server.mojo` (UDP path) plus
this file pass, the migration in `examples/fetch/main.mojo` from local
syscall shims to `src/io/` is structurally validated.
"""

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.io import resolve_host, tcp_connect, tcp_listener


fn _accept_blocking(listener_fd: Int32) raises -> Int32:
    """Strip O_NONBLOCK from the listener and block in `accept(2)`."""
    # F_SETFL=4, flags=0 — clears O_NONBLOCK set by tcp_listener's
    # SOCK_NONBLOCK so the test can synchronously wait for the SYN.
    _ = external_call["fcntl", Int32](listener_fd, Int32(4), Int32(0))
    var sa = _heap_alloc[UInt8](28).as_any_origin()
    var alen = _heap_alloc[Int32](1).as_any_origin()
    alen[0] = Int32(28)
    var cfd = external_call["accept", Int32](listener_fd, sa, alen)
    sa.free()
    alen.free()
    if cfd < 0:
        raise "accept() returned " + String(Int(cfd))
    return cfd


fn _send_bytes(fd: Int32, data: List[UInt8]) raises:
    var buf = _heap_alloc[UInt8](len(data)).as_any_origin()
    for i in range(len(data)):
        buf[i] = data[i]
    var rc = external_call["send", Int](fd, buf, len(data), Int32(0))
    buf.free()
    if rc <= 0:
        raise "send() returned " + String(rc)


fn _recv_bytes(fd: Int32, max_n: Int) raises -> List[UInt8]:
    var buf = _heap_alloc[UInt8](max_n).as_any_origin()
    var rc = external_call["recv", Int](fd, buf, max_n, Int32(0))
    var out = List[UInt8]()
    if rc > 0:
        for i in range(rc):
            out.append(buf[i])
    buf.free()
    if rc < 0:
        raise "recv() returned " + String(rc)
    return out^


fn _bytes_of(s: String) -> List[UInt8]:
    var sb = s.as_bytes()
    var out = List[UInt8](capacity=len(sb))
    for i in range(len(sb)):
        out.append(sb[i])
    return out^


fn _string_of(bytes: List[UInt8]) -> String:
    var s = String()
    for i in range(len(bytes)):
        s += chr(Int(bytes[i]))
    return s^


fn test_loopback_roundtrip() raises:
    """Server binds dual-stack, client resolves+connects, both sides exchange."""
    var srv = tcp_listener(0)

    var sa = _heap_alloc[UInt8](28).as_any_origin()
    var alen = _heap_alloc[Int32](1).as_any_origin()
    alen[0] = Int32(28)
    _ = external_call["getsockname", Int32](srv.raw(), sa, alen)
    # sockaddr_in6 port at offset 2, big-endian u16.
    var port = (Int(sa[2]) << 8) | Int(sa[3])
    sa.free()
    alen.free()
    if port == 0:
        raise "test_loopback: getsockname returned port 0"

    var addrs = resolve_host(String("localhost"), port)
    if len(addrs) == 0:
        raise "test_loopback: resolve_host gave no addresses"
    var client = tcp_connect(addrs[0])

    var conn_fd = _accept_blocking(srv.raw())

    # Client -> server.
    _send_bytes(client.raw(), _bytes_of(String("ping")))
    var got = _string_of(_recv_bytes(conn_fd, 64))
    if got != "ping":
        raise "server got '" + got + "', expected 'ping'"

    # Server -> client.
    _send_bytes(conn_fd, _bytes_of(String("pong:") + got))
    var back = _string_of(_recv_bytes(client.raw(), 64))
    if back != "pong:ping":
        raise "client got '" + back + "', expected 'pong:ping'"

    _ = external_call["close", Int32](conn_fd)
    # NLL guard: keep `srv` and `client` alive past the last syscall site.
    _ = srv.raw()
    _ = client.raw()

    print("PASS: test_loopback_roundtrip")


fn main() raises:
    test_loopback_roundtrip()
