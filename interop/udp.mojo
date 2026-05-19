# interop/udp.mojo
#
# UDP socket, poll, getaddrinfo, and monotonic clock helpers for the QUIC
# Interop Runner test infrastructure.  Isolated from src/ — no production
# code imports.
#
# All networking is done via external_call to Linux libc/syscalls.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc


# ── constants ────────────────────────────────────────────────────────────────

comptime AF_INET: Int32 = 2
comptime AF_INET6: Int32 = 10
comptime SOCK_DGRAM: Int32 = 2
comptime SOL_SOCKET: Int32 = 1
comptime SO_REUSEADDR: Int32 = 2
comptime IPPROTO_IPV6: Int32 = 41
comptime IPV6_V6ONLY: Int32 = 26
comptime POLLIN: Int16 = 1
comptime CLOCK_MONOTONIC: Int32 = 1
comptime _ADDR_SIZE: Int = 28  # sizeof(sockaddr_in6) — used for all address buffers


# ── internal helpers ─────────────────────────────────────────────────────────


def _to_cstr(s: String) -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Allocate a null-terminated C string from a Mojo String.
    Caller must call .free() on the returned pointer."""
    var slen = s.byte_length()
    var buf = alloc[UInt8](slen + 1).as_any_origin()
    var bytes = s.as_bytes()
    for i in range(slen):
        buf[i] = bytes[i]
    buf[slen] = 0
    return buf


def _store_le32(buf: UnsafePointer[UInt8, MutAnyOrigin], offset: Int, val: Int32):
    """Store a 32-bit value in little-endian at buf[offset..offset+4]."""
    buf[offset] = UInt8(Int(val) & 0xFF)
    buf[offset + 1] = UInt8((Int(val) >> 8) & 0xFF)
    buf[offset + 2] = UInt8((Int(val) >> 16) & 0xFF)
    buf[offset + 3] = UInt8((Int(val) >> 24) & 0xFF)


def _load_le32(buf: UnsafePointer[UInt8, MutAnyOrigin], offset: Int) -> Int:
    """Load a 32-bit little-endian value from buf[offset..offset+4]."""
    return (
        Int(buf[offset])
        | (Int(buf[offset + 1]) << 8)
        | (Int(buf[offset + 2]) << 16)
        | (Int(buf[offset + 3]) << 24)
    )


def _load_le64(buf: UnsafePointer[UInt8, MutAnyOrigin], offset: Int) -> Int:
    """Load a 64-bit little-endian value from buf[offset..offset+8]."""
    var val: Int = 0
    for i in range(8):
        val |= Int(buf[offset + i]) << (i * 8)
    return val


# ── public API ───────────────────────────────────────────────────────────────


def udp_bind(port: Int) raises -> Int32:
    """Create a dual-stack UDP socket bound to [::]:port.

    Uses AF_INET6 with IPV6_V6ONLY=0 so both IPv4 and IPv6 clients
    can reach the server (IPv4 arrives as ::ffff:a.b.c.d).
    """
    var fd = external_call["socket", Int32](AF_INET6, SOCK_DGRAM, Int32(0))
    if fd < 0:
        raise "udp_bind: socket() failed"

    var optval = alloc[UInt8](4).as_any_origin()

    # SO_REUSEADDR
    _store_le32(optval, 0, Int32(1))
    var sso = external_call["setsockopt", Int32](
        fd, SOL_SOCKET, SO_REUSEADDR, optval, Int32(4)
    )
    if sso < 0:
        optval.free()
        _ = external_call["close", Int32](fd)
        raise "udp_bind: setsockopt(SO_REUSEADDR) failed"

    # IPV6_V6ONLY = 0 (dual-stack: accept both IPv4 and IPv6)
    _store_le32(optval, 0, Int32(0))
    var v6o = external_call["setsockopt", Int32](
        fd, IPPROTO_IPV6, IPV6_V6ONLY, optval, Int32(4)
    )
    optval.free()
    if v6o < 0:
        _ = external_call["close", Int32](fd)
        raise "udp_bind: setsockopt(IPV6_V6ONLY) failed"

    # Build sockaddr_in6 (28 bytes)
    var addr = alloc[UInt8](_ADDR_SIZE).as_any_origin()
    for i in range(_ADDR_SIZE):
        addr[i] = 0
    # sin6_family = AF_INET6 (10) — little-endian u16
    addr[0] = 10
    addr[1] = 0
    # sin6_port — big-endian u16 at offset 2
    var port_be = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    addr[2] = UInt8(port_be & 0xFF)
    addr[3] = UInt8((port_be >> 8) & 0xFF)
    # sin6_addr = :: (all zeros, already zero)

    var rc = external_call["bind", Int32](fd, addr, Int32(_ADDR_SIZE))
    addr.free()
    if rc < 0:
        _ = external_call["close", Int32](fd)
        raise "udp_bind: bind() failed on port " + String(port)

    return fd


def udp_recvfrom(fd: Int32) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Receive a UDP datagram.  Returns (data, sockaddr_bytes).

    Address buffer is _ADDR_SIZE bytes (sockaddr_in6) to handle both
    IPv4-mapped and native IPv6 peers on a dual-stack socket.
    """
    var buf = alloc[UInt8](65536).as_any_origin()
    var addr = alloc[UInt8](_ADDR_SIZE).as_any_origin()
    for i in range(_ADDR_SIZE):
        addr[i] = 0
    var addrlen = alloc[UInt8](4).as_any_origin()
    _store_le32(addrlen, 0, Int32(_ADDR_SIZE))

    var n = external_call["recvfrom", Int](
        fd, buf, Int(65536), Int32(0), addr, addrlen
    )
    if n < 0:
        buf.free()
        addr.free()
        addrlen.free()
        raise "udp_recvfrom: recvfrom() failed"

    var data = List[UInt8](capacity=n)
    for i in range(n):
        data.append(buf[i])

    var addr_bytes = List[UInt8](capacity=_ADDR_SIZE)
    for i in range(_ADDR_SIZE):
        addr_bytes.append(addr[i])

    buf.free()
    addr.free()
    addrlen.free()
    return Tuple(data^, addr_bytes^)


def udp_sendto(fd: Int32, data: Span[UInt8, _], addr: Span[UInt8, _]) raises:
    """Send a UDP datagram to the given sockaddr."""
    var dlen = len(data)
    var buf = alloc[UInt8](dlen).as_any_origin()
    for i in range(dlen):
        buf[i] = data[i]

    var alen = len(addr)
    var addr_buf = alloc[UInt8](alen).as_any_origin()
    for i in range(alen):
        addr_buf[i] = addr[i]

    var n = external_call["sendto", Int](
        fd, buf, dlen, Int32(0), addr_buf, Int32(alen)
    )
    buf.free()
    addr_buf.free()
    if n < 0:
        raise "udp_sendto: sendto() failed"


def udp_poll(fd: Int32, timeout_ms: Int) raises -> Bool:
    """Wait for data on fd using poll(2).  Returns True if readable."""
    # struct pollfd: fd(4 bytes LE) + events(2 bytes LE) + revents(2 bytes LE) = 8 bytes
    var pfd = alloc[UInt8](8).as_any_origin()
    _store_le32(pfd, 0, fd)
    # events = POLLIN = 1  (little-endian u16)
    pfd[4] = 1
    pfd[5] = 0
    # revents = 0
    pfd[6] = 0
    pfd[7] = 0

    var rc = external_call["poll", Int32](pfd, Int32(1), Int32(timeout_ms))
    if rc < 0:
        pfd.free()
        raise "udp_poll: poll() failed"

    # Read revents at offset 6 (little-endian u16)
    var revents = Int(pfd[6]) | (Int(pfd[7]) << 8)
    pfd.free()
    return (revents & Int(POLLIN)) != 0


def udp_connect(host: String, port: Int) raises -> Int32:
    """Create a connected UDP socket to host:port via getaddrinfo."""
    var host_cstr = _to_cstr(host)
    var port_str = _to_cstr(String(port))

    # struct addrinfo hints — 48 bytes on x86_64
    var hints = alloc[UInt8](48).as_any_origin()
    for i in range(48):
        hints[i] = 0
    # ai_flags = 0 (already zero)
    # ai_family = AF_INET = 2 at offset 4
    _store_le32(hints, 4, AF_INET)
    # ai_socktype = SOCK_DGRAM = 2 at offset 8
    _store_le32(hints, 8, SOCK_DGRAM)

    # result_ptr is a pointer-to-pointer
    var result_ptr = alloc[UnsafePointer[UInt8, MutAnyOrigin]](1).as_any_origin()
    result_ptr[0] = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=0)

    var rc = external_call["getaddrinfo", Int32](
        host_cstr, port_str, hints, result_ptr
    )
    host_cstr.free()
    port_str.free()
    hints.free()

    if rc != 0:
        result_ptr.free()
        raise "udp_connect: getaddrinfo() failed with code " + String(rc)

    var result = result_ptr[0]
    result_ptr.free()

    if not result:
        raise "udp_connect: getaddrinfo() returned null"

    # Read ai_addrlen at offset 16 (4 bytes LE)
    var ai_addrlen = _load_le32(result, 16)

    # Read ai_addr pointer at offset 24 (8 bytes LE)
    var ai_addr_val = _load_le64(result, 24)
    var ai_addr = UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=ai_addr_val)

    # Create socket
    var fd = external_call["socket", Int32](AF_INET, SOCK_DGRAM, Int32(0))
    if fd < 0:
        _ = external_call["freeaddrinfo", Int32](result)
        raise "udp_connect: socket() failed"

    # Connect
    var crc = external_call["connect", Int32](fd, ai_addr, Int32(ai_addrlen))
    _ = external_call["freeaddrinfo", Int32](result)

    if crc < 0:
        _ = external_call["close", Int32](fd)
        raise "udp_connect: connect() failed"

    return fd


def monotonic_us() -> UInt64:
    """Return monotonic clock in microseconds."""
    # struct timespec: tv_sec(i64) + tv_nsec(i64) = 16 bytes
    var ts = alloc[UInt8](16).as_any_origin()
    for i in range(16):
        ts[i] = 0
    _ = external_call["clock_gettime", Int32](CLOCK_MONOTONIC, ts)
    var tv_sec = UInt64(_load_le64(ts, 0))
    var tv_nsec = UInt64(_load_le64(ts, 8))
    ts.free()
    return tv_sec * 1_000_000 + tv_nsec / 1_000


def udp_close(fd: Int32):
    """Close a socket fd."""
    _ = external_call["close", Int32](fd)
