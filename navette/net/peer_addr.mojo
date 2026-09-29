"""Peer address extraction utilities shared across TCP and QUIC servers."""

from std.ffi import external_call

from navette.util.owned_alloc import Owned


def peer_addr_from_fd(fd: Int32) -> String:
    """Extract the peer IP address from a connected socket fd via getpeername(2).

    Handles IPv4, IPv6, and IPv4-mapped IPv6 (::ffff:a.b.c.d) addresses.
    Returns the IP as a string (e.g. "192.168.1.1" or "fe80:0:0:0:0:0:0:1").
    Returns "" on failure.
    """
    # sockaddr_storage is 128 bytes on Linux, enough for any address family.
    var addr_buf = Owned[UInt8](128)
    var addr = addr_buf.ptr()
    for i in range(128):
        addr[unsafe_offset=i] = UInt8(0)

    # addrlen is an in/out parameter for getpeername(2).
    var len_buf = Owned[Int32](1)
    var len_ptr = len_buf.ptr()
    len_ptr[unsafe_offset=0] = Int32(128)

    var rc = external_call["getpeername", Int32](fd, addr, len_ptr)
    if rc < 0:
        return String("")

    var family = Int(addr[unsafe_offset=0])  # sa_family low byte (LE u16)

    if family == 2:  # AF_INET
        # sockaddr_in layout: family(2) port(2 BE) addr(4) zero(8)
        return (
            String(Int(addr[unsafe_offset=4])) + "." + String(Int(addr[unsafe_offset=5])) + "."
            + String(Int(addr[unsafe_offset=6])) + "." + String(Int(addr[unsafe_offset=7]))
        )

    if family == 10:  # AF_INET6
        # sockaddr_in6 layout: family(2) port(2 BE) flowinfo(4) addr(16) scope_id(4)
        # Check for IPv4-mapped address (::ffff:a.b.c.d)
        var is_v4_mapped = True
        for i in range(10):
            if addr[unsafe_offset=8 + i] != UInt8(0):
                is_v4_mapped = False
                break
        if is_v4_mapped and addr[unsafe_offset=18] == UInt8(0xFF) and addr[unsafe_offset=19] == UInt8(0xFF):
            return (
                String(Int(addr[unsafe_offset=20])) + "." + String(Int(addr[unsafe_offset=21])) + "."
                + String(Int(addr[unsafe_offset=22])) + "." + String(Int(addr[unsafe_offset=23]))
            )

        # Full IPv6 — format as 8 colon-separated hex segments.
        var result = String("")
        for i in range(8):
            if i > 0:
                result += ":"
            var hi = Int(addr[unsafe_offset=8 + 2 * i])
            var lo = Int(addr[unsafe_offset=8 + 2 * i + 1])
            var seg = (hi << 8) | lo
            if seg == 0:
                result += "0"
            else:
                var hex_buf = List[Byte]()
                var v = seg
                while v > 0:
                    var nyb = v & 0xF
                    if nyb < 10:
                        hex_buf.append(UInt8(nyb + 48))
                    else:
                        hex_buf.append(UInt8(nyb - 10 + 97))
                    v >>= 4
                var j = len(hex_buf) - 1
                while j >= 0:
                    result += chr(Int(hex_buf[j]))
                    j -= 1
        return result^

    return String("")
