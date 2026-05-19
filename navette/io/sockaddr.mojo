"""sockaddr.mojo — tagged union over sockaddr_in / sockaddr_in6.

`SockAddr` packs an AF_INET or AF_INET6 socket address into the byte
layout that `connect(2)`, `bind(2)`, and `sendmsg(2)` expect on Linux.
The struct carries the family tag and the packed bytes together so
callers can hand it to a syscall without re-deriving the family from
the length.

# Linux x86_64 layouts

sockaddr_in   (16 B)  family(2 LE)  port(2 BE)  addr(4)              zero(8)
sockaddr_in6  (28 B)  family(2 LE)  port(2 BE)  flowinfo(4)  addr(16)  scope_id(4 LE)

# Why not a `Variant`?

A 28-byte buffer + a family tag is cheaper and avoids Mojo 0.26.x's
Variant-in-loop compile-hang gotcha. The packed bytes are also exactly
what the kernel wants — no second copy at the syscall boundary.
"""

from std.collections.optional import Optional
from std.memory import UnsafePointer


comptime _AF_INET: Int32 = 2
comptime _AF_INET6: Int32 = 10


struct SockAddr(Copyable, Movable):
    """An IPv4 or IPv6 socket address packed for the kernel."""

    var bytes: List[UInt8]
    var family_: Int32

    def __init__(out self, var bytes: List[UInt8], family: Int32):
        self.bytes = bytes^
        self.family_ = family

    def __init__(out self, *, deinit take: Self):
        self.bytes = take.bytes^
        self.family_ = take.family_

    def is_ipv4(self) -> Bool:
        return self.family_ == _AF_INET

    def is_ipv6(self) -> Bool:
        return self.family_ == _AF_INET6

    def family(self) -> Int32:
        return self.family_

    def byte_len(self) -> Int32:
        return Int32(len(self.bytes))

    def pack(self, dst: UnsafePointer[UInt8, MutAnyOrigin]) -> Int32:
        """Copy packed sockaddr bytes to `dst`. Returns the length written.

        `dst` must point to at least `byte_len()` writable bytes — 16 for
        IPv4, 28 for IPv6. Callers typically alloc a 28-byte scratch buffer
        and pass `pack`'s return value as the `addrlen` arg to `connect(2)`.
        """
        for i in range(len(self.bytes)):
            dst[i] = self.bytes[i]
        return Int32(len(self.bytes))

    def port(self) -> Int:
        """The TCP/UDP port number encoded in the address."""
        var hi = Int(self.bytes[2])
        var lo = Int(self.bytes[3])
        return (hi << 8) | lo

    def to_string(self) -> String:
        """Dotted-IPv4 ('1.2.3.4') or hex-block IPv6 ('aaaa:bbbb:...') — no port."""
        if self.is_ipv4():
            return (
                String(Int(self.bytes[4])) + "." + String(Int(self.bytes[5]))
                + "." + String(Int(self.bytes[6])) + "." + String(Int(self.bytes[7]))
            )
        var hex_chars = String("0123456789abcdef").as_bytes()
        var s = String()
        for i in range(8):
            var b1 = Int(self.bytes[8 + 2 * i])
            var b2 = Int(self.bytes[8 + 2 * i + 1])
            if i > 0:
                s += ":"
            s += chr(Int(hex_chars[(b1 >> 4) & 0xF]))
            s += chr(Int(hex_chars[b1 & 0xF]))
            s += chr(Int(hex_chars[(b2 >> 4) & 0xF]))
            s += chr(Int(hex_chars[b2 & 0xF]))
        return s^


def sockaddr_ipv4(o1: Int, o2: Int, o3: Int, o4: Int, port: Int) -> SockAddr:
    """Build an AF_INET SockAddr from four octets + a port."""
    var b = List[UInt8](capacity=16)
    for _ in range(16):
        b.append(UInt8(0))
    b[0] = UInt8(2)  # AF_INET (LE u16 lo byte)
    b[2] = UInt8((port >> 8) & 0xFF)
    b[3] = UInt8(port & 0xFF)
    b[4] = UInt8(o1 & 0xFF)
    b[5] = UInt8(o2 & 0xFF)
    b[6] = UInt8(o3 & 0xFF)
    b[7] = UInt8(o4 & 0xFF)
    return SockAddr(b^, _AF_INET)


def sockaddr_ipv6(
    addr16: List[UInt8], port: Int, scope_id: Int = 0
) raises -> SockAddr:
    """Build an AF_INET6 SockAddr from 16 raw address bytes + a port.

    `addr16` must contain exactly 16 bytes in network order (the same
    layout the kernel returns in `sin6_addr.s6_addr`).
    """
    if len(addr16) != 16:
        raise "sockaddr_ipv6: addr16 must be exactly 16 bytes"
    var b = List[UInt8](capacity=28)
    for _ in range(28):
        b.append(UInt8(0))
    b[0] = UInt8(10)  # AF_INET6 (LE u16 lo byte)
    b[2] = UInt8((port >> 8) & 0xFF)
    b[3] = UInt8(port & 0xFF)
    # flowinfo (offset 4..8) stays zero
    for i in range(16):
        b[8 + i] = addr16[i]
    # scope_id (offset 24..28, LE u32)
    b[24] = UInt8(scope_id & 0xFF)
    b[25] = UInt8((scope_id >> 8) & 0xFF)
    b[26] = UInt8((scope_id >> 16) & 0xFF)
    b[27] = UInt8((scope_id >> 24) & 0xFF)
    return SockAddr(b^, _AF_INET6)


def parse_dotted_ipv4(s: String, port: Int) -> Optional[SockAddr]:
    """Parse a strict dotted-quad IPv4 literal into a SockAddr.

    Accepts exactly four octets, exactly three dots, digits only, each
    octet 0..=255. Returns `None` on any malformed input (so
    `999.999.999.999`, `1.2.3`, `1..2.3.4`, etc. are rejected).
    """
    var bytes = s.as_bytes()
    if len(bytes) == 0:
        return Optional[SockAddr]()
    var octets = List[Int]()
    var current = 0
    var have_digit = False
    var dot_count = 0
    for i in range(len(bytes)):
        var b = bytes[i]
        if b == UInt8(46):  # '.'
            if not have_digit:
                return Optional[SockAddr]()
            octets.append(current)
            current = 0
            have_digit = False
            dot_count += 1
            if dot_count > 3:
                return Optional[SockAddr]()
        elif b >= UInt8(48) and b <= UInt8(57):  # '0'..'9'
            current = current * 10 + (Int(b) - 48)
            if current > 255:
                return Optional[SockAddr]()
            have_digit = True
        else:
            return Optional[SockAddr]()
    if not have_digit or dot_count != 3:
        return Optional[SockAddr]()
    octets.append(current)
    return Optional[SockAddr](
        sockaddr_ipv4(octets[0], octets[1], octets[2], octets[3], port)
    )
