"""The 17-byte source key that fair share and the memory budget count by.

A peer is identified by its IPv4 /32 or its IPv6 prefix (default /48),
never by port, `flowinfo` or `scope_id`: a single host cannot mint new
identities by opening sockets. IPv4-mapped IPv6 (`::ffff:a.b.c.d`, what
the dual-stack listeners deliver for IPv4 peers) keys exactly like a
native `sockaddr_in`. Compute the key once when a connection is created
and store it; migration and NAT rebinding must not move a connection
between sources.
"""

from std.collections import InlineArray, Span

from navette.util.siphash import SipKey, siphash13
from navette.util.sockaddr import sockaddr_ip

comptime SOURCE_KEY_LEN: Int = 17
comptime SOURCE_TAG_RESERVED: UInt8 = 0
comptime SOURCE_TAG_V4: UInt8 = 4
comptime SOURCE_TAG_V6: UInt8 = 6
comptime DEFAULT_IPV6_SOURCE_PREFIX: Int = 48


struct SourceKey(Copyable, Equatable, Movable):
    """Tag byte + address bytes, zero-padded; tag 0 is the one reserved key for malformed input."""

    var bytes: InlineArray[UInt8, SOURCE_KEY_LEN]

    def __init__(out self):
        """The reserved key (all zeros)."""
        self.bytes = InlineArray[UInt8, SOURCE_KEY_LEN](fill=UInt8(0))

    @staticmethod
    def reserved() -> Self:
        return Self()

    def tag(self) -> UInt8:
        return self.bytes[0]

    def is_reserved(self) -> Bool:
        return self.bytes[0] == SOURCE_TAG_RESERVED

    def hash(self, key: SipKey) -> UInt64:
        """SipHash-1-3 over all 17 bytes; the table bucket selector."""
        return siphash13(key, Span(self.bytes))

    def __eq__(self, other: Self) -> Bool:
        for i in range(SOURCE_KEY_LEN):
            if self.bytes[i] != other.bytes[i]:
                return False
        return True

    def __ne__(self, other: Self) -> Bool:
        return not (self == other)


def _v4_key(a: UInt8, b: UInt8, c: UInt8, d: UInt8) -> SourceKey:
    var k = SourceKey()
    k.bytes[0] = SOURCE_TAG_V4
    k.bytes[1] = a
    k.bytes[2] = b
    k.bytes[3] = c
    k.bytes[4] = d
    return k^


def source_key_from_sockaddr(sa: Span[Byte, _], ipv6_prefix_bits: Int) -> SourceKey:
    """Key a Linux `sockaddr_in` / `sockaddr_in6` blob (family little-endian).

    Only address bytes are read. `ipv6_prefix_bits` is clamped to
    [0, 128]. A blob too short for its family, or any other family,
    yields the reserved key, so malformed input can never alias a real
    source.
    """
    var ip = sockaddr_ip(sa)
    var off = ip[0]
    if ip[1] == 0:
        return SourceKey.reserved()
    if ip[1] == 4:
        return _v4_key(sa[off], sa[off + 1], sa[off + 2], sa[off + 3])
    var bits = min(max(ipv6_prefix_bits, 0), 128)
    var k = SourceKey()
    k.bytes[0] = SOURCE_TAG_V6
    for i in range(16):
        var keep = bits - 8 * i
        var mask: UInt8
        if keep >= 8:
            mask = 0xFF
        elif keep <= 0:
            mask = 0
        else:
            mask = UInt8((0xFF << (8 - keep)) & 0xFF)
        k.bytes[1 + i] = sa[off + i] & mask
    return k^
