"""SourceKey: IPv4 / IPv4-mapped equivalence, prefix masking, ignored fields, malformed input."""

from navette.protect.source_key import (
    SourceKey,
    source_key_from_sockaddr,
    SOURCE_TAG_V4,
    SOURCE_TAG_V6,
)
from navette.util.siphash import SipKey
from tests._test_util import assert_true
from tests.protect._prop import Rng, sockaddr_in, sockaddr_in6, mapped_v6


def _bit(addr: List[Byte], i: Int) -> Int:
    return Int((addr[i // 8] >> UInt8(7 - i % 8)) & 1)


def test_ipv4_and_mapped_key_alike_property() raises:
    """`sockaddr_in` and `::ffff:a.b.c.d` key identically, whatever port/flowinfo/scope (2,000 cases)."""
    var rng = Rng(0x4444)
    for ci in range(2000):
        var ip = rng.bytes(4)
        var k4 = source_key_from_sockaddr(Span(sockaddr_in(ip[0], ip[1], ip[2], ip[3], rng.below(65536))), 48)
        var k6 = source_key_from_sockaddr(
            Span(sockaddr_in6(mapped_v6(ip[0], ip[1], ip[2], ip[3]), rng.below(65536), UInt32(rng.next() & 0xFFFFFFFF), UInt32(rng.next() & 0xFFFFFFFF))),
            rng.below(129),
        )
        assert_true(k4 == k6, "mapped == native, case " + String(ci))
        assert_true(k4.tag() == SOURCE_TAG_V4, "v4 tag")
        for i in range(4):
            assert_true(k4.bytes[1 + i] == ip[i], "address bytes kept")
        for i in range(5, 17):
            assert_true(k4.bytes[i] == 0, "zero padded")
    print("PASS: test_ipv4_and_mapped_key_alike_property")


def test_ipv6_prefix_property() raises:
    """Two native IPv6 addresses key alike iff they agree on the first `p` bits (3,000 cases)."""
    var rng = Rng(0x6666)
    for ci in range(3000):
        var p = rng.below(129)
        var a = rng.bytes(16)
        a[0] = a[0] | 0x20  # never ::/8, so never the mapped pattern
        var b = a.copy()
        var flip = rng.below(128)
        if rng.chance(50):
            b[flip // 8] = b[flip // 8] ^ UInt8(1 << (7 - flip % 8))
        var agree = True
        for i in range(p):
            if _bit(a, i) != _bit(b, i):
                agree = False
        var ka = source_key_from_sockaddr(Span(sockaddr_in6(a, rng.below(65536), UInt32(rng.below(1000)), UInt32(rng.below(9)))), p)
        var kb = source_key_from_sockaddr(Span(sockaddr_in6(b, rng.below(65536), UInt32(rng.below(1000)), UInt32(rng.below(9)))), p)
        assert_true((ka == kb) == agree, "prefix equality, case " + String(ci) + " p=" + String(p))
        assert_true(ka.tag() == SOURCE_TAG_V6, "v6 tag")
    print("PASS: test_ipv6_prefix_property")


def test_default_48_examples() raises:
    var a = List[Byte](length=16, fill=Byte(0))
    a[0] = 0x20
    a[1] = 0x01
    a[2] = 0x0D
    a[3] = 0xB8
    a[4] = 0x00
    a[5] = 0x01
    var same48 = a.copy()
    same48[6] = 0xAB
    same48[15] = 0x01
    var other48 = a.copy()
    other48[5] = 0x02
    var ka = source_key_from_sockaddr(Span(sockaddr_in6(a, 443, 0, 0)), 48)
    assert_true(ka == source_key_from_sockaddr(Span(sockaddr_in6(same48, 1, 7, 3)), 48), "same /48")
    assert_true(ka != source_key_from_sockaddr(Span(sockaddr_in6(other48, 443, 0, 0)), 48), "different /48")
    print("PASS: test_default_48_examples")


def test_malformed_maps_to_reserved() raises:
    var rng = Rng(0xBAD)
    for ci in range(500):
        var n = rng.below(40)
        var blob = rng.bytes(n)
        if n >= 2:
            var fam = rng.below(3)
            if fam == 0:
                blob[0] = 2
                blob[1] = 0
            elif fam == 1:
                blob[0] = 10
                blob[1] = 0
            else:
                blob[0] = 99
        var k = source_key_from_sockaddr(Span(blob), 48)
        var fam_v = 0 if n < 2 else Int(blob[0]) | (Int(blob[1]) << 8)
        var well_formed = (fam_v == 2 and n >= 8) or (fam_v == 10 and n >= 24)
        assert_true(k.is_reserved() == (not well_formed), "reserved iff malformed, case " + String(ci))
    print("PASS: test_malformed_maps_to_reserved")


def test_hash_depends_on_key_only() raises:
    var sip = SipKey(k0=UInt64(1), k1=UInt64(2))
    var k1 = source_key_from_sockaddr(Span(sockaddr_in(10, 0, 0, 1, 1111)), 48)
    var k2 = source_key_from_sockaddr(Span(sockaddr_in(10, 0, 0, 1, 2222)), 48)
    assert_true(k1.hash(sip) == k2.hash(sip), "port does not reach the hash")
    print("PASS: test_hash_depends_on_key_only")


def main() raises:
    test_ipv4_and_mapped_key_alike_property()
    test_ipv6_prefix_property()
    test_default_48_examples()
    test_malformed_maps_to_reserved()
    test_hash_depends_on_key_only()
