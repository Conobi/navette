"""sockaddr_ip: IPv4, IPv6, IPv4-mapped IPv6, and malformed blobs."""

from navette.util.sockaddr import sockaddr_ip
from tests._test_util import assert_true
from tests.protect._prop import sockaddr_in, sockaddr_in6, mapped_v6


def _expect(sa: List[Byte], off: Int, n: Int, what: String) raises:
    var r = sockaddr_ip(Span(sa))
    assert_true(
        r[0] == off and r[1] == n,
        what + ": got (" + String(r[0]) + ", " + String(r[1]) + ")",
    )


def test_ipv4() raises:
    _expect(sockaddr_in(192, 0, 2, 1, 443), 4, 4, "sockaddr_in")
    # Exactly family + port + address is enough.
    var short = sockaddr_in(192, 0, 2, 1, 443)
    short.resize(8, 0)
    _expect(short, 4, 4, "8-byte sockaddr_in")
    print("PASS: test_ipv4")


def test_ipv6() raises:
    var addr = List[Byte](length=16, fill=Byte(0))
    addr[0] = 0x20
    addr[1] = 0x01
    addr[15] = 0x01
    _expect(sockaddr_in6(addr, 443, UInt32(7), UInt32(3)), 8, 16, "sockaddr_in6")
    # All-zero (::) and loopback (::1) are native IPv6, not mapped.
    _expect(sockaddr_in6(List[Byte](length=16, fill=Byte(0)), 1, UInt32(0), UInt32(0)), 8, 16, "::")
    # ::ffff with a non-zero byte in the zero run is not mapped.
    var almost = mapped_v6(10, 0, 0, 1)
    almost[9] = 1
    _expect(sockaddr_in6(almost, 443, UInt32(0), UInt32(0)), 8, 16, "near-mapped")
    print("PASS: test_ipv6")


def test_ipv4_mapped_ipv6() raises:
    _expect(sockaddr_in6(mapped_v6(10, 0, 0, 1), 443, UInt32(9), UInt32(9)), 20, 4, "::ffff:10.0.0.1")
    print("PASS: test_ipv4_mapped_ipv6")


def test_malformed() raises:
    _expect(List[Byte](), 0, 0, "empty")
    _expect(List[Byte](length=1, fill=Byte(2)), 0, 0, "1 byte")
    var v4 = sockaddr_in(192, 0, 2, 1, 443)
    v4.resize(7, 0)
    _expect(v4, 0, 0, "7-byte sockaddr_in")
    var v6 = sockaddr_in6(mapped_v6(10, 0, 0, 1), 443, UInt32(0), UInt32(0))
    v6.resize(23, 0)
    _expect(v6, 0, 0, "23-byte sockaddr_in6")
    var unix_family = sockaddr_in(192, 0, 2, 1, 443)
    unix_family[0] = 1
    _expect(unix_family, 0, 0, "AF_UNIX")
    # Family is little-endian: 0x0200 is not AF_INET.
    var be_family = sockaddr_in(192, 0, 2, 1, 443)
    be_family[0] = 0
    be_family[1] = 2
    _expect(be_family, 0, 0, "big-endian AF_INET")
    print("PASS: test_malformed")


def main() raises:
    test_ipv4()
    test_ipv6()
    test_ipv4_mapped_ipv6()
    test_malformed()
