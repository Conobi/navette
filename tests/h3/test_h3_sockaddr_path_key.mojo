"""The peer sockaddr survives the PathKey round trip the egress path takes.

Egress builds its destination from the connection's PathKey, so anything the
key drops is lost on the wire: a link-local (fe80::/10) peer needs its IPv6
scope id to be routable at all.
"""

from tests._test_util import assert_true, assert_equal_int
from navette.h3.h3_udp_server import _path_key_to_sockaddr, _sockaddr_to_path_key


def _v6(first: UInt8, second: UInt8, scope_id: UInt32) -> List[Byte]:
    """A sockaddr_in6 for [first second ::1]:443 with `scope_id`, zero flowinfo."""
    var sa = List[Byte](length=28, fill=Byte(0))
    sa[0] = 10
    sa[2] = 0x01
    sa[3] = 0xBB
    sa[8] = first
    sa[9] = second
    sa[23] = 1
    for i in range(4):
        sa[24 + i] = UInt8((scope_id >> UInt32(8 * i)) & 0xFF)
    return sa^


def _round_trip(mut sa: List[Byte]) -> List[Byte]:
    var key = _sockaddr_to_path_key(Pointer(to=sa[0]), 0, len(sa))
    return _path_key_to_sockaddr(key)


def _assert_same(got: List[Byte], want: List[Byte], what: String) raises:
    assert_equal_int(len(got), len(want), what + " length")
    for i in range(len(want)):
        assert_equal_int(Int(got[i]), Int(want[i]), what + " byte " + String(i))


def test_link_local_keeps_scope_id() raises:
    var sa = _v6(0xFE, 0x80, UInt32(0x01020304))
    var key = _sockaddr_to_path_key(Pointer(to=sa[0]), 0, len(sa))
    assert_equal_int(Int(key.scope_id), 0x01020304, "decoded scope id")
    _assert_same(_round_trip(sa), sa, "link-local sockaddr_in6")


def test_link_local_on_two_interfaces_is_two_paths() raises:
    var a = _v6(0xFE, 0x80, UInt32(2))
    var b = _v6(0xFE, 0x80, UInt32(3))
    var ka = _sockaddr_to_path_key(Pointer(to=a[0]), 0, len(a))
    var kb = _sockaddr_to_path_key(Pointer(to=b[0]), 0, len(b))
    assert_true(not (ka == kb), "same fe80:: address on two links must differ")


def test_global_v6_unchanged() raises:
    var sa = _v6(0x20, 0x01, UInt32(0))
    _assert_same(_round_trip(sa), sa, "global sockaddr_in6")
    var sa2 = _v6(0x20, 0x01, UInt32(0))
    var k1 = _sockaddr_to_path_key(Pointer(to=sa[0]), 0, len(sa))
    var k2 = _sockaddr_to_path_key(Pointer(to=sa2[0]), 0, len(sa2))
    assert_true(k1 == k2, "equal global v6 keys stay equal")


def test_v4_unchanged() raises:
    var sa = List[Byte](length=16, fill=Byte(0))
    sa[0] = 2
    sa[2] = 0x01
    sa[3] = 0xBB
    sa[4] = 192
    sa[5] = 0
    sa[6] = 2
    sa[7] = 7
    var key = _sockaddr_to_path_key(Pointer(to=sa[0]), 0, len(sa))
    assert_equal_int(Int(key.scope_id), 0, "v4 has no scope id")
    _assert_same(_round_trip(sa), sa, "sockaddr_in")


def main() raises:
    test_link_local_keeps_scope_id()
    test_link_local_on_two_interfaces_is_two_paths()
    test_global_v6_unchanged()
    test_v4_unchanged()
    print("test_h3_sockaddr_path_key: 4 passed")
