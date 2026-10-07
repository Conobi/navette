"""The peer sockaddr survives the PathKey round trip the egress path takes.

Egress addresses each datagram from the connection's PathKey, so anything the
key drops is lost on the wire: a link-local (fe80::/10) peer needs its IPv6
scope id to be routable at all.
"""

from bouclette import Message
from tests._test_util import assert_true, assert_equal_int
from navette.h3.h3_udp_server import _set_msg_peer, _sockaddr_to_path_key
from navette.quic.path import PathKey


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


def _wire_sockaddr(key: PathKey) -> List[Byte]:
    """The sockaddr bytes egress hands the kernel for `key`."""
    var msg = Message(List[Byte]())
    _set_msg_peer(msg, key)
    var p = msg._peer.addr_unsafe_ptr()
    var out = List[Byte]()
    for i in range(Int(msg._peer.len)):
        out.append(p[unsafe_offset=i])
    return out^


def _reference_sockaddr(key: PathKey) -> List[Byte]:
    """The sockaddr the egress path built before it kept destinations as PathKeys: the bytes to match."""
    var v6 = key.family == Int32(10)
    var out = List[Byte](length=28 if v6 else 16, fill=Byte(0))
    out[0] = UInt8(key.family & 0xFF)
    out[2] = UInt8(key.port >> 8)
    out[3] = UInt8(key.port & 0xFF)
    for i in range(16 if v6 else 4):
        out[(8 + i) if v6 else (4 + i)] = key.addr[i if v6 else 12 + i]
    for i in range(4 if v6 else 0):  # sin6_scope_id, host order (LE)
        out[24 + i] = UInt8((key.scope_id >> UInt32(8 * i)) & 0xFF)
    return out^


def _round_trip(mut sa: List[Byte]) -> List[Byte]:
    var key = _sockaddr_to_path_key(Pointer(to=sa[0]), 0, len(sa))
    return _wire_sockaddr(key)


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


def test_wire_sockaddr_matches_reference() raises:
    var v4 = PathKey.from_v4(203, 0, 113, 9, UInt16(4433))
    _assert_same(_wire_sockaddr(v4), _reference_sockaddr(v4), "IPv4")
    var addr = InlineArray[UInt8, 16](fill=Byte(0))
    for i in range(16):
        addr[i] = UInt8(0xF0 + i) if i < 2 else UInt8(i * 17)
    var v6 = PathKey(Int32(10), addr^, UInt16(0xBEEF), UInt32(0xA1B2C3D4))
    _assert_same(_wire_sockaddr(v6), _reference_sockaddr(v6), "IPv6 with scope id")
    var msg = Message(List[Byte]())
    _set_msg_peer(msg, PathKey.zero())
    assert_equal_int(Int(msg._peer.len), 0, "an unknown family leaves the peer unset")


def main() raises:
    test_link_local_keeps_scope_id()
    test_link_local_on_two_interfaces_is_two_paths()
    test_global_v6_unchanged()
    test_v4_unchanged()
    test_wire_sockaddr_matches_reference()
    print("test_h3_sockaddr_path_key: 5 passed")
