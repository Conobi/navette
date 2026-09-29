"""`demux_key`: raw for 8-byte DCIDs, keyed SipHash of the whole DCID otherwise."""

from navette.quic.cid import demux_key, dcid_to_u64
from navette.util.siphash import SipKey
from tests._test_util import assert_true
from tests.protect._prop import Rng


def test_eight_byte_dcids_stay_raw() raises:
    var rng = Rng(0x8)
    var k = SipKey(k0=UInt64(9), k1=UInt64(10))
    for _ in range(1000):
        var d = rng.bytes(8)
        assert_true(demux_key(Span(d), k) == dcid_to_u64(Span(d)), "8-byte key is the raw u64 (caps.conn_id)")
    print("PASS: test_eight_byte_dcids_stay_raw")


def test_long_dcids_sharing_a_prefix_differ() raises:
    var k = SipKey.random()
    var a = List[Byte](length=20, fill=Byte(0x11))
    var b = a.copy()
    b[19] = 0x12
    assert_true(demux_key(Span(a), k) != demux_key(Span(b), k), "20-byte DCIDs with one differing tail byte")
    var c = a.copy()
    c.resize(9, 0)
    assert_true(demux_key(Span(a), k) != demux_key(Span(c), k), "same 9-byte prefix, different length")
    print("PASS: test_long_dcids_sharing_a_prefix_differ")


def test_no_collisions_property() raises:
    """10,000 distinct DCIDs of 12..20 bytes sharing an 8-byte prefix: all keys distinct."""
    var rng = Rng(0xD0C1D)
    var k = SipKey(k0=rng.next(), k1=rng.next())
    var prefix = rng.bytes(8)
    var seen = Dict[UInt64, Int]()
    for i in range(10000):
        var d = prefix.copy()
        d.append(UInt8((i >> 24) & 0xFF))  # a counter makes every input distinct
        d.append(UInt8((i >> 16) & 0xFF))
        d.append(UInt8((i >> 8) & 0xFF))
        d.append(UInt8(i & 0xFF))
        d.extend(Span(rng.bytes(rng.below(9))))
        var key = demux_key(Span(d), k)
        assert_true(key not in seen, "collision at case " + String(i))
        seen[key] = i
    print("PASS: test_no_collisions_property")


def main() raises:
    test_eight_byte_dcids_stay_raw()
    test_long_dcids_sharing_a_prefix_differ()
    test_no_collisions_property()
