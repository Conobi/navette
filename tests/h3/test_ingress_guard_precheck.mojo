"""IngressGuard: header checks before any connection state, and Version Negotiation pacing."""

from std.collections import Span

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.h3.ingress_guard import IngressGuard, PRE_PASS, PRE_DROP, PRE_VN
from navette.quic.packet import PacketType, parse_packet_header
from tests._test_util import assert_true, assert_equal_int
from tests.h3._wire import filled, long_packet, initial, initial_n, handshake, short_packet


def _eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def test_precheck_table(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    assert_equal_int(g.precheck(Span(initial_n(8, 1200))), PRE_PASS, "1,200 B Initial")
    assert_equal_int(g.precheck(Span(initial_n(8, 1199))), PRE_DROP, "1,199 B Initial")
    assert_equal_int(Int(g.stats.dropped_initial_size), 1, "counted")
    assert_equal_int(g.precheck(Span(long_packet(0x1A2A3A4A, 1200))), PRE_VN, "unknown version, full size")
    assert_equal_int(g.precheck(Span(long_packet(0x1A2A3A4A, 1199))), PRE_DROP, "unknown version, small")
    assert_equal_int(Int(g.stats.dropped_vn_small), 1, "vn_small")
    assert_equal_int(g.precheck(Span(long_packet(0, 1200))), PRE_DROP, "version 0 never answered")
    assert_equal_int(g.precheck(Span(initial_n(21, 1200))), PRE_DROP, "wire DCID length 21")
    assert_equal_int(g.precheck(Span(filled(0xC0, 5))), PRE_DROP, "truncated long header")
    assert_equal_int(g.precheck(Span(short_packet(40))), PRE_PASS, "short header passes to demux")
    assert_equal_int(g.precheck(Span(handshake(300))), PRE_PASS, "small Handshake packet is fine")
    assert_equal_int(Int(g.stats.dropped_undecodable), 3, "v0 + len 21 + truncated")
    assert_equal_int(g.precheck(Span(short_packet(8))), PRE_DROP, "short header shorter than a CID")
    assert_equal_int(g.precheck(Span(List[Byte]())), PRE_DROP, "empty datagram")
    assert_equal_int(Int(g.stats.dropped_undecodable), 5, "short + empty")
    # A DCID that runs past the end of a v1 long header.
    var cut = List[Byte](long_packet(1, 300, first=0xE3, dcid_len=20)[:20])
    assert_equal_int(g.precheck(Span(cut)), PRE_DROP, "DCID past the end")
    assert_equal_int(Int(g.stats.dropped_undecodable), 6, "DCID past the end counted")
    print("  test_precheck_table: PASS")


def test_gro_segment_is_checked_alone(lib: SharedLibrary) raises:
    """With GRO the server passes each segment; a 1,199 B final segment is dropped on its own length."""
    var g = IngressGuard(lib)
    var seg = initial_n(8, 1199)
    assert_equal_int(g.precheck(Span(seg)), PRE_DROP, "segment length, not the delivery length")
    print("  test_gro_segment_is_checked_alone: PASS")


def test_fixed_bit_clear_dropped(lib: SharedLibrary) raises:
    """RFC 9000 Section 17.2 / 17.3: a v1 packet with the fixed bit 0 is discarded (we never grease it)."""
    var g = IngressGuard(lib)
    assert_equal_int(g.precheck(Span(long_packet(1, 1200, first=0x83))), PRE_DROP, "v1 Initial, fixed bit 0")
    assert_equal_int(g.precheck(Span(long_packet(1, 300, first=0xA3))), PRE_DROP, "v1 Handshake, fixed bit 0")
    var short = short_packet(40)
    short[0] = 0x03
    assert_equal_int(g.precheck(Span(short)), PRE_DROP, "short header, fixed bit 0")
    assert_equal_int(Int(g.stats.dropped_undecodable), 3, "counted as undecodable")
    assert_equal_int(
        g.precheck(Span(long_packet(0x1A2A3A4A, 1200, first=0x80))), PRE_VN, "unknown version: the bit is v1-only"
    )
    print("  test_fixed_bit_clear_dropped: PASS")


def test_new_connection_filter(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    assert_equal_int(g.unknown_dcid(Span(short_packet(40))), PRE_DROP, "unknown short header")
    assert_equal_int(Int(g.stats.dropped_unknown_dcid), 1, "counted")
    assert_equal_int(g.unknown_dcid(Span(initial_n(7, 1200))), PRE_DROP, "DCID < 8")
    assert_equal_int(g.unknown_dcid(Span(initial_n(20, 1200))), PRE_PASS, "DCID 20")
    assert_equal_int(g.unknown_dcid(Span(initial_n(8, 1200))), PRE_PASS, "DCID 8")
    assert_equal_int(g.unknown_dcid(Span(handshake(300))), PRE_DROP, "unknown Handshake")
    assert_equal_int(g.unknown_dcid(Span(long_packet(1, 1200, first=0xD3))), PRE_DROP, "unknown 0-RTT")
    assert_equal_int(Int(g.stats.dropped_unknown_dcid), 3, "short + Handshake + 0-RTT")
    assert_equal_int(Int(g.stats.dropped_initial_dcid_len), 1, "dcid_len counted")
    print("  test_new_connection_filter: PASS")


def test_vn_bucket_and_layout(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var pkt = long_packet(0x1A2A3A4A, 1200, dcid_len=12, scid_len=5)
    var sent = 0
    for _ in range(10):
        if g.answer_vn(Span(pkt), UInt64(1_000_000), backlog=0):
            sent += 1
    assert_equal_int(sent, 4, "burst 4")
    assert_equal_int(Int(g.stats.stateless_bucket_empty_vn), 6, "6 refused")
    assert_true(g.answer_vn(Span(pkt), UInt64(1_010_000), backlog=0), "10 ms later: one token at 100/s")
    assert_equal_int(Int(g.stats.vn_sent), 5, "vn_sent")
    var hr = parse_packet_header(Span(g.out), 8)
    assert_true(hr[0].packet_type == PacketType.version_negotiation(), "VN in g.out")
    assert_true(_eq(hr[0].dcid.as_span(), Span(filled(0x5C, 5))), "DCID = client SCID")
    assert_true(_eq(hr[0].scid.as_span(), Span(filled(0xD1, 12))), "SCID = client DCID")
    print("  test_vn_bucket_and_layout: PASS")


def test_vn_long_cids_echoed(lib: SharedLibrary) raises:
    """RFC 8999 lets an unknown version carry CIDs up to 255 bytes; they are echoed, not refused."""
    var g = IngressGuard(lib)
    var pkt = long_packet(0x0A0A0A0A, 1200, dcid_len=255, scid_len=255)
    assert_equal_int(g.precheck(Span(pkt)), PRE_VN, "long CIDs are fine for an unknown version")
    assert_true(g.answer_vn(Span(pkt), UInt64(1_000_000), backlog=0), "answered")
    assert_equal_int(len(g.out), 1 + 4 + 1 + 255 + 1 + 255 + 4, "both CIDs echoed")
    print("  test_vn_long_cids_echoed: PASS")


def test_vn_egress_bounds(lib: SharedLibrary) raises:
    var g = IngressGuard(lib)
    var pkt = long_packet(0x1A2A3A4A, 1200)
    assert_true(not g.answer_vn(Span(pkt), UInt64(1_000_000), backlog=1280), "egress backlog full")
    assert_equal_int(Int(g.stats.stateless_dropped_egress), 1, "counted as egress drop")
    assert_equal_int(Int(g.stats.stateless_bucket_empty_vn), 0, "no token spent")
    assert_true(g.answer_vn(Span(pkt), UInt64(1_000_000), backlog=1279), "just below the bound")
    print("  test_vn_egress_bounds: PASS")


def main() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var lib = tls.shared()
    print("test_ingress_guard_precheck:")
    test_precheck_table(lib)
    test_gro_segment_is_checked_alone(lib)
    test_fixed_bit_clear_dropped(lib)
    test_new_connection_filter(lib)
    test_vn_bucket_and_layout(lib)
    test_vn_long_cids_echoed(lib)
    test_vn_egress_bounds(lib)
    print("PASS: test_ingress_guard_precheck")
    _ = tls^
