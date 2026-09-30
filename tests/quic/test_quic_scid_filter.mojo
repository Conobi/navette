"""After the first authenticated Initial fixes the peer's SCID, long-header packets with another SCID are discarded (RFC 9000 Section 7.2).

The filter covered Initials only and never engaged when the first SCID
was zero-length, so a later Initial with another SCID could re-point
`peer_cid`.
"""

from std.collections import Span

from navette.quic.packet import parse_packet_header
from navette.quic.packet_protect import PacketProtect
from tests._test_util import assert_true, assert_equal_int
from tests.quic.test_quic_coalesced import Fixture


def _forged(f: Fixture, scid: List[Byte], pn: UInt8) raises -> List[Byte]:
    """A 1,200-byte datagram holding one client Initial (PING) with any SCID, sealed with the client's Initial keys."""
    var protect = PacketProtect(f.tls.shared())
    protect.derive_initial_keys(f.client.initial_dcid.as_span(), is_client=True)
    var plaintext_len = 20
    var dcid = f.own_dcid()
    var out = List[Byte]()
    out.append(0xC0)
    out.append(0)
    out.append(0)
    out.append(0)
    out.append(1)
    out.append(UInt8(len(dcid)))
    out.extend(Span(dcid))
    out.append(UInt8(len(scid)))
    out.extend(Span(scid))
    out.append(0)  # token length
    var length_field = 1 + plaintext_len + 16
    out.append(UInt8(0x40 | (length_field >> 8)))
    out.append(UInt8(length_field & 0xFF))
    var pn_offset = len(out)
    out.append(pn)
    var payload_start = len(out)
    out.append(0x01)
    out.resize(payload_start + plaintext_len + 16, Byte(0))
    var total = len(out)
    var ptr = out.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()
    _ = protect.encrypt_payload_in_place(0, UInt64(pn), ptr, payload_start, plaintext_len, total)
    protect.protect_header_ptr(0, ptr, total, pn_offset, 1)
    out.resize(1200, Byte(0))
    return out^


def _long_header(type_bits: UInt8, scid: List[Byte]) -> List[Byte]:
    """A long header (Handshake: type_bits 0x20) with an 8-byte DCID, `scid` and a 30-byte body."""
    var out = List[Byte]()
    out.append(0xC0 | type_bits)
    out.append(0)
    out.append(0)
    out.append(0)
    out.append(1)
    out.append(8)
    for _ in range(8):
        out.append(0x11)
    out.append(UInt8(len(scid)))
    out.extend(Span(scid))
    out.append(30)  # length
    for _ in range(30):
        out.append(0)
    return out^


def test_handshake_from_other_scid_dropped() raises:
    var f = Fixture()
    f.server.recv(Span(f.first), f.now)
    var own = List[Byte](f.client.local_cid.as_span())
    var other = List[Byte](length=8, fill=0x77)
    var hs_other = parse_packet_header(Span(_long_header(0x20, other)), 8)[0].copy()
    var hs_own = parse_packet_header(Span(_long_header(0x20, own)), 8)[0].copy()
    assert_true(f.server._is_long_from_other_scid(hs_other), "Handshake with another SCID dropped")
    assert_true(not f.server._is_long_from_other_scid(hs_own), "Handshake with the adopted SCID kept")
    print("  test_handshake_from_other_scid_dropped: PASS")


def test_zero_length_scid_adopted() raises:
    var f = Fixture()
    f.server.recv(Span(_forged(f, List[Byte](), 0)), f.now)
    assert_true(f.server.last_datagram_authenticated, "the forged Initial authenticates")
    assert_true(Bool(f.server._initial_peer_scid), "an empty SCID is adopted")
    assert_equal_int(len(f.server.peer_cid), 0, "peer_cid is the empty SCID")
    f.server.recv(Span(_forged(f, List[Byte](f.client.local_cid.as_span()), 1)), f.now)
    assert_equal_int(f.server.spaces[0].largest_recv_pn, 0, "a later Initial with another SCID is discarded")
    assert_equal_int(len(f.server.peer_cid), 0, "peer_cid unchanged")
    print("  test_zero_length_scid_adopted: PASS")


def main() raises:
    print("test_quic_scid_filter:")
    test_handshake_from_other_scid_dropped()
    test_zero_length_scid_adopted()
    print("All test_quic_scid_filter tests passed.")
