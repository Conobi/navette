"""Packet-number skipping defends against optimistic ACKs only if the skips are secret and checked (RFC 9000 Sections 13.1, 21.4).

The seed used to come from our SCID, which the peer sees on the wire, so
the peer could predict every skipped number (quiche CVE-2025-4820). An
ACK of a skipped or never-sent packet number now closes the connection
with PROTOCOL_VIOLATION instead of raising out of the datagram.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.frame import AckFrame, AckRange
from navette.quic.pn_space import PacketNumberSpace, EncryptionLevel
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _space(seed: UInt64) -> PacketNumberSpace:
    var s = PacketNumberSpace(EncryptionLevel.application())
    s.pn_skip_rng = seed
    s.pn_skip_next = UInt64(50)
    return s^


def _ack(largest: UInt64, first_range: UInt64) -> AckFrame:
    var a = AckFrame()
    a.largest_ack = largest
    a.first_ack_range = first_range
    return a^


def test_skipped_pn_ack_rejected() raises:
    var s = _space(0x9E3779B97F4A7C15)
    for _ in range(600):
        _ = s.alloc_pn()
    assert_true(s.skip_hi > s.skip_lo, "600 allocations skip at least once")
    var no_ranges = List[AckRange]()
    var ok = s.on_ack_received(_ack(10, 10), Span(no_ranges))
    assert_true(not s.ack_violation, "ACK of sent PNs 0..10 accepted")
    assert_equal_int(len(ok), 0, "nothing was in flight")
    var bad = s.on_ack_received(_ack(s.skip_lo, 0), Span(no_ranges))
    assert_true(s.ack_violation, "ACK of a skipped PN flagged")
    assert_equal_int(len(bad), 0, "flagged ACK acknowledges nothing")
    # The last number of a gap, reached through a second range.
    var t = _space(0x9E3779B97F4A7C15)
    for _ in range(600):
        _ = t.alloc_pn()
    var last = t.skip_hi - 1
    var ranges = List[AckRange]()
    ranges.append(AckRange(gap=0, ack_range=0))  # covers largest - 2
    _ = t.on_ack_received(_ack(last + 2, 0), Span(ranges))
    assert_true(t.ack_violation, "a skipped PN inside a later ACK range is flagged")
    print("  test_skipped_pn_ack_rejected: PASS")


def test_ack_at_next_pn_flagged_not_raised() raises:
    var s = _space(0)
    for _ in range(5):
        _ = s.alloc_pn()
    var no_ranges = List[AckRange]()
    _ = s.on_ack_received(_ack(s.next_pn, 0), Span(no_ranges))
    assert_true(s.ack_violation, "ACK of a never-sent PN flagged")
    print("  test_ack_at_next_pn_flagged_not_raised: PASS")


struct Pair(Movable):
    var tls: TlsBackend
    var client: QuicConnection
    var server: QuicConnection
    var now: UInt64

    def __init__(out self) raises:
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var scfg = QuicServerConfig(self.tls.shared(), Span(cert), Span(key))
        var ccfg = QuicClientConfig.with_ca(self.tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        self.client = QuicConnection.client(self.tls.shared(), ccfg, "localhost", default_transport_params(), self.now)
        var orig = List[Byte](self.client.initial_dcid.as_span())
        var orig2 = orig.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), self.now
        )
        for _ in range(20):
            self.now += UInt64(10_000)
            var c_dg = List[List[Byte]]()
            _ = self.client.send(self.now, c_dg)
            for ref d in c_dg:
                try:
                    self.server.recv(Span(d), self.now)
                except:
                    pass
            var s_dg = List[List[Byte]]()
            _ = self.server.send(self.now, s_dg)
            for ref d in s_dg:
                try:
                    self.client.recv(Span(d), self.now)
                except:
                    pass
            if self.client.is_established() and self.server.is_established():
                break
        assert_true(self.server.is_established(), "handshake")


def _cid_seed(cid: Span[Byte, _]) -> UInt64:
    """The seed the old code derived from the SCID."""
    var seed = UInt64(0)
    for i in range(min(8, len(cid))):
        seed = (seed << 8) | UInt64(cid[i])
    return seed


def test_seed_not_from_cid() raises:
    var a = Pair()
    var b = Pair()
    var sa = a.server.spaces[2].pn_skip_rng
    var sb = b.server.spaces[2].pn_skip_rng
    assert_true(sa != 0 and sb != 0, "skipping enabled")
    assert_true(sa != _cid_seed(a.server.local_cid.as_span()), "seed is not the SCID")
    assert_true(sa != sb, "two connections draw different seeds")
    print("  test_seed_not_from_cid: PASS")


def test_ack_above_next_pn_closes() raises:
    var p = Pair()
    var no_ranges = List[AckRange]()
    p.server._handle_ack(_ack(p.server.spaces[2].next_pn + 3, 0), Span(no_ranges), 2, p.now)
    assert_true(Bool(p.server.close.pending), "server closes")
    assert_equal_int(Int(p.server.close.pending.value().error_code), 0x0A, "PROTOCOL_VIOLATION")
    print("  test_ack_above_next_pn_closes: PASS")


def main() raises:
    print("test_quic_pn_skip:")
    test_skipped_pn_ack_rejected()
    test_ack_at_next_pn_flagged_not_raised()
    test_seed_not_from_cid()
    test_ack_above_next_pn_closes()
    print("All test_quic_pn_skip tests passed.")
