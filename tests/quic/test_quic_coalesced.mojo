"""Coalesced packets at a QUIC server: a foreign DCID ends the datagram, an Initial in a small datagram is ignored, and the peer CID comes only from an authenticated Initial (RFC 9000 Sections 12.2, 14.1, 7.2).

The forged packets are sealed with the client's real Initial keys, so
only the DCID or the datagram size tells them apart from genuine ones;
each check has a positive control proving the forged packet is otherwise
accepted.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.packet_protect import PacketProtect
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _send_all(mut conn: QuicConnection, now: UInt64) raises -> List[List[Byte]]:
    var out = List[List[Byte]]()
    for _ in range(16):
        var batch = List[List[Byte]]()
        if conn.send(now, batch) == 0:
            break
        for ref d in batch:
            out.append(d.copy())
    return out^


def _eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


struct Fixture(Movable):
    """A client's first Initial datagram and a server that has not seen it yet."""

    var tls: TlsBackend
    var client: QuicConnection
    var server: QuicConnection
    var first: List[Byte]
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
        var dgs = _send_all(self.client, self.now)
        assert_true(len(dgs) >= 1, "a first flight")
        self.first = dgs[0].copy()
        var orig = List[Byte](self.client.initial_dcid.as_span())
        var orig2 = orig.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), self.now
        )

    def forged(self, dcid: List[Byte], pn: UInt8) raises -> List[Byte]:
        """A 60-byte client Initial carrying PING, sealed with this client's Initial keys, with any header DCID."""
        var protect = PacketProtect(self.tls.shared())
        protect.derive_initial_keys(self.client.initial_dcid.as_span(), is_client=True)
        var plaintext_len = 20
        var out = List[Byte]()
        out.append(0xC0)  # Initial, 1-byte packet number
        out.append(0)
        out.append(0)
        out.append(0)
        out.append(1)
        out.append(UInt8(len(dcid)))
        out.extend(Span(dcid))
        var scid = self.client.local_cid.as_span()
        out.append(UInt8(len(scid)))
        out.extend(scid)
        out.append(0)  # token length
        var length_field = 1 + plaintext_len + 16
        out.append(UInt8(0x40 | (length_field >> 8)))
        out.append(UInt8(length_field & 0xFF))
        var pn_offset = len(out)
        out.append(pn)
        var payload_start = len(out)
        out.append(0x01)  # PING, then PADDING
        out.resize(payload_start + plaintext_len + 16, Byte(0))
        var total = len(out)
        var ptr = out.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()
        _ = protect.encrypt_payload_in_place(0, UInt64(pn), ptr, payload_start, plaintext_len, total)
        protect.protect_header_ptr(0, ptr, total, pn_offset, 1)
        return out^

    def own_dcid(self) -> List[Byte]:
        return List[Byte](self.client.initial_dcid.as_span())


def test_foreign_dcid_ends_datagram() raises:
    """A coalesced packet whose DCID differs from the first packet's is not processed."""
    var f = Fixture()
    var dg = f.first.copy()
    dg.extend(Span(f.forged(List[Byte](length=8, fill=0x99), 5)))
    f.server.recv(Span(dg), f.now)
    assert_equal_int(f.server.spaces[0].largest_recv_pn, 0, "the foreign-DCID packet was not processed")
    assert_true(f.server.last_datagram_authenticated, "the first packet authenticated")

    var g = Fixture()
    var ok = g.first.copy()
    ok.extend(Span(g.forged(g.own_dcid(), 5)))
    g.server.recv(Span(ok), g.now)
    assert_equal_int(g.server.spaces[0].largest_recv_pn, 5, "control: the same packet with the first DCID is processed")
    print("  test_foreign_dcid_ends_datagram: PASS")


def test_initial_in_small_datagram_dropped() raises:
    """RFC 9000 Section 14.1: a server ignores an Initial in a datagram under 1,200 bytes, coalesced or not."""
    var f = Fixture()
    f.server.recv(Span(f.first), f.now)
    var small = f.forged(f.own_dcid(), 5)
    small.extend(Span(f.forged(f.own_dcid(), 6)))
    f.server.recv(Span(small), f.now)
    assert_equal_int(f.server.spaces[0].largest_recv_pn, 0, "Initials in a 120-byte datagram ignored")
    assert_true(not f.server.last_datagram_authenticated, "nothing authenticated in that datagram")

    var full = f.forged(f.own_dcid(), 7)
    full.resize(1200, Byte(0))  # trailing zeros end the datagram's packets
    f.server.recv(Span(full), f.now)
    assert_equal_int(f.server.spaces[0].largest_recv_pn, 7, "control: the same Initial in a 1,200-byte datagram is processed")
    assert_true(f.server.last_datagram_authenticated, "authenticated")
    print("  test_initial_in_small_datagram_dropped: PASS")


def test_unauthenticated_initial_cannot_rewrite_peer_cid() raises:
    """Pin: an Initial that does not decrypt never sets `peer_cid`."""
    var f = Fixture()
    f.server.recv(Span(f.first), f.now)
    var before = List[Byte](f.server.peer_cid.as_span())
    var bogus = f.forged(f.own_dcid(), 5)
    bogus[len(bogus) - 1] ^= 0x01  # break the AEAD tag
    bogus.resize(1200, Byte(0))
    f.server.recv(Span(bogus), f.now)
    assert_true(_eq(f.server.peer_cid.as_span(), Span(before)), "peer_cid unchanged")
    print("  test_unauthenticated_initial_cannot_rewrite_peer_cid: PASS")


def main() raises:
    print("test_quic_coalesced:")
    test_foreign_dcid_ends_datagram()
    test_initial_in_small_datagram_dropped()
    test_unauthenticated_initial_cannot_rewrite_peer_cid()
    print("PASS: test_quic_coalesced")
