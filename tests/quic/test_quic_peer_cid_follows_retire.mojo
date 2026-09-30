# tests/quic/test_quic_peer_cid_follows_retire.mojo
#
# Once we retire one of the peer's CIDs we must stop addressing packets
# to it (RFC 9000 Section 5.1.2): the DCID we send with follows the
# active remote CID whenever retire_prior_to or a path rotation moves it.

from std.collections import Span
from navette.quic.connection import QuicConnection
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.tls.lib import TlsBackend
from tests._test_util import (
    assert_true, assert_equal_int, load_test_cert, load_test_ca,
)
from tests.h3._h3_raw_pair import RawPair, raw_params


def _cid_and_token(tag: UInt8) -> List[Byte]:
    """[8-byte CID filled with `tag` | 16-byte reset token]."""
    var d = List[Byte](capacity=24)
    for _ in range(8):
        d.append(tag)
    for _ in range(16):
        d.append(0x77)
    return d^


def _retire_queued(ref p: RawPair, seq: UInt64) -> Bool:
    for ref s in p.cli.cid_mgr.retire_queue:
        if s == seq:
            return True
    return False


def _sent_dcid_is(mut p: RawPair, cid: List[Byte]) raises -> Bool:
    """True if the client's next datagram is short-header addressed to `cid`."""
    var scratch = List[List[Byte]](capacity=1)
    p.now += UInt64(10_000)
    var n = p.cli.send(p.now, scratch)
    assert_true(n > 0, "client has something to send")
    ref dg = scratch[0]
    assert_true((dg[0] & 0x80) == 0, "1-RTT short header")
    for i in range(len(cid)):
        if dg[1 + i] != cid[i]:
            return False
    return True


def test_retire_prior_to_moves_outgoing_dcid() raises:
    var p = RawPair()
    var d = _cid_and_token(0xC1)
    var seq = UInt64(1_000)
    p.cli._on_new_cid_from_cursor(seq, seq, Span(d), 8, p.now)
    assert_true(not p.cli.close.pending, "frame accepted")
    assert_equal_int(Int(p.cli.cid_mgr.remote_active_cid_seq), Int(seq), "active seq moved")
    assert_true(_retire_queued(p, UInt64(0)), "RETIRE_CONNECTION_ID for seq 0 queued")
    assert_true(_sent_dcid_is(p, List[Byte](d[:8])), "packets go to the new CID")
    print("  test_retire_prior_to_moves_outgoing_dcid: PASS")


def test_rotation_moves_outgoing_dcid() raises:
    var p = RawPair()
    if len(p.cli.cid_mgr.remote_cids) < 2:
        # No spare issued by the server yet: supply one.
        var d = _cid_and_token(0xC2)
        p.cli._on_new_cid_from_cursor(UInt64(1_000), UInt64(0), Span(d), 8, p.now)
        assert_true(not p.cli.close.pending, "frame accepted")
    var old_seq = p.cli.cid_mgr.remote_active_cid_seq
    assert_true(p.cli._rotate_to_spare_remote_cid(p.now), "rotated")
    assert_true(_retire_queued(p, old_seq), "old CID retired")
    var active = p.cli.cid_mgr.remote_active_cid_seq
    var cid = List[Byte]()
    for ref e in p.cli.cid_mgr.remote_cids:
        if e.sequence == active:
            cid = e.cid.copy()
    assert_equal_int(len(cid), 8, "active entry present")
    assert_true(_sent_dcid_is(p, cid), "packets go to the rotated-to CID")
    print("  test_rotation_moves_outgoing_dcid: PASS")


def test_unauthenticated_initial_does_not_redirect() raises:
    var p = RawPair()
    var before = List[Byte](p.cli.peer_cid.as_span())
    # Long-header Initial, SCID 0xEE*8, garbage protected payload.
    var pkt: List[Byte] = [0xC3, 0x00, 0x00, 0x00, 0x01, 0x08]
    pkt.extend(p.cli.local_cid.as_span())
    pkt.append(0x08)
    for _ in range(8):
        pkt.append(0xEE)
    pkt.append(0x00)  # token length
    pkt.append(0x40)  # length = 64 (2-byte varint)
    pkt.append(0x40)
    for _ in range(64):
        pkt.append(0x5C)
    try:
        p.cli.recv(Span(pkt), p.now)
    except:
        pass
    assert_true(
        _eq(p.cli.peer_cid.as_span(), Span(before)),
        "a forged Initial must not change the DCID we send to",
    )
    print("  test_unauthenticated_initial_does_not_redirect: PASS")


def _eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _seq0_cid(ref q: QuicConnection) -> List[Byte]:
    """The CID recorded for the peer's sequence number 0 (empty if gone)."""
    for ref e in q.cid_mgr.remote_cids:
        if e.sequence == UInt64(0):
            return e.cid.copy()
    return List[Byte]()


def test_seq0_holds_the_adopted_scid() raises:
    var p = RawPair()
    assert_true(
        _eq(Span(_seq0_cid(p.cli)), p.srv._quic.local_cid.as_span()),
        "client: seq 0 is the server's SCID",
    )
    assert_true(
        _eq(Span(_seq0_cid(p.srv._quic)), p.cli.local_cid.as_span()),
        "server: seq 0 is the client's SCID",
    )
    assert_true(
        _eq(p.cli.peer_cid.as_span(), p.srv._quic.local_cid.as_span()),
        "client addresses the server's SCID",
    )
    assert_true(
        _eq(p.srv._quic.peer_cid.as_span(), p.cli.local_cid.as_span()),
        "server addresses the client's SCID",
    )
    print("  test_seq0_holds_the_adopted_scid: PASS")


def test_second_initial_with_other_scid_is_discarded() raises:
    """Two servers answer the same client Initial (same Initial keys,
    different SCIDs): only the first to arrive is adopted."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var srv_cfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var cli = QuicConnection.client(
        tls.shared(), cli_cfg, "localhost", raw_params(), now
    )
    var odcid = List[Byte](cli.initial_dcid.as_span())
    var cdcid = List[Byte](cli.initial_dcid.as_span())
    var s1 = QuicConnection.server(
        tls.shared(), srv_cfg, raw_params(), Span(odcid), Span(cdcid), now,
    )
    var s2 = QuicConnection.server(
        tls.shared(), srv_cfg, raw_params(), Span(odcid), Span(cdcid), now,
    )
    var out = List[List[Byte]](capacity=1)
    var n = cli.send(now, out)
    assert_true(n > 0, "client Initial")
    for i in range(n):
        s1.recv(Span(out[i]), now)
        s2.recv(Span(out[i]), now)
    var from_s1 = List[List[Byte]](capacity=1)
    var from_s2 = List[List[Byte]](capacity=1)
    assert_true(s1.send(now, from_s1) > 0, "s1 answers")
    assert_true(s2.send(now, from_s2) > 0, "s2 answers")
    cli.recv(Span(from_s1[0]), now)
    assert_true(
        _eq(cli.peer_cid.as_span(), s1.local_cid.as_span()), "adopted s1's SCID"
    )
    try:
        cli.recv(Span(from_s2[0]), now)
    except:
        pass
    assert_true(
        _eq(cli.peer_cid.as_span(), s1.local_cid.as_span()),
        "a later Initial with another SCID must not redirect us",
    )
    assert_true(
        _eq(Span(_seq0_cid(cli)), s1.local_cid.as_span()), "seq 0 unchanged"
    )
    _ = s2.local_cid
    _ = tls^
    print("  test_second_initial_with_other_scid_is_discarded: PASS")


def main() raises:
    print("test_quic_peer_cid_follows_retire:")
    test_retire_prior_to_moves_outgoing_dcid()
    test_rotation_moves_outgoing_dcid()
    test_unauthenticated_initial_does_not_redirect()
    test_seq0_holds_the_adopted_scid()
    test_second_initial_with_other_scid_is_discarded()
    print("All test_quic_peer_cid_follows_retire tests passed.")
