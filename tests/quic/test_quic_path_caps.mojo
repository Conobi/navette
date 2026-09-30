"""Path validation state stays bounded and moves only on authenticated datagrams (RFC 9000 Sections 8.2, 9, 9.3).

A peer can send PATH_CHALLENGE frames and change its source address as
fast as it likes: queued PATH_RESPONSEs and pending challenges are capped
(quiche keeps 3 received challenges; we keep at most 4 of our own), an
address change seen on a datagram that does not decrypt does nothing, and
a server that advertised disable_active_migration drops datagrams from a
new address instead of closing.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.path import (
    PathKey,
    PathState,
    PathValidator,
    MAX_PENDING_CHALLENGES,
    MAX_PENDING_RESPONSES,
)
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca
from tests.protect._prop import Rng, prop_iters


def _tok8(i: Int) -> List[Byte]:
    var t = List[Byte](capacity=8)
    for k in range(8):
        t.append(UInt8((i >> (k % 4 * 8)) & 0xFF))
    return t^


def _path_key(i: Int) -> PathKey:
    return PathKey.from_v4(10, 0, UInt8(i // 256), UInt8(i % 256), UInt16(4000 + i))


def _path_state() -> PathState:
    var ps = PathState()
    return ps^


def test_response_ring_keeps_three_newest() raises:
    var ps = _path_state()
    for i in range(10_000):
        ps.on_challenge_received(Span(_tok8(i)))
    assert_equal_int(ps.pending_response_count(), MAX_PENDING_RESPONSES, "ring of 3")
    assert_equal_int(Int(ps.pending_response(0)[0]), 9_997 & 0xFF, "oldest kept is the third newest")
    var frames = ps.emit_response_frames(max_n=2)
    assert_equal_int(len(frames), 2, "emits what fits")
    assert_equal_int(ps.pending_response_count(), 1, "the rest stays queued")
    assert_equal_int(Int(ps.pending_response(0)[0]), 9_999 & 0xFF, "newest left")
    print("  test_response_ring_keeps_three_newest: PASS")


def test_pending_challenges_capped() raises:
    var pv = PathValidator()
    var started = 0
    for i in range(20):
        if pv.start_challenge(_path_key(i), UInt64(1_000)):
            started += 1
    assert_equal_int(started, MAX_PENDING_CHALLENGES, "4 pending at most")
    assert_equal_int(len(pv.pending), MAX_PENDING_CHALLENGES, "list bounded")
    print("  test_pending_challenges_capped: PASS")


def test_challenge_flood_property() raises:
    var iters = prop_iters(200)
    for idx in range(iters):
        var seed = UInt64(0xC0FFEE) + UInt64(idx)
        var rng = Rng(seed)
        var ps = _path_state()
        var now = UInt64(1_000)
        for step in range(60):
            var op = rng.below(5)
            if op == 0:
                ps.on_challenge_received(Span(rng.bytes(8)))
            elif op == 1:
                _ = ps.emit_response_frames(max_n=rng.below(4))
            elif op == 2:
                _ = ps.begin_challenge(_path_key(rng.below(10)), now)
            elif op == 3:
                now += UInt64(rng.below(2_000_000))
                ps.validator.gc_expired(now, UInt64(100_000))
            else:
                _ = ps.validator.on_response(Span(rng.bytes(8)), _path_key(rng.below(10)), now)
            var where = " (seed " + String(seed) + ", case " + String(idx) + ", step " + String(step) + ")"
            assert_true(ps.pending_response_count() <= MAX_PENDING_RESPONSES, "responses <= 3" + where)
            assert_true(len(ps.validator.pending) <= MAX_PENDING_CHALLENGES, "pending <= 4" + where)
    print("  test_challenge_flood_property: PASS (" + String(iters) + " cases)")


def test_send_gate_is_default_deny() raises:
    """With four challenges pending, a fifth address gets nothing: only the validated or a pending path may be sent to."""
    var ps = _path_state()
    ps.seed_peer_addr(_path_key(1000))
    for i in range(MAX_PENDING_CHALLENGES):
        assert_true(ps.begin_challenge(_path_key(i), UInt64(1_000)), "challenge started")
    assert_true(not ps.begin_challenge(_path_key(99), UInt64(1_000)), "the fifth is refused")
    assert_true(not ps.can_send(_path_key(99), 1), "no byte to an address with no challenge")
    assert_true(ps.can_send(_path_key(1000), 65_536), "the validated path is not budgeted")
    assert_true(not ps.can_send(_path_key(0), 1), "a pending path starts with no budget")
    ps.validator.record_received_bytes(_path_key(0), 100)
    assert_true(ps.can_send(_path_key(0), 300), "3x what it sent")
    assert_true(not ps.can_send(_path_key(0), 301), "and no more")
    print("  test_send_gate_is_default_deny: PASS")


# ── Connection-level: the ingress sequence the H3 server runs ─────────────


def _params(disable_migration: Bool) -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.disable_active_migration = disable_migration
    return p^


struct Pair(Movable):
    """An established client / server pair; the server believes the client is at `home`."""

    var tls: TlsBackend
    var client: QuicConnection
    var server: QuicConnection
    var now: UInt64

    def __init__(out self, disable_migration: Bool) raises:
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        var scfg = QuicServerConfig(self.tls.shared(), Span(cert), Span(key))
        var ccfg = QuicClientConfig.with_ca(self.tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        self.client = QuicConnection.client(self.tls.shared(), ccfg, "localhost", _params(False), self.now)
        var orig = List[Byte](self.client.initial_dcid.as_span())
        var orig2 = orig.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, _params(disable_migration), Span(orig), Span(orig2), self.now
        )
        self.server.bootstrap_peer_addr(_home())
        for _ in range(20):
            self.now += UInt64(10_000)
            for ref d in self.client_datagrams():
                _ = self.feed_server(d, _home())
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

    def client_datagrams(mut self) raises -> List[List[Byte]]:
        var out = List[List[Byte]]()
        _ = self.client.send(self.now, out)
        return out^

    def feed_server(mut self, dg: List[Byte], var from_addr: PathKey) raises -> Bool:
        """What H3UdpServer does per datagram: drop check, feed, then path bookkeeping only if it authenticated.

        True when the server would move its send destination to `from_addr`.
        """
        if self.server.should_drop_from(from_addr):
            return False
        try:
            self.server.recv(Span(dg), self.now)
        except:
            pass
        if self.server.last_datagram_authenticated:
            return self.server.note_authenticated_ingress(from_addr^, len(dg), self.now)
        return False


def _home() -> PathKey:
    return PathKey.from_v4(127, 0, 0, 1, 5000)


def _away() -> PathKey:
    return PathKey.from_v4(127, 0, 0, 2, 6000)


def _garbage_short(dcid: Span[Byte, _]) -> List[Byte]:
    var p = List[Byte]()
    p.append(0x41)
    p.extend(dcid)
    for i in range(40):
        p.append(UInt8(i * 7))
    return p^


def test_unauthenticated_datagram_starts_no_challenge() raises:
    var p = Pair(disable_migration=False)
    _ = p.feed_server(_garbage_short(p.server.local_cid.as_span()), _away())
    assert_true(not p.server.last_datagram_authenticated, "garbage does not authenticate")
    assert_equal_int(len(p.server.path.validator.pending), 0, "no challenge from an unauthenticated datagram")
    # Positive control: a real client packet from the new address starts one.
    var sid = p.client.open_stream(True)
    p.client.send_stream_data(sid, Span(List[Byte](length=4, fill=Byte(1))), False)
    for ref d in p.client_datagrams():
        _ = p.feed_server(d, _away())
    assert_equal_int(len(p.server.path.validator.pending), 1, "an authenticated datagram does")
    print("  test_unauthenticated_datagram_starts_no_challenge: PASS")


def test_migration_disabled_drops_not_closes() raises:
    var p = Pair(disable_migration=True)
    assert_true(p.server.should_drop_from(_away()), "new address dropped")
    assert_true(not p.server.should_drop_from(_home()), "home address kept")
    var before = p.server.bytes_received
    var sid = p.client.open_stream(True)
    p.client.send_stream_data(sid, Span(List[Byte](length=4, fill=Byte(1))), False)
    for ref d in p.client_datagrams():
        _ = p.feed_server(d, _away())
    assert_equal_int(Int(p.server.bytes_received), Int(before), "nothing fed from the new address")
    assert_true(not p.server.is_closing() and not p.server.is_closed(), "not closed")
    assert_equal_int(len(p.server.path.validator.pending), 0, "no challenge")
    print("  test_migration_disabled_drops_not_closes: PASS")


def _settle(mut p: Pair) raises:
    """Exchange until neither side has anything left to send."""
    for _ in range(6):
        p.now += UInt64(30_000)
        for ref d in p.client_datagrams():
            _ = p.feed_server(d, _home())
        var s_dg = List[List[Byte]]()
        _ = p.server.send(p.now, s_dg)
        for ref d in s_dg:
            try:
                p.client.recv(Span(d), p.now)
            except:
                pass


def _stream_datagrams(mut p: Pair) raises -> List[List[Byte]]:
    """Client datagrams carrying 4 bytes on a fresh stream (non-probing, ack-eliciting)."""
    var sid = p.client.open_stream(True)
    p.client.send_stream_data(sid, Span(List[Byte](length=4, fill=Byte(1))), False)
    return p.client_datagrams()


def test_replayed_packet_is_dropped() raises:
    """RFC 9000 Section 12.3: an already-processed packet number is discarded, from any address."""
    var p = Pair(disable_migration=False)
    _settle(p)
    var dgs = _stream_datagrams(p)
    assert_true(len(dgs) >= 1, "client produced a datagram")
    _ = p.feed_server(dgs[0], _home())
    assert_true(p.server.last_datagram_authenticated, "the original authenticates")
    var ae_before = p.server.spaces[2].ack_eliciting_since_last_ack
    var largest_before = p.server.spaces[2].largest_recv_pn
    _ = p.feed_server(dgs[0], _away())
    assert_true(not p.server.last_datagram_authenticated, "a replay does not authenticate")
    assert_equal_int(len(p.server.path.validator.pending), 0, "a replay starts no challenge")
    assert_equal_int(
        p.server.spaces[2].ack_eliciting_since_last_ack, ae_before, "a replay owes no ACK"
    )
    assert_equal_int(p.server.spaces[2].largest_recv_pn, largest_before, "PN state unchanged")
    assert_true(not p.server.last_datagram_may_migrate, "a replay never moves the address")
    print("  test_replayed_packet_is_dropped: PASS")


def test_only_newest_non_probing_may_migrate() raises:
    """RFC 9000 Section 9.3: a probing-only packet starts validation but moves nothing; a newer non-probing one may."""
    var p = Pair(disable_migration=False)
    _settle(p)
    _ = p.client.start_path_challenge(_away(), p.now)
    var probe = p.client_datagrams()
    assert_true(len(probe) >= 1, "client produced a probe")
    _ = p.feed_server(probe[0], _away())
    assert_true(p.server.last_datagram_authenticated, "the probe authenticates")
    assert_true(not p.server.last_datagram_may_migrate, "a probing-only packet does not migrate")
    assert_equal_int(len(p.server.path.validator.pending), 1, "the probe starts validation")
    # Newer, non-probing: may move. An older non-probing one held back may not.
    var older = _stream_datagrams(p)
    var newer = _stream_datagrams(p)
    assert_true(p.feed_server(newer[0], _away()), "the destination moves to the address under validation")
    assert_true(p.server.last_datagram_may_migrate, "the newest non-probing packet may migrate")
    assert_true(not p.feed_server(older[0], _home()), "a reordered packet moves nothing")
    assert_true(p.server.last_datagram_authenticated, "a reordered packet is still processed")
    assert_true(not p.server.last_datagram_may_migrate, "a reordered packet does not migrate")
    print("  test_only_newest_non_probing_may_migrate: PASS")


def test_full_challenge_cap_refuses_new_address() raises:
    """Four authenticated datagrams from junk sources fill the cap; a fifth source is dropped and never sent to."""
    var p = Pair(disable_migration=False)
    _settle(p)
    for i in range(MAX_PENDING_CHALLENGES):
        for ref d in _stream_datagrams(p):
            _ = p.feed_server(d, _path_key(i))
    assert_equal_int(len(p.server.path.validator.pending), MAX_PENDING_CHALLENGES, "cap filled")
    assert_true(p.server.should_drop_from(_away()), "a fifth source is dropped before decryption")
    assert_true(not p.server.can_send_to(_away(), 1), "and nothing may be sent to it")
    assert_true(p.server.can_send_to(_home(), 65_536), "the validated path is unaffected")
    print("  test_full_challenge_cap_refuses_new_address: PASS")


def test_pending_challenges_expire_on_the_timer() raises:
    """Pending challenges are dropped 3 x max(PTO, kInitialRtt PTO) after they start, and `timeout` wakes for it."""
    var p = Pair(disable_migration=False)
    _settle(p)
    for ref d in _stream_datagrams(p):
        _ = p.feed_server(d, _away())
    assert_equal_int(len(p.server.path.validator.pending), 1, "challenge pending")
    assert_true(p.server.is_usable_destination(_away()), "usable while under validation")
    var t = p.server.timeout(p.now)
    assert_true(Bool(t), "a deadline is armed")
    p.now += UInt64(3_100_000)
    var out = List[List[Byte]]()
    _ = p.server.send(p.now, out)
    assert_equal_int(len(p.server.path.validator.pending), 0, "expired on the timer")
    assert_true(not p.server.is_usable_destination(_away()), "an expired address is no destination")
    assert_true(not p.server.can_send_to(_away(), 1), "and gets nothing")
    assert_true(p.server.is_usable_destination(_home()), "the validated address stays")
    print("  test_pending_challenges_expire_on_the_timer: PASS")


def main() raises:
    print("test_quic_path_caps:")
    test_response_ring_keeps_three_newest()
    test_pending_challenges_capped()
    test_challenge_flood_property()
    test_send_gate_is_default_deny()
    test_unauthenticated_datagram_starts_no_challenge()
    test_migration_disabled_drops_not_closes()
    test_replayed_packet_is_dropped()
    test_only_newest_non_probing_may_migrate()
    test_full_challenge_cap_refuses_new_address()
    test_pending_challenges_expire_on_the_timer()
    print("All test_quic_path_caps tests passed.")
