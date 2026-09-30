"""Server-side path validation of a peer's new address (RFC 9000 Sections 8.2, 9)."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.path import PathKey, MAX_CHALLENGE_ATTEMPTS
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _server() raises -> QuicConnection:
    """A server connection, handshake not driven: path state only."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
    var odcid = List[Byte](client.initial_dcid.as_span())
    var odcid2 = odcid.copy()
    var server = QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(odcid), Span(odcid2), now
    )
    _ = tls^
    return server^


def _addr(last: UInt8, port: UInt16) -> PathKey:
    return PathKey.from_v4(UInt8(10), UInt8(0), UInt8(0), last, port)


def test_rebind_without_spare_cid_completes() raises:
    """A validated new address becomes the peer address even with no spare
    remote CID: the current CID is kept (RFC 9000 Section 9.5 allows it for
    a peer-initiated address change) instead of stalling on a path the gate
    then denies."""
    var conn = _server()
    assert_equal_int(len(conn.cid_mgr.remote_cids), 1, "no spare remote CID")
    conn.bootstrap_peer_addr(_addr(1, 5000))
    _ = conn.start_path_challenge(_addr(2, 6000), UInt64(1000))
    var token = List[Byte](copy=conn.path.validator.pending[0].token)
    var cid_before = List[Byte](conn.peer_cid.as_span())
    conn.on_path_response_received(Span(token), _addr(2, 6000), UInt64(2000))
    assert_true(conn.path.peer_addr == _addr(2, 6000), "peer address follows the validated path")
    assert_true(conn.can_send_to(_addr(2, 6000), 1_000_000), "the new address is unconstrained")
    assert_true(not conn.can_send_to(_addr(1, 5000), 1), "the old address gets nothing")
    assert_equal_int(Int(conn.cid_mgr.remote_active_cid_seq), 0, "CID kept")
    var cid_after = List[Byte](conn.peer_cid.as_span())
    assert_true(cid_after == cid_before, "same DCID on the new path")
    print("  test_rebind_without_spare_cid_completes: PASS")


struct _Pair(Movable):
    """An established client/server pair sharing one TLS backend."""

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
        self.client = QuicConnection.client(
            self.tls.shared(), ccfg, "localhost", default_transport_params(), self.now
        )
        var odcid = List[Byte](self.client.initial_dcid.as_span())
        var odcid2 = odcid.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, default_transport_params(), Span(odcid), Span(odcid2), self.now
        )
        var buf = List[List[Byte]](capacity=1)
        for _ in range(60):
            self.now += UInt64(10_000)
            for _ in range(32):
                if self.client.send(self.now, buf) == 0:
                    break
                self.server.recv(Span(buf[0]), self.now)
            for _ in range(32):
                if self.server.send(self.now, buf) == 0:
                    break
                self.client.recv(Span(buf[0]), self.now)
            if self.client.handshake_confirmed and self.server.is_established():
                break
        assert_true(self.client.handshake_confirmed, "handshake confirmed")
        # Settle: let every ACK land so the server owes nothing.
        for _ in range(8):
            self.now += UInt64(30_000)
            for _ in range(32):
                if self.client.send(self.now, buf) == 0:
                    break
                self.server.recv(Span(buf[0]), self.now)
            for _ in range(32):
                if self.server.send(self.now, buf) == 0:
                    break
                self.client.recv(Span(buf[0]), self.now)


def _new_address_seen(mut p: _Pair, migrate: Bool) raises -> PathKey:
    """Book an authenticated datagram from a new address on the server,
    crediting it enough bytes that the 3x budget is not what limits egress."""
    var b = _addr(2, 6000)
    p.server.last_datagram_may_migrate = migrate
    p.server.note_authenticated_ingress(PathKey(copy=b), 1_000_000, p.now)
    assert_equal_int(len(p.server.path.validator.pending), 1, "challenge started")
    return b^


def test_silent_peer_gets_bounded_challenges() raises:
    """A new address that never answers is probed on a backoff schedule,
    not with a challenge in every packet: over 3 s the server sends a
    handful of datagrams (RFC 9000 Section 8.2.1)."""
    var p = _Pair()
    _ = _new_address_seen(p, True)
    var sent = 0
    var buf = List[List[Byte]](capacity=1)
    for _ in range(3000):
        p.now += UInt64(1_000)
        sent += p.server.send(p.now, buf)
    assert_true(sent <= 16, "datagrams in 3 s to a silent new address: " + String(sent))
    print("  test_silent_peer_gets_bounded_challenges: PASS")


def test_challenge_resent_from_timeout() raises:
    """Driven only by `timeout()`, an unanswered challenge is re-sent until
    its attempts are used up, then expires."""
    var p = _Pair()
    _ = _new_address_seen(p, True)
    var buf = List[List[Byte]](capacity=1)
    var most = 0
    for _ in range(200):
        _ = p.server.send(p.now, buf)
        if len(p.server.path.validator.pending) == 0:
            break
        most = max(most, Int(p.server.path.validator.pending[0].attempts))
        var t = p.server.timeout(p.now)
        assert_true(Bool(t), "a deadline is armed")
        assert_true(t.value() > p.now, "the deadline is in the future after send")
        p.now = t.value()
    assert_equal_int(most, Int(MAX_CHALLENGE_ATTEMPTS), "every attempt was sent")
    assert_equal_int(len(p.server.path.validator.pending), 0, "the challenge expired")
    print("  test_challenge_resent_from_timeout: PASS")


def test_probing_address_not_challenged_via_old_path() raises:
    """A challenge for an address we are not sending to is not piggybacked
    on packets to the peer address, where it cannot validate anything."""
    var p = _Pair()
    _ = _new_address_seen(p, False)
    var buf = List[List[Byte]](capacity=1)
    p.now += UInt64(1_000)
    assert_equal_int(p.server.send(p.now, buf), 0, "nothing to send to the peer address")
    print("  test_probing_address_not_challenged_via_old_path: PASS")


def main() raises:
    print("test_quic_path_migration:")
    test_rebind_without_spare_cid_completes()
    test_silent_peer_gets_bounded_challenges()
    test_challenge_resent_from_timeout()
    test_probing_address_not_challenged_via_old_path()
    print("PASS: test_quic_path_migration")
