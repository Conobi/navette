"""A server holds 1-RTT packets that arrive before its TLS handshake completes and processes them once it does (RFC 9001 Section 5.7).

Processing them early would ACK them, and a client may take an ACK of a
1-RTT packet as handshake confirmation, drop its Handshake keys and never
resend a lost Finished: both sides then stall until the idle timeout.
Holding them instead of dropping them spares the client a retransmit.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
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


def _deliver(mut to: QuicConnection, dgs: List[List[Byte]], now: UInt64) raises:
    for ref d in dgs:
        to.recv(Span(d), now)


def _server_has_stream(mut server: QuicConnection, sid: UInt64) -> Bool:
    return Bool(server.stream_map.try_stream_ptr(Int(sid)))


struct Pair(Movable):
    """A client that has the server's whole flight, so it holds 1-RTT keys, and a server still waiting for its Finished."""

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
        var first = _send_all(self.client, self.now)
        var orig = List[Byte](self.client.initial_dcid.as_span())
        var orig2 = orig.copy()
        self.server = QuicConnection.server(
            self.tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), self.now
        )
        _deliver(self.server, first, self.now)
        _deliver(self.client, _send_all(self.server, self.now), self.now)
        assert_true(self.client.protect.has_keys(2), "the client holds 1-RTT keys")
        assert_true(not self.server.is_established(), "the server still waits for Finished")

    def request(mut self) raises -> UInt64:
        var sid = self.client.open_stream(True)
        var body = List[Byte](String("GET /").as_bytes())
        self.client.send_stream_data(sid, Span(body), True)
        return sid


def _withheld_finished_then_requests(mut p: Pair, n: Int) raises -> Tuple[List[List[Byte]], List[UInt64]]:
    """Hold back the client's Finished, deliver `n` requests, one 1-RTT datagram each, then return Finished and the stream ids."""
    var hs = _send_all(p.client, p.now)
    var sids = List[UInt64]()
    for _ in range(n):
        sids.append(p.request())
        var dgs = _send_all(p.client, p.now)
        assert_equal_int(len(dgs), 1, "one 1-RTT datagram per request")
        _deliver(p.server, dgs, p.now)
    return (hs^, sids^)


def test_1rtt_before_finished_buffered_then_processed() raises:
    """1-RTT packets that overtake Finished are held unprocessed and unACKed, then processed as soon as Finished lands."""
    var p = Pair()
    var r = _withheld_finished_then_requests(p, 1)
    var sid = r[1][0]
    assert_equal_int(p.server.spaces[2].largest_recv_pn, -1, "no 1-RTT packet processed, so none owed an ACK")
    assert_true(not p.server.spaces[2].ack_needed, "no 1-RTT ACK pending")
    assert_true(not _server_has_stream(p.server, sid), "no stream opened")

    _deliver(p.server, r[0], p.now)
    assert_true(p.server.is_established(), "Finished completes the handshake")
    assert_true(_server_has_stream(p.server, sid), "the held request opened its stream with no client retransmit")
    assert_true(p.server.spaces[2].largest_recv_pn >= 0, "1-RTT now processed")
    assert_true(p.server.spaces[2].ack_needed, "the 1-RTT ACK is now owed")
    assert_equal_int(p.server._early_1rtt.capacity(), 0, "the buffer is freed after replay")
    _ = p.tls.shared()
    print("  test_1rtt_before_finished_buffered_then_processed: PASS")


def test_early_1rtt_buffer_capped_at_ten() raises:
    """Only the first ten early 1-RTT packets are kept; later ones are dropped and wait for the client to resend."""
    var p = Pair()
    var r = _withheld_finished_then_requests(p, 12)
    _deliver(p.server, r[0], p.now)
    assert_true(p.server.is_established(), "Finished completes the handshake")
    assert_true(_server_has_stream(p.server, r[1][9]), "the tenth request was replayed")
    assert_true(not _server_has_stream(p.server, r[1][10]), "the eleventh was dropped")
    assert_true(not _server_has_stream(p.server, r[1][11]), "the twelfth was dropped")
    _ = p.tls.shared()
    print("  test_early_1rtt_buffer_capped_at_ten: PASS")


def test_close_frees_early_1rtt() raises:
    """Closing a handshaking server frees its held 1-RTT packets; a late Finished then opens nothing."""
    var p = Pair()
    var r = _withheld_finished_then_requests(p, 2)
    assert_equal_int(len(p.server._early_1rtt), 2, "both requests are held")
    p.server.close_transport(UInt64(0), String("bye"), p.now)
    assert_equal_int(p.server._early_1rtt.capacity(), 0, "close frees the held packets")
    _deliver(p.server, r[0], p.now)
    assert_true(not _server_has_stream(p.server, r[1][0]), "nothing replayed after close")
    _ = p.tls.shared()
    print("  test_close_frees_early_1rtt: PASS")


def test_coalesced_finished_and_1rtt_processed() raises:
    """A datagram carrying Handshake(Finished) then 1-RTT completes the handshake on the first and processes the second."""
    var p = Pair()
    var sid = p.request()
    var dgs = _send_all(p.client, p.now)
    var opened_with_finished = False
    for ref d in dgs:
        var was_established = p.server.is_established()
        p.server.recv(Span(d), p.now)
        if not was_established and p.server.is_established():
            opened_with_finished = _server_has_stream(p.server, sid)
    assert_true(opened_with_finished, "the datagram that completed the handshake also delivered the request")
    assert_true(p.server.is_established(), "handshake complete")
    assert_true(p.server.spaces[2].largest_recv_pn >= 0, "the coalesced 1-RTT packet was processed")
    assert_true(_server_has_stream(p.server, sid), "the request opened its stream")
    assert_equal_int(p.server._early_1rtt.capacity(), 0, "nothing held, nothing allocated")
    _ = p.tls.shared()
    print("  test_coalesced_finished_and_1rtt_processed: PASS")


def main() raises:
    print("test_quic_early_1rtt:")
    test_1rtt_before_finished_buffered_then_processed()
    test_early_1rtt_buffer_capped_at_ten()
    test_close_frees_early_1rtt()
    test_coalesced_finished_and_1rtt_processed()
    print("PASS: test_quic_early_1rtt")
