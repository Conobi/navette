"""A QUIC client follows one Retry and checks the server's CID transport parameters (RFC 9000 Sections 7.3, 17.2.5.2)."""

from std.collections import Span

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.packet import PacketType, parse_packet_header
from navette.quic.stateless import build_retry
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _bytes(v: UInt8, n: Int) -> List[Byte]:
    return List[Byte](length=n, fill=v)


def _eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


struct Fixture(Movable):
    """TLS configs plus a client that has sent its first Initial (`first`)."""

    var tls: TlsBackend
    var scfg: QuicServerConfig
    var client: QuicConnection
    var first: List[List[Byte]]
    var now: UInt64

    def __init__(out self) raises:
        self.tls = TlsBackend("lib/librustls_mojo.so")
        var ck = load_test_cert()
        var cert = ck[0].copy()
        var key = ck[1].copy()
        var ca = load_test_ca()
        self.scfg = QuicServerConfig(self.tls.shared(), Span(cert), Span(key))
        var ccfg = QuicClientConfig.with_ca(self.tls.shared(), Span(ca))
        self.now = UInt64(1_000_000)
        self.client = QuicConnection.client(self.tls.shared(), ccfg, "localhost", default_transport_params(), self.now)
        self.first = _send_all(self.client, self.now)
        assert_true(len(self.first) > 0, "client sends its first Initial")

    def lib(self) -> SharedLibrary:
        return self.tls.shared()

    def orig(self) -> List[Byte]:
        return List[Byte](self.client.initial_dcid.as_span())

    def retry(self, rscid: List[Byte], token: List[Byte]) raises -> List[Byte]:
        """A Retry answering the client's first Initial, keyed by its original DCID."""
        var out = List[Byte](capacity=1252)
        build_retry(out, self.lib(), Span(self.orig()), self.client.local_cid.as_span(), Span(rscid), Span(token))
        return out^

    def server(self, orig: List[Byte], client_dcid: List[Byte], retry_scid: List[Byte]) raises -> QuicConnection:
        return QuicConnection.server(
            self.lib(), self.scfg, default_transport_params(), Span(orig), Span(client_dcid), self.now,
            retry_scid=retry_scid,
        )


def _send_all(mut conn: QuicConnection, now: UInt64) raises -> List[List[Byte]]:
    var out = List[List[Byte]]()
    for _ in range(16):
        var batch = List[List[Byte]]()
        if conn.send(now, batch) == 0:
            break
        for ref d in batch:
            out.append(d.copy())
    return out^


def _pump(mut client: QuicConnection, mut server: QuicConnection, mut now: UInt64, dgs: List[List[Byte]]) raises:
    """Deliver `dgs` to the server, then exchange until quiet or 20 rounds."""
    for ref d in dgs:
        server.recv(Span(d), now)
    for _ in range(20):
        now += UInt64(10_000)
        var s = _send_all(server, now)
        for ref d in s:
            client.recv(Span(d), now)
        var c = _send_all(client, now)
        for ref d in c:
            server.recv(Span(d), now)
        if len(s) == 0 and len(c) == 0:
            break


def _first_header_of(dgs: List[List[Byte]]) raises -> Tuple[List[Byte], List[Byte]]:
    """(DCID, token) of the first packet the client sent."""
    var h = parse_packet_header(Span(dgs[0]), 8)[0].copy()
    assert_true(h.packet_type == PacketType.initial(), "an Initial")
    return (List[Byte](h.dcid.as_span()), List[Byte](h.token_span()))


def _client_close_code(ref client: QuicConnection) -> Int:
    if not client.close.pending:
        return -1
    return Int(client.close.pending.value().error_code)


def test_client_follows_retry_to_handshake() raises:
    var f = Fixture()
    var orig = f.orig()
    var rscid = _bytes(0x5A, 8)
    var token = _bytes(0x01, 90)
    f.client.recv(Span(f.retry(rscid, token)), f.now)
    var second = _send_all(f.client, f.now)
    assert_true(len(second) > 0, "client re-sends its Initial")
    var h = _first_header_of(second)
    assert_true(_eq(Span(h[0]), Span(rscid)), "DCID switched to the Retry SCID")
    assert_true(_eq(Span(h[1]), Span(token)), "Initial carries the token")
    assert_true(len(second[0]) >= 1200, "still padded to 1,200 B")
    var server = f.server(orig, rscid, rscid)
    _pump(f.client, server, f.now, second)
    assert_true(f.client.is_established() and server.is_established(), "handshake after Retry")
    assert_equal_int(_client_close_code(f.client), -1, "client accepted the server's CID parameters")
    print("  test_client_follows_retry_to_handshake: PASS")


def test_retry_that_cannot_rewind_changes_nothing() raises:
    """A Retry whose CRYPTO rewind fails is ignored whole: no token, SCID, keys or sent-packet state applied."""
    var f = Fixture()
    var sent_before = len(f.client.spaces[0].sent_packets)
    var peer_before = List[Byte](f.client.peer_cid.as_span())
    # Force a gap between the sent CRYPTO data and the unsent tail.
    f.client.crypto_streams[0].send_offset = UInt64(100_000)
    f.client.crypto_streams[0].send_buf = List[Byte](length=1, fill=Byte(0x16))
    f.client.crypto_streams[0].sent_cursor = 0
    var raised = False
    try:
        f.client.recv(Span(f.retry(_bytes(0x5C, 8), _bytes(0x03, 40))), f.now)
    except:
        raised = True
    assert_true(not raised, "an unusable Retry is ignored, not raised")
    assert_true(not f.client._retry_scid, "Retry SCID not recorded")
    assert_equal_int(len(f.client._retry_token), 0, "token not recorded")
    assert_true(_eq(f.client.peer_cid.as_span(), Span(peer_before)), "DCID unchanged")
    assert_equal_int(len(f.client.spaces[0].sent_packets), sent_before, "sent packets kept")
    assert_equal_int(Int(f.client.crypto_streams[0].send_offset), 100_000, "CRYPTO send state untouched")
    print("  test_retry_that_cannot_rewind_changes_nothing: PASS")


def test_handshake_without_retry_checks_original_dcid() raises:
    var f = Fixture()
    var orig = f.orig()
    var server = f.server(orig, orig, List[Byte]())
    _pump(f.client, server, f.now, f.first)
    assert_true(f.client.is_established(), "matching original_destination_connection_id")
    var g = Fixture()
    var bad = g.server(_bytes(0x77, 8), g.orig(), List[Byte]())
    _pump(g.client, bad, g.now, g.first)
    assert_equal_int(_client_close_code(g.client), 0x08, "wrong original_destination_connection_id")
    assert_true(not g.client.is_established(), "a client closing on its peer's parameters is never established")
    print("  test_handshake_without_retry_checks_original_dcid: PASS")


def test_retry_with_bad_tag_is_ignored() raises:
    var f = Fixture()
    var r = f.retry(_bytes(0x5A, 8), _bytes(0x01, 90))
    r[len(r) - 1] ^= 0x01
    f.client.recv(Span(r), f.now)
    f.now += UInt64(2_000_000)  # past the PTO, so the client re-sends
    var again = _send_all(f.client, f.now)
    assert_true(len(again) > 0, "PTO probe")
    var h = _first_header_of(again)
    assert_true(_eq(Span(h[0]), Span(f.orig())), "DCID unchanged")
    assert_equal_int(len(h[1]), 0, "no token")
    print("  test_retry_with_bad_tag_is_ignored: PASS")


def test_second_retry_is_ignored() raises:
    var f = Fixture()
    var first_scid = _bytes(0x5A, 8)
    f.client.recv(Span(f.retry(first_scid, _bytes(0x01, 90))), f.now)
    f.client.recv(Span(f.retry(_bytes(0x6B, 8), _bytes(0x02, 90))), f.now)
    var h = _first_header_of(_send_all(f.client, f.now))
    assert_true(_eq(Span(h[0]), Span(first_scid)), "DCID stays the first Retry SCID")
    assert_true(_eq(Span(h[1]), Span(_bytes(0x01, 90))), "first token kept")
    print("  test_second_retry_is_ignored: PASS")


def test_retry_after_server_initial_is_ignored() raises:
    var f = Fixture()
    var orig = f.orig()
    var server = f.server(orig, orig, List[Byte]())
    for ref d in f.first:
        server.recv(Span(d), f.now)
    for ref d in _send_all(server, f.now):
        f.client.recv(Span(d), f.now)
    var peer = List[Byte](f.client.peer_cid.as_span())
    f.client.recv(Span(f.retry(_bytes(0x5A, 8), _bytes(0x01, 90))), f.now)
    assert_true(_eq(f.client.peer_cid.as_span(), Span(peer)), "a late Retry changes nothing")
    print("  test_retry_after_server_initial_is_ignored: PASS")


def test_retry_scid_mismatch_closes_client() raises:
    var f = Fixture()
    var orig = f.orig()
    var rscid = _bytes(0x5A, 8)
    f.client.recv(Span(f.retry(rscid, _bytes(0x01, 90))), f.now)
    var server = f.server(orig, rscid, _bytes(0x5B, 8))
    _pump(f.client, server, f.now, _send_all(f.client, f.now))
    assert_equal_int(_client_close_code(f.client), 0x08, "retry_source_connection_id mismatch")
    assert_true(not f.client.is_established(), "not established after a failed parameter check")
    print("  test_retry_scid_mismatch_closes_client: PASS")


def test_missing_retry_scid_after_retry_closes_client() raises:
    var f = Fixture()
    var orig = f.orig()
    var rscid = _bytes(0x5A, 8)
    f.client.recv(Span(f.retry(rscid, _bytes(0x01, 90))), f.now)
    var server = f.server(orig, rscid, List[Byte]())
    _pump(f.client, server, f.now, _send_all(f.client, f.now))
    assert_equal_int(_client_close_code(f.client), 0x08, "retry_source_connection_id absent after a Retry")
    print("  test_missing_retry_scid_after_retry_closes_client: PASS")


def test_retry_scid_equal_to_orig_dcid_ignored() raises:
    var f = Fixture()
    var orig = f.orig()
    f.client.recv(Span(f.retry(orig, _bytes(0x01, 90))), f.now)
    f.now += UInt64(2_000_000)
    var h = _first_header_of(_send_all(f.client, f.now))
    assert_equal_int(len(h[1]), 0, "Retry ignored: no token")
    print("  test_retry_scid_equal_to_orig_dcid_ignored: PASS")


def main() raises:
    print("test_quic_retry_handshake:")
    test_client_follows_retry_to_handshake()
    test_retry_that_cannot_rewind_changes_nothing()
    test_handshake_without_retry_checks_original_dcid()
    test_retry_with_bad_tag_is_ignored()
    test_second_retry_is_ignored()
    test_retry_after_server_initial_is_ignored()
    test_retry_scid_mismatch_closes_client()
    test_missing_retry_scid_after_retry_closes_client()
    test_retry_scid_equal_to_orig_dcid_ignored()
    print("PASS: test_quic_retry_handshake")
