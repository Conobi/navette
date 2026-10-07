"""A server handshake not done HANDSHAKE_TIMEOUT_US after the connection was created closes silently."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection, HANDSHAKE_TIMEOUT_US
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def test_abandoned_handshake_closes_silently() raises:
    """One client Initial, then silence: `timeout()` names the deadline, and `send()` at it closes with nothing on the wire."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(load_test_ca()))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
    var first = List[List[Byte]]()
    _ = client.send(now, first)
    var orig = List[Byte](client.initial_dcid.as_span())
    var orig2 = orig.copy()
    var server = QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), now
    )
    for ref d in first:
        server.recv(Span(d), now)
    var deadline = now + HANDSHAKE_TIMEOUT_US
    var batch = List[List[Byte]]()
    _ = server.send(now, batch)
    var t = server.timeout(now)
    assert_true(Bool(t) and t.value() <= deadline, "the handshake deadline bounds timeout()")

    batch.clear()
    batch.clear()
    _ = server.send(deadline - 1, batch)
    assert_true(not server.is_closed(), "alive just before the deadline")
    batch.clear()
    batch.clear()
    assert_equal_int(server.send(deadline, batch), 0, "nothing sent at the deadline")
    assert_true(server.is_closed(), "closed at the deadline")
    assert_true(not server.close.pending, "no CONNECTION_CLOSE queued")
    _ = tls^
    print("  test_abandoned_handshake_closes_silently: PASS")


def main() raises:
    print("test_quic_handshake_timeout:")
    test_abandoned_handshake_closes_silently()
    print("PASS: test_quic_handshake_timeout")
