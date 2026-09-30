"""Control frames that must survive loss are re-sent (RFC 9000 Section 13.3)."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, load_test_cert, load_test_ca


def _send_all(mut conn: QuicConnection, now: UInt64) raises -> List[List[Byte]]:
    var out = List[List[Byte]]()
    for _ in range(16):
        var batch = List[List[Byte]]()
        if conn.send(now, batch) == 0:
            break
        for ref d in batch:
            out.append(d.copy())
    return out^


def _deliver(mut to: QuicConnection, dgs: List[List[Byte]], now: UInt64):
    for ref d in dgs:
        try:
            to.recv(Span(d), now)
        except:
            pass


def test_lost_handshake_done_is_resent() raises:
    """Dropping the server's first flight after it completes the handshake
    (the one carrying HANDSHAKE_DONE) still lets the client confirm."""
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
    var dropped = False
    for _ in range(200):
        now += UInt64(50_000)
        _deliver(server, _send_all(client, now), now)
        var from_server = _send_all(server, now)
        if server.is_established() and not dropped and len(from_server) > 0:
            dropped = True
            continue
        _deliver(client, from_server, now)
        if client.handshake_confirmed:
            break
    assert_true(dropped, "the HANDSHAKE_DONE flight was dropped")
    assert_true(client.handshake_confirmed, "a lost HANDSHAKE_DONE is re-sent and the client confirms")
    assert_true(client.is_established(), "client established")
    _ = tls^
    print("  test_lost_handshake_done_is_resent: PASS")


def main() raises:
    print("test_quic_control_frame_retransmit:")
    test_lost_handshake_done_is_resent()
    print("PASS: test_quic_control_frame_retransmit")
