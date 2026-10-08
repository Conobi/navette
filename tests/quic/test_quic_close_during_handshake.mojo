"""A server that closes mid-handshake stops sending Initial packets once the client's Handshake packet arrives (RFC 9001 Section 4.9.1).

The client discards its Initial keys as soon as it sends a Handshake packet.
A server close datagram that still leads with an Initial packet is then
undecryptable at its first packet, and quiche drops the whole datagram, so
the Handshake and 1-RTT copies of the close behind it were never read and
the client timed out instead of seeing the error.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, load_test_cert, load_test_ca


def _is_initial(first_byte: UInt8) -> Bool:
    """Long header with packet type 0 (RFC 9000 Section 17.2.2)."""
    return (first_byte & 0x80) != 0 and ((first_byte >> 4) & 0x03) == 0


def test_close_after_client_handshake_skips_initial() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
    var dcid_a = List[Byte](client.initial_dcid.as_span())
    var dcid_b = List[Byte](client.initial_dcid.as_span())
    var server = QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(dcid_a), Span(dcid_b), now
    )
    var dg = List[List[Byte]]()
    # Exchange until the client holds Handshake keys, keeping its first
    # Handshake packet away from the server.
    for _ in range(10):
        if client.protect.has_keys(1):
            break
        dg.clear()
        while client.send(now, dg) > 0:
            pass
        for ref d in dg:
            server.recv(Span(d), now)
        now += 10_000
        dg.clear()
        while server.send(now, dg) > 0:
            pass
        for ref d in dg:
            client.recv(Span(d), now)
    assert_true(client.protect.has_keys(1), "the client holds Handshake keys")
    # The server closes before the client's Handshake packet reaches it; that
    # first close still carries an Initial packet, and is lost.
    server.close_transport(UInt64(0x0A), String("test close"), now)
    dg.clear()
    _ = server.send(now, dg)
    assert_true(len(dg) == 1 and _is_initial(dg[0][0]), "the first close leads with Initial")
    # The client's Handshake packet arrives a PTO later, re-arming the close.
    now += 1_000_000
    dg.clear()
    while client.send(now, dg) > 0:
        pass
    for ref d in dg:
        server.recv(Span(d), now)
    dg.clear()
    _ = server.send(now, dg)
    assert_true(len(dg) == 1, "the close is sent again")
    assert_true(not _is_initial(dg[0][0]), "no Initial packet once the client sent Handshake")
    client.recv(Span(dg[0]), now)
    assert_true(client.is_draining() or client.is_closed(), "the client reads the close")
    _ = tls^
    print("  test_close_after_client_handshake_skips_initial: PASS")


def main() raises:
    print("test_quic_close_during_handshake:")
    test_close_after_client_handshake_skips_initial()
    print("All test_quic_close_during_handshake tests passed.")
