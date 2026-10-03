"""`QuicConnection.server(stream_window=...)`: a new connection advertises min(CAP, window) bidi streams.

The server keeps CAP (`initial_max_streams_bidi`, 100 by default) as its re-grant ceiling, so the
narrowed connection can be raised back later. Narrowing declines 0-RTT for that connection (RFC 9000
Section 7.4.1: limits below the remembered ones are only allowed when early data is rejected), so it
applies with 0-RTT enabled too; the rejection itself is proven against a 0-RTT client in the shim's tests.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from tests._test_util import assert_true, load_test_cert, load_test_ca


def _handshake(tls: TlsBackend, max_early_data: UInt32, stream_window: UInt64) raises -> Tuple[UInt64, UInt64, Bool]:
    """(client's peer_max_streams_bidi, server's initial_max_streams_bidi, server zrtt enabled) after a handshake."""
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key), max_early_data=max_early_data)
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), now)
    var dcid_a = List[Byte](client.initial_dcid.as_span())
    var dcid_b = List[Byte](client.initial_dcid.as_span())
    var server = QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(dcid_a), Span(dcid_b), now, stream_window=stream_window
    )
    var c_dg = List[List[Byte]]()
    var s_dg = List[List[Byte]]()
    for _ in range(30):
        now += 10_000
        for i in range(client.send(now, c_dg)):
            server.recv(Span(c_dg[i]), now)
        for i in range(server.send(now, s_dg)):
            client.recv(Span(s_dg[i]), now)
        if client.is_established() and server.is_established():
            break
    assert_true(client.is_established() and server.is_established(), "handshake did not complete")
    return (client.stream_map.peer_max_streams_bidi, server.stream_map.initial_max_streams_bidi, server.zrtt.enabled)


def main() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var failed = 0
    try:
        var r = _handshake(tls, 0, 32)
        assert_true(r[0] == 32, "narrowed: client sees 32, got " + String(r[0]))
        assert_true(r[1] == 100, "narrowed: server keeps the ceiling 100, got " + String(r[1]))
    except e:
        print("FAIL narrowed:", e)
        failed += 1
    try:
        var r = _handshake(tls, 0, UInt64.MAX)
        assert_true(r[0] == 100 and r[1] == 100, "default window is the identity: " + String(r[0]))
        r = _handshake(tls, 0, 500)
        assert_true(r[0] == 100, "a window above CAP advertises CAP: " + String(r[0]))
    except e:
        print("FAIL identity:", e)
        failed += 1
    try:
        var r = _handshake(tls, UInt32.MAX, 32)
        assert_true(r[0] == 32, "0-RTT on, narrowed: client sees 32, got " + String(r[0]))
        assert_true(not r[2], "0-RTT on, narrowed: the connection declines early data")
        r = _handshake(tls, UInt32.MAX, UInt64.MAX)
        assert_true(r[0] == 100 and r[2], "0-RTT on, not narrowed: 100 and early data still accepted")
    except e:
        print("FAIL 0-RTT:", e)
        failed += 1
    _ = tls^
    if failed:
        raise Error(String(failed) + " failed")
    print("PASS: test_quic_server_stream_window")
