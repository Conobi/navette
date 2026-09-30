"""Control frames that must survive loss are re-sent (RFC 9000 Section 13.3)."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
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


comptime _DATA = 0
comptime _STREAM_DATA = 1
comptime _STREAMS = 2


def _blocked_at(ref conn: QuicConnection, kind: Int, sid: UInt64) raises -> UInt64:
    """The limit the connection last announced itself blocked at for `kind`."""
    if kind == _DATA:
        return conn.stream_map.conn_fc_send.blocked_at
    if kind == _STREAM_DATA:
        return conn.stream_map.stream_ptr(Int(sid))[].fc_send.value().blocked_at
    return conn.stream_map.streams_blocked_at_bidi


def _blocked_frame_resent_after_loss(kind: Int, var sparams: TransportParams) raises -> Int:
    """Establish, get the client blocked on `kind`, drop the datagram that
    carries the first blocked frame, and count how many sends announce the
    block (a send that moves the blocked marker onto the current limit)."""
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
    var server = QuicConnection.server(tls.shared(), scfg, sparams^, Span(odcid), Span(odcid2), now)
    for _ in range(40):
        now += UInt64(10_000)
        _deliver(server, _send_all(client, now), now)
        _deliver(client, _send_all(server, now), now)
        if client.handshake_confirmed:
            break
    assert_true(client.handshake_confirmed, "handshake confirmed")
    var sid = client.open_stream(True)
    var body = List[Byte](length=6000, fill=0x61)
    client.send_stream_data(sid, Span(body), False)
    if kind == _STREAMS:
        try:
            _ = client.open_stream(True)
        except:
            pass
    var announces = 0
    var dropped = False
    for _ in range(300):
        now += UInt64(20_000)
        var before = _blocked_at(client, kind, sid)
        var from_client = _send_all(client, now)
        var after = _blocked_at(client, kind, sid)
        if after != before and after != UInt64(0):
            announces += 1
            if not dropped:
                dropped = True
                continue
        _deliver(server, from_client, now)
        _deliver(client, _send_all(server, now), now)
        if announces >= 2:
            break
    assert_true(dropped, "the first blocked frame was sent and dropped")
    _ = tls^
    return announces


def _params(max_data: UInt64, stream_data: UInt64, bidi: UInt64) -> TransportParams:
    var p = default_transport_params()
    p.initial_max_data = max_data
    p.initial_max_stream_data_bidi_remote = stream_data
    p.initial_max_streams_bidi = bidi
    return p^


def test_lost_data_blocked_is_resent() raises:
    """DATA_BLOCKED lost while still blocked on the same limit is re-sent."""
    var n = _blocked_frame_resent_after_loss(_DATA, _params(2000, 1_000_000, 10))
    assert_true(n >= 2, "a lost DATA_BLOCKED is announced again")
    print("  test_lost_data_blocked_is_resent: PASS")


def test_lost_stream_data_blocked_is_resent() raises:
    """STREAM_DATA_BLOCKED lost while the stream is still blocked is re-sent."""
    var n = _blocked_frame_resent_after_loss(_STREAM_DATA, _params(1_000_000, 2000, 10))
    assert_true(n >= 2, "a lost STREAM_DATA_BLOCKED is announced again")
    print("  test_lost_stream_data_blocked_is_resent: PASS")


def test_lost_streams_blocked_is_resent() raises:
    """STREAMS_BLOCKED lost while still at the stream limit is re-sent."""
    var n = _blocked_frame_resent_after_loss(_STREAMS, _params(1_000_000, 1_000_000, 1))
    assert_true(n >= 2, "a lost STREAMS_BLOCKED is announced again")
    print("  test_lost_streams_blocked_is_resent: PASS")


def main() raises:
    print("test_quic_control_frame_retransmit:")
    test_lost_handshake_done_is_resent()
    test_lost_data_blocked_is_resent()
    test_lost_stream_data_blocked_is_resent()
    test_lost_streams_blocked_is_resent()
    print("PASS: test_quic_control_frame_retransmit")
