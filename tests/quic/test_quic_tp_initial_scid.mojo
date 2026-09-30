"""initial_source_connection_id must be present and match the peer's first Initial SCID, both ways (RFC 9000 Section 7.3).

A mismatch, or a missing value, means the Initial SCID was tampered
with on the path: the endpoint closes with TRANSPORT_PARAMETER_ERROR.
Zero-length CIDs are compared like any other.
"""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.cid_buf import CidBuf
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from tests._test_util import assert_true, load_test_cert, load_test_ca


def _cid(v: UInt8, n: Int) -> CidBuf:
    return CidBuf.from_span(Span(List[Byte](length=n, fill=v)))


def _tp_with_scid(scid: Optional[List[Byte]]) -> TransportParams:
    var tp = default_transport_params()
    tp.initial_scid = scid.copy()
    return tp^


def _client(tls: TlsBackend) raises -> QuicConnection:
    var ca = load_test_ca()
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    return QuicConnection.client(tls.shared(), ccfg, "localhost", default_transport_params(), UInt64(1_000_000))


def _server(tls: TlsBackend) raises -> QuicConnection:
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var orig = List[Byte](length=8, fill=Byte(0x11))
    var orig2 = orig.copy()
    return QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), UInt64(1_000_000)
    )


def _check(mut conn: QuicConnection, scid: Optional[List[Byte]]) -> Bool:
    """True when `conn` accepts the peer's initial_source_connection_id `scid`."""
    var tp = _tp_with_scid(scid)
    return not conn._initial_scid_error(tp)


def _run(mut conn: QuicConnection, side: String) raises:
    conn._initial_peer_scid = Optional[CidBuf](_cid(0xAB, 8))
    var same = List[Byte](length=8, fill=Byte(0xAB))
    var other = List[Byte](length=8, fill=Byte(0xCD))
    assert_true(_check(conn, Optional[List[Byte]](same^)), side + ": matching SCID accepted")
    assert_true(not _check(conn, Optional[List[Byte]](other^)), side + ": different SCID refused")
    assert_true(not _check(conn, Optional[List[Byte]](None)), side + ": missing SCID refused")
    assert_true(not _check(conn, Optional[List[Byte]](List[Byte]())), side + ": zero-length vs 8 bytes refused")
    conn._initial_peer_scid = Optional[CidBuf](CidBuf.empty())
    assert_true(_check(conn, Optional[List[Byte]](List[Byte]())), side + ": zero-length matches zero-length")
    assert_true(
        not _check(conn, Optional[List[Byte]](List[Byte](length=8, fill=Byte(0xAB)))),
        side + ": 8 bytes vs zero-length refused",
    )


def test_client_checks_server_initial_scid() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var c = _client(tls)
    _run(c, "client")
    print("  test_client_checks_server_initial_scid: PASS")


def test_server_checks_client_initial_scid() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var s = _server(tls)
    _run(s, "server")
    print("  test_server_checks_client_initial_scid: PASS")


def main() raises:
    print("test_quic_tp_initial_scid:")
    test_client_checks_server_initial_scid()
    test_server_checks_client_initial_scid()
