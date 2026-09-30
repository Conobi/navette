"""Server-side path validation of a peer's new address (RFC 9000 Sections 8.2, 9)."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.path import PathKey
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


def main() raises:
    print("test_quic_path_migration:")
    test_rebind_without_spare_cid_completes()
    print("PASS: test_quic_path_migration")
