"""A server whose check of the client's transport parameters closes the connection never promotes it to established."""

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from navette.quic.guard_tags import GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN
from navette.util.byte_vec import ByteVec
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


def test_forbidden_client_param_closes_without_promotion() raises:
    """A client sending stateless_reset_token (server-only, RFC 9000 Section 18.2) gets TRANSPORT_PARAMETER_ERROR, and the server stays unestablished."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert = ck[0].copy()
    var key = ck[1].copy()
    var ca = load_test_ca()
    var scfg = QuicServerConfig(tls.shared(), Span(cert), Span(key))
    var ccfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var now = UInt64(1_000_000)
    var cparams = default_transport_params()
    var srt = ByteVec[16]()
    srt.extend(Span(List[Byte](length=16, fill=0x42)))
    cparams.stateless_reset_token = srt^
    var client = QuicConnection.client(tls.shared(), ccfg, "localhost", cparams^, now)
    var first = _send_all(client, now)
    var orig = List[Byte](client.initial_dcid.as_span())
    var orig2 = orig.copy()
    var server = QuicConnection.server(
        tls.shared(), scfg, default_transport_params(), Span(orig), Span(orig2), now
    )
    for ref d in first:
        server.recv(Span(d), now)
    for _ in range(10):
        now += UInt64(10_000)
        for ref d in _send_all(server, now):
            client.recv(Span(d), now)
        for ref d in _send_all(client, now):
            server.recv(Span(d), now)
    assert_true(Bool(server.close.pending), "server closes")
    assert_equal_int(Int(server.close.pending.value().error_code), 0x08, "TRANSPORT_PARAMETER_ERROR")
    assert_true(not server.is_established(), "a closing server is never promoted to established")
    var tag = String(GUARD_TAG_TP_STATELESS_RESET_FORBIDDEN)
    assert_true(
        String(unsafe_from_utf8=server.close.pending.value().reason.as_span()).startswith(tag),
        "the guard tag reaches the close reason whole, closing bracket included",
    )
    _ = tls^
    print("  test_forbidden_client_param_closes_without_promotion: PASS")


def main() raises:
    print("test_quic_tp_close_not_established:")
    test_forbidden_client_param_closes_without_promotion()
    print("PASS: test_quic_tp_close_not_established")
