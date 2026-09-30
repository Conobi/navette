# tests/quic/test_quic_cid_frame_close.mojo
#
# CID frame violations reach the wire as a transport CONNECTION_CLOSE,
# not a silently dropped packet: the connection-level handlers turn the
# CidManager verdicts into close_transport calls.

from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.error import CONNECTION_ID_LIMIT_ERROR, PROTOCOL_VIOLATION
from tests._test_util import assert_true, assert_equal_int, load_test_cert, load_test_ca


def _server() raises -> QuicConnection:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var server_config = QuicServerConfig(
        tls.shared(), Span(cert_bytes), Span(key_bytes)
    )
    var params = default_transport_params()
    var now = UInt64(1_000_000)
    var ca_bytes = load_test_ca()
    var client_config = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var client = QuicConnection.client(
        tls.shared(), client_config, "localhost", params, now,
    )
    var orig_dcid = List[Byte](client.initial_dcid.as_span())
    var client_dcid = List[Byte](client.initial_dcid.as_span())
    var server = QuicConnection.server(
        tls.shared(), server_config, params,
        Span(orig_dcid), Span(client_dcid), now,
    )
    _ = tls^
    return server^


def _cid_and_token(seq: Int) -> List[Byte]:
    """[8-byte CID unique per seq | 16-byte reset token]."""
    var d = List[Byte](capacity=24)
    for i in range(8):
        d.append(UInt8((seq >> (8 * i)) & 0xFF) ^ 0x5A)
    for _ in range(16):
        d.append(0x77)
    return d^


def _close_code(ref conn: QuicConnection) -> Int:
    if not conn.close.pending:
        return -1
    return Int(conn.close.pending.value().error_code)


def test_new_cid_flood_closes_with_limit_error() raises:
    var conn = _server()
    var now = UInt64(2_000_000)
    for i in range(1, 10_001):
        var d = _cid_and_token(i)
        conn._on_new_cid_from_cursor(UInt64(i), UInt64(0), Span(d), 8, now)
    assert_equal_int(
        _close_code(conn), Int(CONNECTION_ID_LIMIT_ERROR), "closed with 0x09"
    )
    assert_true(
        len(conn.cid_mgr.remote_cids) <= 2, "remote CIDs bounded by our limit"
    )
    print("  test_new_cid_flood_closes_with_limit_error: PASS")


def test_conflicting_new_cid_closes_with_protocol_violation() raises:
    var conn = _server()
    var now = UInt64(2_000_000)
    var a = _cid_and_token(1)
    conn._on_new_cid_from_cursor(UInt64(1), UInt64(0), Span(a), 8, now)
    assert_equal_int(_close_code(conn), -1, "first NEW_CONNECTION_ID accepted")
    conn._on_new_cid_from_cursor(UInt64(1), UInt64(0), Span(a), 8, now)
    assert_equal_int(_close_code(conn), -1, "exact repeat ignored")
    var b = _cid_and_token(2)
    conn._on_new_cid_from_cursor(UInt64(1), UInt64(0), Span(b), 8, now)
    assert_equal_int(_close_code(conn), Int(PROTOCOL_VIOLATION), "conflict closes")
    print("  test_conflicting_new_cid_closes_with_protocol_violation: PASS")


def test_retire_unissued_closes_with_protocol_violation() raises:
    var conn = _server()
    var now = UInt64(2_000_000)
    conn._on_retire_cid(UInt64(1) << 40, now)
    assert_equal_int(_close_code(conn), Int(PROTOCOL_VIOLATION), "unissued seq closes")
    print("  test_retire_unissued_closes_with_protocol_violation: PASS")


def main() raises:
    print("test_quic_cid_frame_close:")
    test_new_cid_flood_closes_with_limit_error()
    test_conflicting_new_cid_closes_with_protocol_violation()
    test_retire_unissued_closes_with_protocol_violation()
    print("All test_quic_cid_frame_close tests passed.")
