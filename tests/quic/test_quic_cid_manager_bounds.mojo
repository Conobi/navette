# tests/quic/test_quic_cid_manager_bounds.mojo
#
# CidManager edge rules: our configured active_connection_id_limit is
# held to [2, MAX_RETIRE_QUEUE] (and advertised as such), and a
# NEW_CONNECTION_ID that conflicts with a stored CID is a
# PROTOCOL_VIOLATION even when its sequence is below retire_prior_to.

from std.collections import Span
from tests._test_util import assert_true, assert_equal_int
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import default_transport_params
from navette.quic.cid import CidManager, MAX_RETIRE_QUEUE
from navette.quic.error import PROTOCOL_VIOLATION
from tests._test_util import load_test_ca


def _fill(b: UInt8, n: Int) -> List[Byte]:
    var out = List[Byte](capacity=n)
    for _ in range(n):
        out.append(b)
    return out^


def _mgr(lib: SharedLibrary, local_limit: UInt64) raises -> CidManager:
    return CidManager(lib, _fill(0xAA, 8), _fill(0xBB, 8), local_limit, UInt64(4))


def test_local_limit_clamped() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var low = _mgr(tls.shared(), UInt64(0))
    assert_equal_int(Int(low.local_active_limit), 2, "raised to the RFC minimum")
    var high = _mgr(tls.shared(), UInt64(1) << 62)
    assert_equal_int(Int(high.local_active_limit), MAX_RETIRE_QUEUE, "capped")
    assert_true(high.retire_queue_cap <= MAX_RETIRE_QUEUE, "retire cap bounded")
    print("  test_local_limit_clamped: PASS")


def test_advertised_limit_matches_clamp() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var params = default_transport_params()
    params.active_connection_id_limit = UInt64(1_000_000)
    var ca = load_test_ca()
    var cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca))
    var cli = QuicConnection.client(tls.shared(), cfg, "localhost", params, UInt64(1_000_000))
    assert_equal_int(
        Int(cli.local_params.active_connection_id_limit), MAX_RETIRE_QUEUE,
        "we advertise the limit we enforce",
    )
    assert_equal_int(Int(cli.cid_mgr.local_active_limit), MAX_RETIRE_QUEUE, "enforced")
    print("  test_advertised_limit_matches_clamp: PASS")


def test_conflict_checked_before_retire_prior_to() raises:
    var tls = TlsBackend("lib/librustls_mojo.so")
    var m = _mgr(tls.shared(), UInt64(4))
    assert_true(
        not m.on_new_connection_id(UInt64(5), UInt64(5), _fill(0x05, 8), _fill(0x11, 16)),
        "seq 5 with retire_prior_to 5 accepted",
    )
    # Seq 2 is below retire_prior_to but reuses seq 5's CID: a conflict.
    var v = m.on_new_connection_id(UInt64(2), UInt64(0), _fill(0x05, 8), _fill(0x22, 16))
    assert_true(Bool(v), "conflict reported")
    assert_equal_int(Int(v.value().error_code), Int(PROTOCOL_VIOLATION), "PROTOCOL_VIOLATION")
    # A plain stale seq with a fresh CID is still just retired.
    var ok = m.on_new_connection_id(UInt64(3), UInt64(0), _fill(0x03, 8), _fill(0x33, 16))
    assert_true(not ok, "stale seq only retired")
    print("  test_conflict_checked_before_retire_prior_to: PASS")


def main() raises:
    print("test_quic_cid_manager_bounds:")
    test_local_limit_clamped()
    test_advertised_limit_matches_clamp()
    test_conflict_checked_before_retire_prior_to()
    print("All test_quic_cid_manager_bounds tests passed.")
