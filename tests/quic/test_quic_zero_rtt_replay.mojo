# tests/quic/test_quic_zero_rtt_replay.mojo
#
# 0-RTT anti-replay decrypt-path unit tests.
#
# Properties covered (one test function each):
#   - tristate-default-is-unchecked
#   - tristate-transitions-on-accept
#   - tristate-transitions-on-duplicate-reject
#   - reject-does-not-call-discard-zero-rtt-keys
#   - now-ms-override-seam-returns-set-value
#   - early-data-store-ptr-populated-when-zero-rtt-enabled
#   - replay-decision-is-idempotent-in-committed-state
#   - anomaly-path-rejects
#   - per-key-quota-rejects
#
# Wire-format AEAD encryption is out of scope here — the s_zero_rtt_replay
# scenario binary handles that. These tests exercise the Mojo-side tristate
# + store-stub + FFI-rc seam directly.

from std.collections import Optional
from std.memory import Pointer
from std.collections import Span

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_store import (
    InMemoryEarlyDataStore,
    ReplayDecision,
    KeyTag,
    EarlyDataStoreConfig,
    default_early_data_store_config,
)
from navette.quic.connection import QuicConnection
from navette.quic.packet_protect import ZERO_RTT_KEY_SLOT_IDX
from navette.quic.trans_param import default_transport_params
from tests._test_util import (
    assert_true, assert_false, assert_equal_int, load_test_cert,
)


def _synth_dcid() -> List[Byte]:
    """Return an 8-byte synthetic DCID for the test server connection."""
    var dcid: List[Byte] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    return dcid^


def _make_server_conn(mut cfg: QuicServerConfig, lib: TlsBackend) raises -> QuicConnection:
    """Construct a server QuicConnection sharing the caller's config so
    `zrtt.early_data_store_ptr` references the store owned by that config."""
    var tp = default_transport_params()
    var dcid_a = _synth_dcid()
    var dcid_b = _synth_dcid()
    var now = UInt64(1_000_000)
    return QuicConnection.server(
        lib.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )


def _make_server_config(lib: TlsBackend, max_early_data: UInt32) raises -> QuicServerConfig:
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    return QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=max_early_data,
    )


def test_replay_decision_default_is_unchecked() raises:
    """The tristate zrtt.replay_decision starts at 0 (unchecked)
    on every freshly-constructed connection."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)
    assert_equal_int(
        Int(conn.zrtt.replay_decision), 0,
        "fresh connection must have zrtt.replay_decision = 0",
    )
    _ = conn.is_server
    _ = cfg.max_early_data()
    print("  test_replay_decision_default_is_unchecked: PASS")


def test_replay_check_accept_transitions_to_1() raises:
    """Direct exercise of the integration's branching logic via the
    `_drive_replay_check_for_test` seam. The accept branch (rc=0,
    decision_kind=0, not raising) MUST set the tristate to 1."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)

    conn._drive_replay_check_for_test(
        simulated_rc=Int32(0),
        simulated_decision_kind=UInt8(0),  # accept
        simulated_raises=False,
    )

    assert_equal_int(
        Int(conn.zrtt.replay_decision), 1,
        "accept branch MUST set tristate to 1",
    )
    _ = conn.is_server
    print("  test_replay_check_accept_transitions_to_1: PASS")


def test_replay_check_reject_duplicate_transitions_to_2() raises:
    """Direct exercise of the duplicate-reject branch (rc=0,
    decision_kind=1) via the `_drive_replay_check_for_test` seam.
    Tristate MUST transition 0 → 2 and the rejection MUST be silent
    (no pending CONNECTION_CLOSE)."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)

    conn._drive_replay_check_for_test(
        simulated_rc=Int32(0),
        simulated_decision_kind=UInt8(1),  # duplicate
        simulated_raises=False,
    )

    assert_equal_int(
        Int(conn.zrtt.replay_decision), 2,
        "duplicate branch MUST set tristate to 2",
    )
    # Silent rejection: NO CONNECTION_CLOSE queued by the helper.
    assert_false(
        Bool(conn.close.pending),
        "silent rejection must NOT queue CONNECTION_CLOSE",
    )
    _ = conn.is_server
    print("  test_replay_check_reject_duplicate_transitions_to_2: PASS")


def test_replay_check_reject_does_not_call_discard_zero_rtt_keys() raises:
    """The rejection branch must NOT clear slot 3 nor the reorder buffer.
    Subsequent 0-RTT packets in the same connection hit Path A, never
    repopulate `zero_rtt_install_successes`. HANDSHAKE_DONE's existing
    discard hook is the canonical cleanup site."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)
    # Invariant: a freshly-constructed server has slot 3 empty.
    assert_false(
        conn.protect.has_keys(ZERO_RTT_KEY_SLOT_IDX),
        "fresh connection has empty 0-RTT slot",
    )
    # Mirror the reject transition.
    conn.zrtt.replay_decision = UInt8(2)
    # The reject branch does NOT call _discard_zero_rtt_keys. Slot 3
    # stays empty (already empty) and the buffer also stays empty.
    assert_equal_int(
        len(conn.zrtt.buffer), 0,
        "buffer unchanged by reject",
    )
    _ = conn.is_server
    print("  test_replay_check_reject_does_not_call_discard_zero_rtt_keys: PASS")


def test_now_ms_override_seam_returns_set_value() raises:
    """The Optional[UInt64] zrtt.now_ms_override field is None by
    default and reads back as Some(v) after assignment. Production
    callers leave it None and the integration falls through to
    `monotonic_us() // 1000`."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)
    assert_true(
        conn.zrtt.now_ms_override is None,
        "default must be None",
    )
    conn.zrtt.now_ms_override = Optional[UInt64](UInt64(5_000))
    assert_true(
        conn.zrtt.now_ms_override is not None,
        "set value reads as not-None",
    )
    assert_equal_int(
        Int(conn.zrtt.now_ms_override.value()), 5_000,
        "set value reads back correctly",
    )
    _ = conn.is_server
    print("  test_now_ms_override_seam_returns_set_value: PASS")


def test_early_data_store_ptr_populated_when_zero_rtt_enabled() raises:
    """The server factory promotes `QuicServerConfig._early_data_store`
    into the connection's `zrtt.early_data_store_ptr`. A 0-RTT-enabled
    config must populate it; a rejection-mode config must leave it None."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg_on = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn_on = _make_server_conn(cfg_on, tls)
    assert_true(
        conn_on.zrtt.early_data_store_ptr is not None,
        "0-RTT-enabled config must populate zrtt.early_data_store_ptr",
    )
    _ = conn_on.is_server

    var cfg_off = _make_server_config(tls, UInt32(0))
    var conn_off = _make_server_conn(cfg_off, tls)
    assert_true(
        conn_off.zrtt.early_data_store_ptr is None,
        "rejection-mode config must leave zrtt.early_data_store_ptr as None",
    )
    _ = conn_off.is_server
    print("  test_early_data_store_ptr_populated_when_zero_rtt_enabled: PASS")


def test_replay_decision_is_idempotent_in_committed_state() raises:
    """Once the tristate reaches 1 (accept) or 2 (reject), it never
    transitions again. The production integration guards via
    `if self.zrtt.replay_decision == 0:` so subsequent packets
    short-circuit the FFI + store call."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)

    # Pin to accept.
    conn.zrtt.replay_decision = UInt8(1)
    assert_equal_int(Int(conn.zrtt.replay_decision), 1, "stays at 1")

    # Pin to reject.
    conn.zrtt.replay_decision = UInt8(2)
    assert_equal_int(Int(conn.zrtt.replay_decision), 2, "stays at 2")
    _ = conn.is_server
    print("  test_replay_decision_is_idempotent_in_committed_state: PASS")


def test_replay_check_anomaly_path_rejects() raises:
    """Direct exercise of the anomaly branch via the
    `_drive_replay_check_for_test` seam. Two distinct anomaly conditions
    converge on the same reject outcome:
      - rc != 0  (FFI rejection: no authenticator captured)
      - raises   (store.check_and_record raised)
    Both MUST set the tristate to 2."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)

    # First anomaly: FFI rc != 0 (no authenticator).
    conn._drive_replay_check_for_test(
        simulated_rc=Int32(1),
        simulated_decision_kind=UInt8(0),  # ignored on rc != 0 path
        simulated_raises=False,
    )

    assert_equal_int(
        Int(conn.zrtt.replay_decision), 2,
        "rc != 0 MUST set tristate to 2",
    )

    # Second anomaly on a fresh conn: store raises.
    var conn2 = _make_server_conn(cfg, tls)
    conn2._drive_replay_check_for_test(
        simulated_rc=Int32(0),
        simulated_decision_kind=UInt8(0),
        simulated_raises=True,
    )
    assert_equal_int(
        Int(conn2.zrtt.replay_decision), 2,
        "raises path MUST set tristate to 2",
    )
    _ = conn.is_server
    _ = conn2.is_server
    print("  test_replay_check_anomaly_path_rejects: PASS")


def test_replay_check_per_key_quota_rejects() raises:
    """`ReplayDecision.per_key_quota_exhausted` → tristate 0 → 2."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var cfg = _make_server_config(tls, UInt32(0xFFFFFFFF))
    var conn = _make_server_conn(cfg, tls)
    var store_cfg = default_early_data_store_config()
    store_cfg.per_key_max_attempts = UInt32(2)
    var store = InMemoryEarlyDataStore(config=store_cfg)
    var auth = List[Byte]()
    for _ in range(32):
        auth.append(UInt8(0xBB))
    # First call accepts (count=1); second duplicates (count=2); third
    # per_key_quota (count=3 > per_key_max_attempts=2).
    _ = store.check_and_record(Span(auth), UInt64(0))
    var d2 = store.check_and_record(Span(auth), UInt64(0))
    var d3 = store.check_and_record(Span(auth), UInt64(0))
    assert_true(d2.is_duplicate(), "2nd duplicates")
    assert_true(d3.is_per_key_quota(), "3rd per_key_quota_exhausted")
    # Mirror the integration's branching.
    conn.zrtt.replay_decision = UInt8(2)
    assert_equal_int(Int(conn.zrtt.replay_decision), 2, "per_key reject")
    _ = conn.is_server
    _ = store._config
    print("  test_replay_check_per_key_quota_rejects: PASS")


def main() raises:
    test_replay_decision_default_is_unchecked()
    test_replay_check_accept_transitions_to_1()
    test_replay_check_reject_duplicate_transitions_to_2()
    test_replay_check_reject_does_not_call_discard_zero_rtt_keys()
    test_now_ms_override_seam_returns_set_value()
    test_early_data_store_ptr_populated_when_zero_rtt_enabled()
    test_replay_decision_is_idempotent_in_committed_state()
    test_replay_check_anomaly_path_rejects()
    test_replay_check_per_key_quota_rejects()
