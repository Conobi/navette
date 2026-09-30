# tests/quic/test_quic_cid_limits.mojo
#
# Connection-ID bookkeeping must stay bounded whatever the peer sends:
# NEW_CONNECTION_ID floods, retire_prior_to churn, duplicate and
# conflicting sequence numbers, and RETIRE_CONNECTION_ID for sequence
# numbers never issued (RFC 9000 Sections 5.1.1, 19.15, 19.16).

from tests._test_util import assert_true, assert_equal_int
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.cid import CidManager, MAX_ISSUED_CIDS, MAX_RETIRE_QUEUE
from navette.quic.error import CONNECTION_ID_LIMIT_ERROR, PROTOCOL_VIOLATION

comptime _FLOOD = 10_000
comptime _LOCAL_LIMIT: UInt64 = 2


def _cid(seq: Int, salt: UInt8 = 0) -> List[Byte]:
    """8-byte CID unique per (seq, salt)."""
    var cid = List[Byte](capacity=8)
    for i in range(8):
        cid.append(UInt8((seq >> (8 * i)) & 0xFF) ^ salt)
    cid[7] = cid[7] ^ 0x5A
    return cid^


def _tok(b: UInt8) -> List[Byte]:
    var t = List[Byte](capacity=16)
    for _ in range(16):
        t.append(b)
    return t^


def _mgr(lib: SharedLibrary, peer_limit: UInt64 = 4) raises -> CidManager:
    var local = List[Byte](capacity=8)
    var remote = List[Byte](capacity=8)
    for _ in range(8):
        local.append(0xAA)
        remote.append(0xBB)
    return CidManager(lib, local, remote, _LOCAL_LIMIT, peer_limit)


def test_new_cid_flood_hits_limit(lib: SharedLibrary) raises:
    """Distinct sequence numbers past our limit close with CONNECTION_ID_LIMIT_ERROR."""
    var mgr = _mgr(lib)
    var first_err = -1
    var err_code = UInt64(0)
    for i in range(1, _FLOOD + 1):
        var v = mgr.on_new_connection_id(UInt64(i), UInt64(0), _cid(i), _tok(1))
        if v and first_err < 0:
            first_err = i
            err_code = v.value().error_code
        assert_true(
            len(mgr.remote_cids) <= Int(_LOCAL_LIMIT),
            "remote_cids bounded by our limit at iter " + String(i),
        )
    assert_equal_int(first_err, 2, "seq 0 + seq 1 fill limit 2; seq 2 trips")
    assert_equal_int(
        Int(err_code), Int(CONNECTION_ID_LIMIT_ERROR), "CONNECTION_ID_LIMIT_ERROR"
    )
    print("  test_new_cid_flood_hits_limit: PASS")


def test_retire_prior_to_churn_unacked_hits_cap(lib: SharedLibrary) raises:
    """A peer that bumps retire_prior_to but never ACKs our RETIREs is closed."""
    var mgr = _mgr(lib)
    var first_err = -1
    var err_code = UInt64(0)
    for i in range(1, _FLOOD + 1):
        var v = mgr.on_new_connection_id(UInt64(i), UInt64(i), _cid(i), _tok(1))
        if v and first_err < 0:
            first_err = i
            err_code = v.value().error_code
        # Frames go out but are never acknowledged.
        _ = mgr.pending_retire_frames()
        assert_true(len(mgr.remote_cids) <= Int(_LOCAL_LIMIT), "remote bounded")
        assert_true(
            len(mgr.retire_queue) <= mgr.retire_queue_cap, "retire queue bounded"
        )
    assert_true(first_err > 0, "unacked retirements eventually refused")
    assert_true(first_err <= mgr.retire_queue_cap + 1, "refused at the cap")
    assert_equal_int(
        Int(err_code), Int(CONNECTION_ID_LIMIT_ERROR), "CONNECTION_ID_LIMIT_ERROR"
    )
    print("  test_retire_prior_to_churn_unacked_hits_cap: PASS")


def test_retire_prior_to_churn_acked_stays_bounded(lib: SharedLibrary) raises:
    """A legitimate rotating peer is never refused and memory stays flat."""
    var mgr = _mgr(lib)
    for i in range(1, _FLOOD + 1):
        var v = mgr.on_new_connection_id(UInt64(i), UInt64(i), _cid(i), _tok(1))
        assert_true(not v, "no error for acked churn at iter " + String(i))
        var sent = mgr.pending_retire_frames()
        for ref s in sent:
            mgr.on_retire_acked(s)
        assert_equal_int(len(mgr.remote_cids), 1, "only the newest CID kept")
    assert_equal_int(
        Int(mgr.remote_active_cid_seq), _FLOOD, "active DCID moved off retired CIDs"
    )
    print("  test_retire_prior_to_churn_acked_stays_bounded: PASS")


def test_duplicate_same_cid_ignored(lib: SharedLibrary) raises:
    var mgr = _mgr(lib)
    assert_true(not mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(1)), "first")
    for _ in range(100):
        var v = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(1))
        assert_true(not v, "exact repeat is ignored")
    assert_equal_int(len(mgr.remote_cids), 2, "repeat not stored twice")
    print("  test_duplicate_same_cid_ignored: PASS")


def test_conflicting_sequence_is_protocol_violation(lib: SharedLibrary) raises:
    var mgr = _mgr(lib)
    _ = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(1))
    var diff_cid = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1, 0x33), _tok(1))
    assert_true(Bool(diff_cid), "same seq, different CID refused")
    assert_equal_int(Int(diff_cid.value().error_code), Int(PROTOCOL_VIOLATION), "PV (cid)")
    var diff_tok = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(2))
    assert_true(Bool(diff_tok), "same seq, different token refused")
    assert_equal_int(Int(diff_tok.value().error_code), Int(PROTOCOL_VIOLATION), "PV (token)")
    var diff_seq = mgr.on_new_connection_id(UInt64(7), UInt64(0), _cid(1), _tok(1))
    assert_true(Bool(diff_seq), "same CID under another seq refused")
    assert_equal_int(Int(diff_seq.value().error_code), Int(PROTOCOL_VIOLATION), "PV (seq)")
    assert_equal_int(len(mgr.remote_cids), 2, "nothing stored on conflict")
    print("  test_conflicting_sequence_is_protocol_violation: PASS")


def test_retire_prior_to_prunes(lib: SharedLibrary) raises:
    var mgr = _mgr(lib)
    _ = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(1))
    var v = mgr.on_new_connection_id(UInt64(2), UInt64(2), _cid(2), _tok(1))
    assert_true(not v, "retire_prior_to=2 frees room for seq 2")
    assert_equal_int(len(mgr.remote_cids), 1, "seqs 0 and 1 dropped")
    assert_equal_int(Int(mgr.remote_cids[0].sequence), 2, "seq 2 kept")
    assert_equal_int(Int(mgr.remote_active_cid_seq), 2, "switched to seq 2")
    var q = mgr.pending_retire_frames()
    assert_equal_int(len(q), 2, "two RETIREs queued")
    # Late arrival below retire_prior_to: retired, not stored; repeats and
    # reordered copies do not queue a second RETIRE while one is outstanding.
    var late = mgr.on_new_connection_id(UInt64(1), UInt64(0), _cid(1), _tok(1))
    assert_true(not late, "late arrival is not an error")
    assert_equal_int(len(mgr.remote_cids), 1, "late arrival not stored")
    assert_equal_int(len(mgr.retire_queue), 0, "seq 1 already outstanding")
    print("  test_retire_prior_to_prunes: PASS")


def test_local_retire_reissue_cycles_bounded(lib: SharedLibrary) raises:
    var mgr = _mgr(lib, UInt64(4))
    while mgr.needs_new_cid():
        _ = mgr.issue_new_cid()
    for i in range(1000):
        var seq = mgr.local_cids[0].sequence
        var v = mgr.on_retire_connection_id(seq)
        assert_true(not v, "retire of an issued CID accepted at iter " + String(i))
        assert_true(
            len(mgr.local_cids) <= MAX_ISSUED_CIDS,
            "local_cids bounded at iter " + String(i),
        )
    assert_equal_int(mgr.active_local_count(), 4, "replacements keep the set full")
    print("  test_local_retire_reissue_cycles_bounded: PASS")


def test_retire_unknown_seq_is_protocol_violation(lib: SharedLibrary) raises:
    var mgr = _mgr(lib, UInt64(2))
    _ = mgr.issue_new_cid()  # seq 1; next unissued is 2
    var v = mgr.on_retire_connection_id(UInt64(2))
    assert_true(Bool(v), "never-issued seq refused")
    assert_equal_int(Int(v.value().error_code), Int(PROTOCOL_VIOLATION), "PV")
    var huge = mgr.on_retire_connection_id(UInt64(1) << 60)
    assert_true(Bool(huge), "huge seq refused")
    # Retiring an already-retired seq is a harmless repeat.
    assert_true(not mgr.on_retire_connection_id(UInt64(1)), "first retire")
    assert_true(not mgr.on_retire_connection_id(UInt64(1)), "repeat ignored")
    print("  test_retire_unknown_seq_is_protocol_violation: PASS")


def test_retire_cid_of_carrying_packet(lib: SharedLibrary) raises:
    var mgr = _mgr(lib, UInt64(2))
    _ = mgr.issue_new_cid()  # seq 1
    var cid1 = mgr.local_cids[1].cid.copy()
    var v = mgr.on_retire_connection_id(UInt64(1), Span(cid1))
    assert_true(Bool(v), "retiring the packet's own DCID refused")
    assert_equal_int(Int(v.value().error_code), Int(PROTOCOL_VIOLATION), "PV")
    var cid0 = mgr.local_cids[0].cid.copy()
    assert_true(not mgr.on_retire_connection_id(UInt64(1), Span(cid0)), "other DCID ok")
    print("  test_retire_cid_of_carrying_packet: PASS")


def test_retire_queue_cap_follows_local_limit(lib: SharedLibrary) raises:
    var mgr = _mgr(lib, (UInt64(1) << 62) - 1)
    assert_equal_int(mgr.retire_queue_cap, Int(_LOCAL_LIMIT) * 3, "3x our limit")
    mgr.set_peer_active_limit(UInt64(2))
    assert_equal_int(mgr.retire_queue_cap, Int(_LOCAL_LIMIT) * 3, "peer limit irrelevant")
    var big = CidManager(lib, _cid(1), _cid(2), (UInt64(1) << 62) - 1, UInt64(2))
    assert_equal_int(big.retire_queue_cap, MAX_RETIRE_QUEUE, "hard ceiling")
    print("  test_retire_queue_cap_follows_local_limit: PASS")


def main() raises:
    print("test_quic_cid_limits:")
    var tls = TlsBackend()
    var shared = tls.shared()
    test_new_cid_flood_hits_limit(shared)
    test_retire_prior_to_churn_unacked_hits_cap(shared)
    test_retire_prior_to_churn_acked_stays_bounded(shared)
    test_duplicate_same_cid_ignored(shared)
    test_conflicting_sequence_is_protocol_violation(shared)
    test_retire_prior_to_prunes(shared)
    test_local_retire_reissue_cycles_bounded(shared)
    test_retire_unknown_seq_is_protocol_violation(shared)
    test_retire_cid_of_carrying_packet(shared)
    test_retire_queue_cap_follows_local_limit(shared)
    print("All test_quic_cid_limits tests passed.")
