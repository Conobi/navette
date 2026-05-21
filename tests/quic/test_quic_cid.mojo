# tests/test_quic_cid.mojo
#
# TDD tests for CidManager (src/quic/cid.mojo).
# RFC 9000 §5 — Connection ID management.
#
# Run with:
#   uv run mojo run -I . -D ASSERT=all tests/test_quic_cid.mojo

from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from tests._test_util import assert_true, assert_false, assert_equal_int
from navette.tls.lib import RustlsLibrary
from navette.quic.cid import (
    CidEntry,
    CidManager,
    CID_ACTIVE,
    CID_PENDING_RETIRE,
    CID_RETIRED,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_cid(b: UInt8) -> List[UInt8]:
    """Create a fixed 8-byte CID filled with the given byte value."""
    var cid = List[UInt8](capacity=8)
    for _ in range(8):
        cid.append(b)
    return cid^


def _make_token() -> List[UInt8]:
    """Create a fixed 16-byte reset token filled with zeros."""
    var tok = List[UInt8](capacity=16)
    for _ in range(16):
        tok.append(UInt8(0))
    return tok^


def _make_manager(lib_addr: UInt64) raises -> CidManager:
    """Create a CidManager with known CIDs for deterministic testing."""
    var local_cid = _make_cid(UInt8(0xAA))
    var remote_cid = _make_cid(UInt8(0xBB))
    return CidManager(lib_addr, local_cid, remote_cid, UInt64(4), UInt64(4))


# ── 1. test_initial_state ─────────────────────────────────────────────────────


def test_initial_state(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # One local CID at seq=0 (Active)
    assert_equal_int(len(mgr.local_cids), 1, "local_cids should have 1 entry")
    assert_equal_int(Int(mgr.local_cids[0].sequence), 0, "local seq=0")
    assert_equal_int(Int(mgr.local_cids[0].state), Int(CID_ACTIVE), "local state Active")
    assert_equal_int(len(mgr.local_cids[0].cid), 8, "local CID 8 bytes")
    assert_equal_int(len(mgr.local_cids[0].reset_token), 16, "local reset token 16 bytes")

    # One remote CID at seq=0 (Active)
    assert_equal_int(len(mgr.remote_cids), 1, "remote_cids should have 1 entry")
    assert_equal_int(Int(mgr.remote_cids[0].sequence), 0, "remote seq=0")
    assert_equal_int(Int(mgr.remote_cids[0].state), Int(CID_ACTIVE), "remote state Active")

    # Counters
    assert_equal_int(Int(mgr.local_next_seq), 1, "local_next_seq=1")
    assert_equal_int(Int(mgr.remote_active_cid_seq), 0, "remote_active_cid_seq=0")

    print("  test_initial_state: PASS")


# ── 2. test_cid_generation ────────────────────────────────────────────────────


def test_cid_generation(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Each generated CID is 8 bytes
    var cid0 = mgr.generate_cid()
    assert_equal_int(len(cid0), 8, "CID should be 8 bytes")

    # Generate 10 CIDs and verify uniqueness
    var cids = List[List[UInt8]]()
    for _ in range(10):
        cids.append(mgr.generate_cid())

    var unique = True
    for i in range(len(cids)):
        for j in range(i + 1, len(cids)):
            var same = True
            for k in range(8):
                if cids[i][k] != cids[j][k]:
                    same = False
                    break
            if same:
                unique = False
                break

    assert_true(unique, "all 10 generated CIDs should be unique")
    print("  test_cid_generation: PASS")


# ── 3. test_reset_token_deterministic ─────────────────────────────────────────


def test_reset_token_deterministic(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    var cid_a = _make_cid(UInt8(0x01))
    var cid_b = _make_cid(UInt8(0x02))

    var tok_a1 = mgr.generate_reset_token(Span(cid_a))
    var tok_a2 = mgr.generate_reset_token(Span(cid_a))
    var tok_b = mgr.generate_reset_token(Span(cid_b))

    assert_equal_int(len(tok_a1), 16, "reset token is 16 bytes")

    # Same key + same CID → same token
    var same = True
    for i in range(16):
        if tok_a1[i] != tok_a2[i]:
            same = False
            break
    assert_true(same, "same CID → same token (deterministic)")

    # Different CID → different token (with overwhelming probability)
    var diff = False
    for i in range(16):
        if tok_a1[i] != tok_b[i]:
            diff = True
            break
    assert_true(diff, "different CID → different token")

    print("  test_reset_token_deterministic: PASS")


# ── 4. test_issue_new_cid ─────────────────────────────────────────────────────


def test_issue_new_cid(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Initially 1 active local CID
    assert_equal_int(mgr.active_local_count(), 1, "initial active local count = 1")

    var entry_opt = mgr.issue_new_cid()
    assert_true(entry_opt.__bool__(), "issue_new_cid should return Some")

    var entry = CidEntry(other=entry_opt.value())
    assert_equal_int(Int(entry.sequence), 1, "issued CID has seq=1")
    assert_equal_int(Int(entry.state), Int(CID_ACTIVE), "issued CID is Active")
    assert_equal_int(len(entry.cid), 8, "issued CID is 8 bytes")
    assert_equal_int(len(entry.reset_token), 16, "issued CID has 16-byte token")

    assert_equal_int(mgr.active_local_count(), 2, "active local count = 2 after issue")
    assert_equal_int(Int(mgr.local_next_seq), 2, "local_next_seq incremented to 2")

    print("  test_issue_new_cid: PASS")


# ── 5. test_issue_cid_respects_limit ──────────────────────────────────────────


def test_issue_cid_respects_limit(lib_addr: UInt64) raises:
    # peer_active_limit=2: we start with seq=0 (1 active), can issue seq=1 → 2 active, but not seq=2
    var local_cid = _make_cid(UInt8(0xAA))
    var remote_cid = _make_cid(UInt8(0xBB))
    var mgr = CidManager(lib_addr, local_cid, remote_cid, UInt64(2), UInt64(2))

    # Start: 1 active (seq=0)
    assert_equal_int(mgr.active_local_count(), 1, "initial active = 1")

    # Issue seq=1: now 2 active (== peer_active_limit=2) — OK
    var e1 = mgr.issue_new_cid()
    assert_true(e1.__bool__(), "should issue seq=1")

    # Now at limit: cannot issue further
    var e2 = mgr.issue_new_cid()
    assert_false(e2.__bool__(), "should not issue when at limit (peer_active_limit=2)")

    print("  test_issue_cid_respects_limit: PASS")


# ── 6. test_on_new_connection_id_basic ────────────────────────────────────────


def test_on_new_connection_id_basic(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Initially 1 remote CID
    assert_equal_int(len(mgr.remote_cids), 1, "initial remote count = 1")

    var new_cid = _make_cid(UInt8(0xCC))
    var new_tok = _make_token()
    mgr.on_new_connection_id(UInt64(1), UInt64(0), new_cid, new_tok)

    assert_equal_int(len(mgr.remote_cids), 2, "remote count = 2 after new CID")
    assert_equal_int(Int(mgr.remote_cids[1].sequence), 1, "new remote CID has seq=1")
    assert_equal_int(Int(mgr.remote_cids[1].state), Int(CID_ACTIVE), "new remote CID is Active")

    print("  test_on_new_connection_id_basic: PASS")


# ── 7. test_retire_prior_to ────────────────────────────────────────────────────


def test_retire_prior_to(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Add remote CID seq=1 first
    var cid1 = _make_cid(UInt8(0xC1))
    var tok1 = _make_token()
    mgr.on_new_connection_id(UInt64(1), UInt64(0), cid1, tok1)

    # Now receive NEW_CONNECTION_ID with retire_prior_to=1
    # This should queue retirement of seq=0
    var cid2 = _make_cid(UInt8(0xC2))
    var tok2 = _make_token()
    mgr.on_new_connection_id(UInt64(2), UInt64(1), cid2, tok2)

    # retire_queue should contain seq=0
    var queue = mgr.pending_retire_frames()
    assert_equal_int(len(queue), 1, "retire queue has 1 entry")
    assert_equal_int(Int(queue[0]), 0, "queued seq=0 for retirement")

    # remote CID seq=0 should be PendingRetire
    var found_seq0_pending = False
    for i in range(len(mgr.remote_cids)):
        if mgr.remote_cids[i].sequence == UInt64(0):
            if mgr.remote_cids[i].state == CID_PENDING_RETIRE:
                found_seq0_pending = True
    assert_true(found_seq0_pending, "remote seq=0 should be PendingRetire")

    print("  test_retire_prior_to: PASS")


# ── 8. test_retirement_queue_cap ──────────────────────────────────────────────


def test_retirement_queue_cap(lib_addr: UInt64) raises:
    # peer_active_limit=2 → retire_queue_cap = 2 * 8 = 16
    var local_cid = _make_cid(UInt8(0xAA))
    var remote_cid = _make_cid(UInt8(0xBB))
    var mgr = CidManager(lib_addr, local_cid, remote_cid, UInt64(2), UInt64(2))

    # Add retire_queue_cap + 1 sequences to overflow the queue.
    # Cap = peer_active_limit * 8 = 16.
    # We'll add many remote CIDs first, then trigger retire_prior_to for all.
    # Simpler: just add more items to the retire queue than the cap allows.
    # We can do this by sending retire_prior_to > highest_retire_prior_to many times.

    # Add 17 remote CIDs (seq 1..17) each with retire_prior_to pointing to previous
    # so all previous get queued. We need to exceed cap=16.
    # Strategy: receive seq=1..17, each with retire_prior_to=0.
    # Then receive seq=18 with retire_prior_to=18 → tries to retire all 17 → overflow.

    for i in range(1, 18):
        var c = _make_cid(UInt8(i))
        var t = _make_token()
        mgr.on_new_connection_id(UInt64(i), UInt64(0), c, t)

    # Now retire all 17 (seq 0..16) by setting retire_prior_to=17
    var caught = False
    try:
        var c18 = _make_cid(UInt8(18))
        var t18 = _make_token()
        mgr.on_new_connection_id(UInt64(18), UInt64(17), c18, t18)
    except e:
        if "PROTOCOL_VIOLATION" in String(e):
            caught = True

    assert_true(caught, "overflow of retire_queue_cap should raise PROTOCOL_VIOLATION")
    print("  test_retirement_queue_cap: PASS")


# ── 9. test_late_arriving_cid ─────────────────────────────────────────────────


def test_late_arriving_cid(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Advance highest_retire_prior_to to 3 via a CID that says retire_prior_to=3
    var cid3 = _make_cid(UInt8(0xD0))
    var tok3 = _make_token()
    mgr.on_new_connection_id(UInt64(5), UInt64(3), cid3, tok3)

    # Now a "late" CID arrives with seq=2 (< highest_retire_prior_to=3)
    # It should be stored as PendingRetire and its seq added to retire_queue
    var late_cid = _make_cid(UInt8(0xDE))
    var late_tok = _make_token()
    mgr.on_new_connection_id(UInt64(2), UInt64(0), late_cid, late_tok)

    # Find the late CID entry
    var found_pending = False
    for i in range(len(mgr.remote_cids)):
        if mgr.remote_cids[i].sequence == UInt64(2):
            if mgr.remote_cids[i].state == CID_PENDING_RETIRE:
                found_pending = True

    assert_true(found_pending, "late CID (seq<highest_retire_prior_to) should be PendingRetire")

    print("  test_late_arriving_cid: PASS")


# ── 10. test_on_retire_connection_id ─────────────────────────────────────────


def test_on_retire_connection_id(lib_addr: UInt64) raises:
    var mgr = _make_manager(lib_addr)

    # Issue seq=1 so we have 2 active local CIDs
    _ = mgr.issue_new_cid()
    assert_equal_int(mgr.active_local_count(), 2, "2 active local CIDs before retire")

    # Peer retires our seq=0 local CID
    mgr.on_retire_connection_id(UInt64(0))

    # Find seq=0 in local_cids, it should be Retired
    var found_retired = False
    for i in range(len(mgr.local_cids)):
        if mgr.local_cids[i].sequence == UInt64(0):
            if mgr.local_cids[i].state == CID_RETIRED:
                found_retired = True

    assert_true(found_retired, "local seq=0 should be Retired after RETIRE_CONNECTION_ID")

    print("  test_on_retire_connection_id: PASS")


# ── 11. test_retire_triggers_replacement ─────────────────────────────────────


def test_retire_triggers_replacement(lib_addr: UInt64) raises:
    """RFC 9000 §5.1.1: retiring a local CID below peer_active_limit issues a replacement."""
    # peer_active_limit=2; start with seq=0 (1 active). Issue seq=1 → 2 active.
    var local_cid = _make_cid(UInt8(0xAA))
    var remote_cid = _make_cid(UInt8(0xBB))
    var mgr = CidManager(lib_addr, local_cid, remote_cid, UInt64(4), UInt64(2))

    _ = mgr.issue_new_cid()  # seq=1; now 2 active == peer_active_limit
    assert_equal_int(mgr.active_local_count(), 2, "2 active before retire")

    # Peer retires seq=0 → active drops to 1 (< 2) → replacement seq=2 issued
    mgr.on_retire_connection_id(UInt64(0))

    assert_equal_int(mgr.active_local_count(), 2, "active count restored to 2 after replacement")
    assert_equal_int(Int(mgr.local_next_seq), 3, "local_next_seq advanced to 3")

    print("  test_retire_triggers_replacement: PASS")


# ── 12. test_pending_new_cid_entries ─────────────────────────────────────────


def test_pending_new_cid_entries(lib_addr: UInt64) raises:
    """Verify pending_new_cid_entries returns Active CIDs not yet advertised."""
    var mgr = _make_manager(lib_addr)

    # Initial seq=0 is marked advertised=True (handshake CID, no frame needed).
    var pending0 = mgr.pending_new_cid_entries()
    assert_equal_int(len(pending0), 0, "no pending entries initially (seq=0 is pre-advertised)")

    # Issue seq=1; it should appear as pending.
    _ = mgr.issue_new_cid()
    var pending1 = mgr.pending_new_cid_entries()
    assert_equal_int(len(pending1), 1, "one pending entry after issue_new_cid")
    assert_equal_int(Int(pending1[0].sequence), 1, "pending entry is seq=1")

    # Mark seq=1 advertised; pending list becomes empty.
    mgr.mark_advertised(UInt64(1))
    var pending2 = mgr.pending_new_cid_entries()
    assert_equal_int(len(pending2), 0, "no pending entries after mark_advertised")

    print("  test_pending_new_cid_entries: PASS")


# ── 13. test_clear_advertised ─────────────────────────────────────────────────


def test_clear_advertised(lib_addr: UInt64) raises:
    """Clear_advertised allows a CID to be re-advertised on loss."""
    var local = _make_cid(UInt8(0x01))
    var remote = _make_cid(UInt8(0x03))
    var mgr = CidManager(lib_addr, local^, remote^, UInt64(2), UInt64(2))
    var entry = mgr.issue_new_cid()
    assert_true(entry.__bool__(), "issued seq=1")
    mgr.mark_advertised(UInt64(1))
    var pending_before = mgr.pending_new_cid_entries()
    assert_true(len(pending_before) == 0, "nothing pending after mark_advertised")
    mgr.clear_advertised(UInt64(1))
    var pending_after = mgr.pending_new_cid_entries()
    assert_true(len(pending_after) == 1, "pending after clear_advertised")
    print("  test_clear_advertised: PASS")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() raises:
    print("test_quic_cid:")

    # Initialise shared RustlsLibrary for HMAC-SHA256.
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary())
    var lib_addr = UInt64(Int(lib_ptr))

    test_initial_state(lib_addr)
    test_cid_generation(lib_addr)
    test_reset_token_deterministic(lib_addr)
    test_issue_new_cid(lib_addr)
    test_issue_cid_respects_limit(lib_addr)
    test_on_new_connection_id_basic(lib_addr)
    test_retire_prior_to(lib_addr)
    test_retirement_queue_cap(lib_addr)
    test_late_arriving_cid(lib_addr)
    test_on_retire_connection_id(lib_addr)
    test_retire_triggers_replacement(lib_addr)
    test_pending_new_cid_entries(lib_addr)
    test_clear_advertised(lib_addr)

    print("All test_quic_cid tests passed.")
