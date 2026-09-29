# tests/quic/test_quic_cid_issue_cap.mojo
#
# The peer's active_connection_id_limit (a varint up to 2^62-1) must not
# drive how many CIDs we issue: RFC 9000 Section 5.1.1 lets an endpoint
# issue fewer, and an unbounded issuance loop is a single-handshake DoS.

from tests._test_util import assert_true, assert_equal_int
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.cid import CidManager, MAX_ISSUED_CIDS

comptime _HUGE_LIMIT: UInt64 = (UInt64(1) << 62) - 1
# Upper bound on the drive loops so a regression fails instead of hanging.
comptime _LOOP_GUARD = 64


def _make_cid(b: UInt8) -> List[Byte]:
    var cid = List[Byte](capacity=8)
    for _ in range(8):
        cid.append(b)
    return cid^


def _issue_until_refused(mut mgr: CidManager) raises -> Int:
    """Issue CIDs until refused (or the guard trips); returns the count issued."""
    var n = 0
    while n < _LOOP_GUARD:
        if not mgr.issue_new_cid():
            break
        n += 1
    return n


def test_huge_peer_limit_ctor(lib: SharedLibrary) raises:
    var mgr = CidManager(
        lib, _make_cid(0xAA), _make_cid(0xBB), UInt64(2), _HUGE_LIMIT
    )
    var issued = _issue_until_refused(mgr)
    assert_equal_int(
        mgr.active_local_count(), MAX_ISSUED_CIDS,
        "active local CIDs capped at MAX_ISSUED_CIDS",
    )
    assert_equal_int(issued, MAX_ISSUED_CIDS - 1, "seq=0 plus cap-1 issued")
    assert_true(not mgr.needs_new_cid(), "no more issuance wanted at cap")
    assert_equal_int(
        mgr.retire_queue_cap, MAX_ISSUED_CIDS * 8,
        "retire_queue_cap derived from the clamped limit (no overflow)",
    )
    print("  test_huge_peer_limit_ctor: PASS")


def test_huge_peer_limit_setter(lib: SharedLibrary) raises:
    """Transport parameters arrive after construction via the setter."""
    var mgr = CidManager(
        lib, _make_cid(0xAA), _make_cid(0xBB), UInt64(2), UInt64(2)
    )
    mgr.set_peer_active_limit(_HUGE_LIMIT)
    assert_equal_int(
        mgr.retire_queue_cap, MAX_ISSUED_CIDS * 8, "setter clamps retire cap"
    )
    _ = _issue_until_refused(mgr)
    assert_equal_int(
        mgr.active_local_count(), MAX_ISSUED_CIDS, "setter clamps issuance"
    )
    # Retiring one CID issues a single replacement, never more.
    mgr.on_retire_connection_id(UInt64(0))
    assert_equal_int(
        mgr.active_local_count(), MAX_ISSUED_CIDS, "replacement stays at cap"
    )
    print("  test_huge_peer_limit_setter: PASS")


def test_small_peer_limit_respected(lib: SharedLibrary) raises:
    var mgr = CidManager(
        lib, _make_cid(0xAA), _make_cid(0xBB), UInt64(2), UInt64(2)
    )
    mgr.set_peer_active_limit(UInt64(2))
    _ = _issue_until_refused(mgr)
    assert_equal_int(mgr.active_local_count(), 2, "peer limit 2 honoured")
    assert_equal_int(mgr.retire_queue_cap, 16, "retire cap 2 * 8")
    assert_equal_int(mgr.issue_limit(), 2, "issue_limit = min(peer, cap)")
    print("  test_small_peer_limit_respected: PASS")


def main() raises:
    print("test_quic_cid_issue_cap:")
    var tls = TlsBackend()
    var shared = tls.shared()
    test_huge_peer_limit_ctor(shared)
    test_huge_peer_limit_setter(shared)
    test_small_peer_limit_respected(shared)
    print("All test_quic_cid_issue_cap tests passed.")
