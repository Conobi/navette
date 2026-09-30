# tests/quic/test_quic_cid_epoch.mojo
#
# `CidManager.cid_epoch` is the cheap "did the local CID set change" signal
# the H3 server polls to keep its demux keys in sync with issued CIDs.

from tests._test_util import assert_true, assert_equal_int
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.quic.cid import CidManager


def _make_cid(b: UInt8) -> List[Byte]:
    var cid = List[Byte](capacity=8)
    for _ in range(8):
        cid.append(b)
    return cid^


def test_epoch_moves_on_issue_and_retire(lib: SharedLibrary) raises:
    var mgr = CidManager(lib, _make_cid(0xAA), _make_cid(0xBB), UInt64(2), UInt64(4))
    var e0 = mgr.cid_epoch
    _ = mgr.issue_new_cid()
    var e1 = mgr.cid_epoch
    assert_true(e1 > e0, "issue bumps the epoch")
    _ = mgr.issue_new_cid()
    var e2 = mgr.cid_epoch
    assert_true(e2 > e1, "second issue bumps the epoch")
    _ = mgr.on_retire_connection_id(UInt64(1))
    var e3 = mgr.cid_epoch
    assert_true(e3 > e2, "an effective retire bumps the epoch")
    _ = mgr.on_retire_connection_id(UInt64(1))
    assert_equal_int(Int(mgr.cid_epoch), Int(e3), "a repeated retire is ignored")
    print("  test_epoch_moves_on_issue_and_retire: PASS")


def test_epoch_stable_when_nothing_changes(lib: SharedLibrary) raises:
    var mgr = CidManager(lib, _make_cid(0xAA), _make_cid(0xBB), UInt64(2), UInt64(2))
    _ = mgr.issue_new_cid()
    var e = mgr.cid_epoch
    assert_true(not mgr.issue_new_cid(), "at the issue limit")
    _ = mgr.on_retire_connection_id(UInt64(9))  # never issued: verdict, no change
    _ = mgr.pending_new_cid_entries()
    assert_equal_int(Int(mgr.cid_epoch), Int(e), "refused issue and bad retire leave it alone")
    print("  test_epoch_stable_when_nothing_changes: PASS")


def main() raises:
    print("test_quic_cid_epoch:")
    var tls = TlsBackend()
    var shared = tls.shared()
    test_epoch_moves_on_issue_and_retire(shared)
    test_epoch_stable_when_nothing_changes(shared)
    print("All test_quic_cid_epoch tests passed.")
