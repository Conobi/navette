# tests/quic/test_call_tracker.mojo
#
# Unit tests for CallTracker (rdtsc per-call cost tracker).

from std.testing import assert_true
from navette.quic.profile import CallTracker, CallId, rdtsc, N_CALL_IDS


def test_record_and_read() raises:
    """CallTracker records cycles and computes stats correctly."""
    var ct = CallTracker()
    ct.record(CallId.SEND, UInt64(100))
    ct.record(CallId.SEND, UInt64(200))
    ct.record(CallId.SEND, UInt64(150))
    assert_true(ct.count(CallId.SEND) == UInt64(3), "count should be 3")
    assert_true(ct.total(CallId.SEND) == UInt64(450), "total should be 450")
    assert_true(ct.min_cycles(CallId.SEND) == UInt64(100), "min should be 100")
    assert_true(ct.max_cycles(CallId.SEND) == UInt64(200), "max should be 200")
    assert_true(ct.mean_cycles(CallId.SEND) == UInt64(150), "mean should be 150")


def test_unrecorded_is_zero() raises:
    """Unrecorded functions show zero count and zero mean."""
    var ct = CallTracker()
    assert_true(ct.count(CallId.RECV_FROM_BUFFER) == UInt64(0), "unrecorded count should be 0")
    assert_true(ct.mean_cycles(CallId.RECV_FROM_BUFFER) == UInt64(0), "unrecorded mean should be 0")


def test_rdtsc_monotonic() raises:
    """Successive rdtsc calls return increasing values."""
    var a = rdtsc()
    var b = rdtsc()
    assert_true(b > a, "rdtsc must be monotonically increasing")


def test_report_text_not_empty() raises:
    """Report_text produces output for recorded functions."""
    var ct = CallTracker()
    ct.record(CallId.POLL_QUIC_EVENTS, UInt64(500))
    var text = ct.report_text()
    assert_true(text.byte_length() > 50, "report should have content")


def test_multiple_ids_independent() raises:
    """Recording one CallId does not affect others."""
    var ct = CallTracker()
    ct.record(CallId.SEND, UInt64(100))
    ct.record(CallId.RECV_FROM_BUFFER, UInt64(200))
    assert_true(ct.count(CallId.SEND) == UInt64(1), "SEND count should be 1")
    assert_true(ct.count(CallId.RECV_FROM_BUFFER) == UInt64(1), "RECV count should be 1")
    assert_true(ct.count(CallId.POLL_QUIC_EVENTS) == UInt64(0), "untouched POLL count should be 0")
    assert_true(ct.total(CallId.SEND) == UInt64(100), "SEND total should be 100")
    assert_true(ct.total(CallId.RECV_FROM_BUFFER) == UInt64(200), "RECV total should be 200")


def main() raises:
    test_record_and_read()
    test_unrecorded_is_zero()
    test_rdtsc_monotonic()
    test_report_text_not_empty()
    test_multiple_ids_independent()
