"""AcceptBackoff: 100 ms pause, one log per 10 s, every exhaustion counted."""

from navette.protect.accept_backoff import AcceptBackoff, ACCEPT_BACKOFF_US, ACCEPT_LOG_INTERVAL_US
from tests._test_util import assert_true, assert_equal_int


def test_backoff_and_log_rate() raises:
    var b = AcceptBackoff()
    var t = UInt64(5_000_000)
    assert_true(b.may_accept(t), "accepting before any exhaustion")
    assert_true(b.on_fd_exhausted(t), "first exhaustion logs")
    assert_true(not b.may_accept(t + ACCEPT_BACKOFF_US - 1), "paused for 100 ms")
    assert_true(b.may_accept(t + ACCEPT_BACKOFF_US), "resumes after 100 ms")
    var logs = 0
    for i in range(1, 200):
        if b.on_fd_exhausted(t + UInt64(i) * ACCEPT_BACKOFF_US):
            logs += 1
    assert_equal_int(logs, 1, "one more log in 19.9 s (at the 10 s mark)")
    assert_true(b.accept_fd_exhausted == UInt64(200), "every exhaustion counted")
    print("PASS: test_backoff_and_log_rate")


def main() raises:
    test_backoff_and_log_rate()
