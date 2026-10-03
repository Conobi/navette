"""Overload governor core: histogram, sensor arithmetic, controller, per-connection limits, facade (pure, fake clock)."""

from std.bit import bit_width
from navette.protect.governor import DelayHist, interval_us, retry_after_s
from tests._test_util import assert_true
from tests.protect._prop import Rng, prop_iters


def _bucket(us: UInt64) -> UInt64:
    return min(bit_width(us), 31)


def test_p90_exact_property() raises:
    """The histogram p90 lies in the log2 bucket of the exact sorted p90."""
    var rng = Rng(0x6090)
    for c in range(prop_iters(300)):
        var n = 20 + rng.below(400)
        var xs = List[UInt64]()
        var h = DelayHist()
        var top = 1 + rng.below(30)
        for _ in range(n):
            var v = rng.next() >> UInt64(64 - top)
            xs.append(v)
            h.insert(v)
        sort(xs)
        var exact = xs[(9 * n + 9) // 10 - 1]
        var got = h.p90()
        assert_true(_bucket(got) == _bucket(exact), "case " + String(c) + ": p90 " + String(got) + " vs exact " + String(exact))


def test_insert_pass_and_reset() raises:
    var h = DelayHist()
    h.insert_pass(100, 10, 1000)
    assert_true(h.total == 10, "ten samples")
    for k in range(10):
        assert_true(h.buckets[Int(_bucket(UInt64(100 * (k + 1))))] >= 1, "sample " + String(100 * (k + 1)))
    h.insert(UInt64.MAX)
    assert_true(h.buckets[31] == 1, "UInt64.MAX lands in the top bucket")
    h.reset()
    assert_true(h.total == 0 and h.p90() == 0, "reset zeroes")
    for i in range(32):
        assert_true(h.buckets[i] == 0, "bucket zeroed")


def test_derived_constants() raises:
    assert_true(interval_us(5_000) == 100_000, "I = 20 t")
    assert_true(retry_after_s(5_000) == 1, "1 s at the default")
    assert_true(retry_after_s(1_000) == 1, "at least 1 s")
    assert_true(retry_after_s(10_000_000) == 2_000, "200 t in whole seconds")


def main() raises:
    test_p90_exact_property()
    test_insert_pass_and_reset()
    test_derived_constants()
    print("PASS: test_governor")
