"""RateWindow against an explicit list of event times."""

from navette.protect.rate_window import RateWindow, RATE_BUCKET_US, RATE_BUCKETS
from tests._test_util import assert_true, assert_equal_int
from tests.protect._prop import Rng


def test_matches_oracle_property() raises:
    """30 seeds × 2,000 events with random gaps (including backwards steps)."""
    for seed in range(30):
        var rng = Rng(UInt64(0x3A7E + seed))
        var w = RateWindow()
        var slots = List[UInt64]()
        var now = UInt64(10_000_000)
        var newest = UInt64(0)
        for i in range(2000):
            var k = rng.below(100)
            if k < 70:
                now += UInt64(rng.below(30_000))
            elif k < 95:
                now += UInt64(rng.below(400_000))
            else:
                now -= UInt64(rng.below(150_000))
            var slot = now // RATE_BUCKET_US
            if slot > newest:
                newest = slot
            slots.append(newest)
            var got = w.add(now)
            var want = 0
            for s in slots:
                if s + UInt64(RATE_BUCKETS) > newest:
                    want += 1
            assert_equal_int(got, want, "seed " + String(seed) + " event " + String(i))
    print("PASS: test_matches_oracle_property")


def test_threshold_example() raises:
    """201 events inside one second exceed the 200/s guard; spread over 2 s they do not."""
    var w = RateWindow()
    var last = 0
    for i in range(201):
        last = w.add(UInt64(1_000_000 + i * 4_000))
    assert_true(last > 200, "burst trips")
    var w2 = RateWindow()
    var peak = 0
    for i in range(201):
        peak = max(peak, w2.add(UInt64(1_000_000 + i * 10_000)))
    assert_true(peak <= 200, "spread does not trip")
    print("PASS: test_threshold_example")


def main() raises:
    test_matches_oracle_property()
    test_threshold_example()
