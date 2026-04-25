# tests/test_quic_profile.mojo
#
# Unit tests for src/quic/profile.mojo (Plan A).

from src.quic.profile import PROFILE_ACCEPT, monotonic_us
from testing import assert_true


def test_monotonic_us_increases() raises:
    var t0 = monotonic_us()
    # Burn a small amount of work so the clock advances.
    var sink: UInt64 = 0
    for i in range(10000):
        sink = sink + UInt64(i)
    var t1 = monotonic_us()
    assert_true(t1 >= t0, "monotonic_us must be non-decreasing")
    assert_true(sink > 0, "sink used (defeat DCE)")
    print("PASS: test_monotonic_us_increases")


def test_profile_accept_is_bool() raises:
    # Compile-time check: PROFILE_ACCEPT exists and is a Bool.
    @parameter
    if PROFILE_ACCEPT:
        print("PROFILE_ACCEPT is True (on-build)")
    else:
        print("PROFILE_ACCEPT is False (off-build)")
    print("PASS: test_profile_accept_is_bool")


def test_default_init() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    assert_true(p.idle_us_total == UInt64(0), "idle_us_total starts at 0")
    assert_true(p.busy_us_total == UInt64(0), "busy_us_total starts at 0")
    assert_true(p.on_flush_count == UInt64(0), "on_flush_count starts at 0")
    assert_true(p.pkt_count == UInt64(0), "pkt_count starts at 0")
    assert_true(p.ffi_shim_us_total == UInt64(0), "ffi_shim starts at 0")
    assert_true(p.hp_us_total == UInt64(0), "hp starts at 0")
    assert_true(p.aead_us_total == UInt64(0), "aead starts at 0")
    assert_true(p.header_parse_us_total == UInt64(0), "header_parse starts at 0")
    assert_true(p.frame_parse_us_total == UInt64(0), "frame_parse starts at 0")
    assert_true(p.sm_us_total == UInt64(0), "sm starts at 0")
    assert_true(p.drain_us_total == UInt64(0), "drain starts at 0")
    assert_true(p.residual_us_total == UInt64(0), "residual starts at 0")
    assert_true(p.per_pkt_total_overflow == UInt64(0), "overflow starts at 0")
    assert_true(p.hs_arrivals == UInt64(0), "hs_arrivals starts at 0")
    assert_true(p.hs_completed == UInt64(0), "hs_completed starts at 0")
    assert_true(p.hs_timed_out == UInt64(0), "hs_timed_out starts at 0")
    assert_true(len(p.pkts_per_flush_buckets) == 8, "fan-out has 8 buckets")
    assert_true(len(p.per_pkt_total_buckets) == 24, "per_pkt has 24 buckets")
    assert_true(len(p.hs_latency_us) == 0, "latency vector starts empty")
    assert_true(p.run_start_us > UInt64(0), "run_start_us stamped at construction")
    print("PASS: test_default_init")


def test_record_idle_accumulates() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_idle(UInt64(100))
    p.record_idle(UInt64(250))
    p.record_idle(UInt64(50))
    assert_true(p.idle_us_total == UInt64(400), "idle accumulates")
    print("PASS: test_record_idle_accumulates")


def test_record_flush_buckets_and_sums() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Coverage of all 8 buckets.
    p.record_flush(1, UInt64(10))      # bucket 0
    p.record_flush(2, UInt64(20))      # bucket 1 (2-3)
    p.record_flush(3, UInt64(30))      # bucket 1
    p.record_flush(4, UInt64(40))      # bucket 2 (4-7)
    p.record_flush(7, UInt64(50))      # bucket 2
    p.record_flush(8, UInt64(60))      # bucket 3 (8-15)
    p.record_flush(15, UInt64(70))     # bucket 3
    p.record_flush(16, UInt64(80))     # bucket 4 (16-31)
    p.record_flush(31, UInt64(90))     # bucket 4
    p.record_flush(32, UInt64(100))    # bucket 5 (32-63)
    p.record_flush(63, UInt64(110))    # bucket 5
    p.record_flush(64, UInt64(120))    # bucket 6 (64-127)
    p.record_flush(127, UInt64(130))   # bucket 6
    p.record_flush(128, UInt64(140))   # bucket 7 (128+)
    p.record_flush(500, UInt64(150))   # bucket 7
    assert_true(p.on_flush_count == UInt64(15), "on_flush_count = 15")
    var expected_busy = UInt64(10 + 20 + 30 + 40 + 50 + 60 + 70 + 80 + 90 + 100 + 110 + 120 + 130 + 140 + 150)
    assert_true(p.busy_us_total == expected_busy, "busy_us accumulated")
    assert_true(p.pkts_per_flush_buckets[0] == UInt64(1), "bucket[0] = 1")
    assert_true(p.pkts_per_flush_buckets[1] == UInt64(2), "bucket[1] = 2")
    assert_true(p.pkts_per_flush_buckets[2] == UInt64(2), "bucket[2] = 2")
    assert_true(p.pkts_per_flush_buckets[3] == UInt64(2), "bucket[3] = 2")
    assert_true(p.pkts_per_flush_buckets[4] == UInt64(2), "bucket[4] = 2")
    assert_true(p.pkts_per_flush_buckets[5] == UInt64(2), "bucket[5] = 2")
    assert_true(p.pkts_per_flush_buckets[6] == UInt64(2), "bucket[6] = 2")
    assert_true(p.pkts_per_flush_buckets[7] == UInt64(2), "bucket[7] = 2")
    print("PASS: test_record_flush_buckets_and_sums")


def test_per_pkt_bucket_assignment() raises:
    from src.quic.profile import _per_pkt_bucket
    # us == 0 → bucket 0
    assert_true(_per_pkt_bucket(UInt64(0)) == 0, "0us → bucket 0")
    # us == 1 → bucket 1 ([1, 2))
    assert_true(_per_pkt_bucket(UInt64(1)) == 1, "1us → bucket 1")
    # us == 2 → bucket 2 ([2, 4))
    assert_true(_per_pkt_bucket(UInt64(2)) == 2, "2us → bucket 2")
    # us == 3 → still bucket 2
    assert_true(_per_pkt_bucket(UInt64(3)) == 2, "3us → bucket 2")
    # us == 4 → bucket 3
    assert_true(_per_pkt_bucket(UInt64(4)) == 3, "4us → bucket 3")
    # us == 7 → bucket 3
    assert_true(_per_pkt_bucket(UInt64(7)) == 3, "7us → bucket 3")
    # us == 8 → bucket 4
    assert_true(_per_pkt_bucket(UInt64(8)) == 4, "8us → bucket 4")
    # us == 2^22 = 4_194_304 → bucket 23 (top closed bucket)
    assert_true(_per_pkt_bucket(UInt64(4_194_304)) == 23, "4.2Mus → bucket 23")
    # us == 2^23 - 1 = 8_388_607 → still bucket 23
    assert_true(_per_pkt_bucket(UInt64(8_388_607)) == 23, "<8.39s → bucket 23")
    # us == 2^23 = 8_388_608 → overflow (returns 24)
    assert_true(_per_pkt_bucket(UInt64(8_388_608)) == 24, "8.39s → overflow=24")
    # us == 100_000_000 (100s) → overflow
    assert_true(_per_pkt_bucket(UInt64(100_000_000)) == 24, "100s → overflow=24")
    print("PASS: test_per_pkt_bucket_assignment")


def main() raises:
    test_monotonic_us_increases()
    test_profile_accept_is_bool()
    test_default_init()
    test_record_idle_accumulates()
    test_record_flush_buckets_and_sums()
    test_per_pkt_bucket_assignment()
    print("All Plan A tests passed.")
