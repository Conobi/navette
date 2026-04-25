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


def test_record_pkt_sums_and_residual() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # total=120, legs sum to 70 → residual = 50.
    # ffi_us=80 overlaps with sm_us=20; not subtracted from residual.
    p.record_pkt(
        total_us=UInt64(120),
        ffi_us=UInt64(80),
        hp_us=UInt64(10),
        aead_us=UInt64(15),
        header_parse_us=UInt64(8),
        frame_parse_us=UInt64(12),
        sm_us=UInt64(25),
    )
    assert_true(p.pkt_count == UInt64(1), "pkt_count = 1")
    assert_true(p.ffi_shim_us_total == UInt64(80), "ffi sum")
    assert_true(p.hp_us_total == UInt64(10), "hp sum")
    assert_true(p.aead_us_total == UInt64(15), "aead sum")
    assert_true(p.header_parse_us_total == UInt64(8), "header_parse sum")
    assert_true(p.frame_parse_us_total == UInt64(12), "frame_parse sum")
    assert_true(p.sm_us_total == UInt64(25), "sm sum")
    # residual = total - (hp + aead + header_parse + frame_parse + sm)
    #         = 120 - (10 + 15 + 8 + 12 + 25) = 120 - 70 = 50
    assert_true(p.residual_us_total == UInt64(50), "residual = 50")
    # Bucket: 120us → bucket 7 ([64, 128))
    assert_true(p.per_pkt_total_buckets[7] == UInt64(1), "120us in bucket 7")
    assert_true(p.per_pkt_total_overflow == UInt64(0), "no overflow")
    print("PASS: test_record_pkt_sums_and_residual")


def test_record_pkt_overflow() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # total=10s = 10_000_000us → overflow.
    p.record_pkt(
        total_us=UInt64(10_000_000),
        ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
        header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
    )
    assert_true(p.pkt_count == UInt64(1), "pkt_count = 1")
    assert_true(p.per_pkt_total_overflow == UInt64(1), "overflow = 1")
    # All closed buckets stay 0.
    for i in range(24):
        assert_true(p.per_pkt_total_buckets[i] == UInt64(0), "no closed-bucket bump")
    assert_true(p.residual_us_total == UInt64(10_000_000), "residual = total when legs=0")
    print("PASS: test_record_pkt_overflow")


def test_record_pkt_residual_underflow_safe() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Defensive: legs sum to MORE than total (clock noise / overlap).
    # residual must clamp to 0 instead of UInt64-underflowing.
    p.record_pkt(
        total_us=UInt64(50),
        ffi_us=UInt64(0),
        hp_us=UInt64(20),
        aead_us=UInt64(20),
        header_parse_us=UInt64(20),
        frame_parse_us=UInt64(20),
        sm_us=UInt64(20),  # legs sum = 100 > total = 50
    )
    assert_true(p.residual_us_total == UInt64(0), "residual clamped to 0 on underflow")
    print("PASS: test_record_pkt_residual_underflow_safe")


def test_record_drain_accumulates() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain(UInt64(40))
    p.record_drain(UInt64(60))
    p.record_drain(UInt64(0))
    assert_true(p.drain_us_total == UInt64(100), "drain accumulates")
    print("PASS: test_record_drain_accumulates")


def test_handshake_records() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))
    p.record_handshake_complete(UInt64(46000))
    p.record_handshake_timeout(UInt64(7))
    p.record_handshake_timeout()  # default count=1
    assert_true(p.hs_arrivals == UInt64(3), "3 arrivals")
    assert_true(p.hs_completed == UInt64(2), "2 completed")
    assert_true(p.hs_timed_out == UInt64(8), "7 + 1 = 8 timeouts")
    assert_true(len(p.hs_latency_us) == 2, "latency vector has 2 entries")
    assert_true(p.hs_latency_us[0] == UInt64(8400), "first latency")
    assert_true(p.hs_latency_us[1] == UInt64(46000), "second latency")
    print("PASS: test_handshake_records")


def test_exact_percentile_basic() raises:
    from src.quic.profile import _exact_percentile
    var v = List[UInt64]()
    for i in range(1, 101):  # 1..100 inclusive
        v.append(UInt64(i))
    # Nearest-rank: p50 → ceil(0.50 * 100) = 50 → v[49] = 50
    assert_true(_exact_percentile(v, 50.0) == UInt64(50), "p50 of 1..100 = 50")
    # p90 → ceil(0.90 * 100) = 90 → v[89] = 90
    assert_true(_exact_percentile(v, 90.0) == UInt64(90), "p90 of 1..100 = 90")
    # p99 → ceil(0.99 * 100) = 99 → v[98] = 99
    assert_true(_exact_percentile(v, 99.0) == UInt64(99), "p99 of 1..100 = 99")
    # p100 → ceil(1.0 * 100) = 100 → v[99] = 100
    assert_true(_exact_percentile(v, 100.0) == UInt64(100), "p100 of 1..100 = 100")
    print("PASS: test_exact_percentile_basic")


def test_exact_percentile_empty_returns_zero() raises:
    from src.quic.profile import _exact_percentile
    var v = List[UInt64]()
    assert_true(_exact_percentile(v, 50.0) == UInt64(0), "empty → 0")
    print("PASS: test_exact_percentile_empty_returns_zero")


def test_exact_percentile_unsorted_input() raises:
    from src.quic.profile import _exact_percentile
    var v = List[UInt64]()
    v.append(UInt64(50))
    v.append(UInt64(10))
    v.append(UInt64(30))
    v.append(UInt64(40))
    v.append(UInt64(20))
    # After sort: [10, 20, 30, 40, 50]; p50 → ceil(2.5) = 3 → v[2] = 30
    assert_true(_exact_percentile(v, 50.0) == UInt64(30), "p50 of [50,10,30,40,20] = 30")
    print("PASS: test_exact_percentile_unsorted_input")


def test_bucket_percentile_uniform() raises:
    """Uniform [1us, 1ms): p50 ≈ 500us, p90 ≈ 900us, p99 ≈ 990us, ±25%."""
    from src.quic.profile import AcceptProfile, _bucket_percentile
    var p = AcceptProfile()
    # 10000 samples uniform [1us, 1_000_000ns = 1000us).
    # Use deterministic LCG for reproducibility.
    var seed: UInt64 = UInt64(0xdeadbeef)
    for _ in range(10000):
        seed = seed * UInt64(6364136223846793005) + UInt64(1442695040888963407)
        var us = UInt64(1) + (seed % UInt64(999))  # [1, 1000)
        p.record_pkt(
            total_us=us,
            ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
            header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
        )
    var p50 = _bucket_percentile(p.per_pkt_total_buckets, p.pkt_count - p.per_pkt_total_overflow, 50.0)
    var p90 = _bucket_percentile(p.per_pkt_total_buckets, p.pkt_count - p.per_pkt_total_overflow, 90.0)
    var p99 = _bucket_percentile(p.per_pkt_total_buckets, p.pkt_count - p.per_pkt_total_overflow, 99.0)
    # ±25% tolerance.
    assert_true(p50 >= UInt64(375) and p50 <= UInt64(625), "p50 in [375, 625]")
    assert_true(p90 >= UInt64(675) and p90 <= UInt64(1125), "p90 in [675, 1125]")
    assert_true(p99 >= UInt64(742) and p99 <= UInt64(1238), "p99 in [742, 1238]")
    print("PASS: test_bucket_percentile_uniform")


def test_bucket_percentile_overflow() raises:
    """999 samples at 100us + 1 over the 2^23us cutoff. p99.99 → overflow lower bound."""
    from src.quic.profile import AcceptProfile, _bucket_percentile
    var p = AcceptProfile()
    for _ in range(999):
        p.record_pkt(
            total_us=UInt64(100),
            ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
            header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
        )
    # Overflow boundary is 2^23 = 8_388_608us (~8.39s); use 10s to ensure overflow.
    p.record_pkt(
        total_us=UInt64(10_000_000),
        ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
        header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
    )
    assert_true(p.per_pkt_total_overflow == UInt64(1), "1 overflow sample")
    # p50 over the 999 closed-bucket samples (excluding overflow) → 100us → bucket 7.
    var n_closed = p.pkt_count - p.per_pkt_total_overflow
    var p50 = _bucket_percentile(p.per_pkt_total_buckets, n_closed, 50.0)
    # 100us is in bucket 7 ([64, 128)). Linear interp inside → estimator returns ~64..128.
    assert_true(p50 >= UInt64(64) and p50 < UInt64(128), "p50 in bucket 7 range")
    print("PASS: test_bucket_percentile_overflow")


def test_report_text_canned() raises:
    """Construct a canned profile, format, assert the report contains key markers.

    Exact-string golden match is brittle (timestamps / minor format drift).
    We assert on stable content markers + numeric values.
    """
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Idle / busy.
    p.record_idle(UInt64(31_830_000))
    p.record_flush(1, UInt64(2_380_000))  # one wakeup with 2.38s busy
    # Per-packet: one canned packet.
    p.record_pkt(
        total_us=UInt64(120),
        ffi_us=UInt64(78),
        hp_us=UInt64(12),
        aead_us=UInt64(22),
        header_parse_us=UInt64(6),
        frame_parse_us=UInt64(11),
        sm_us=UInt64(14),
    )
    p.record_drain(UInt64(39))
    # Handshake.
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))
    p.record_handshake_timeout(UInt64(1))

    var s = p.report_text()

    # Header.
    assert_true("=== mojo-net QUIC accept-loop profile ===" in s, "header present")
    assert_true("=== end ===" in s, "footer present")
    # Idle / busy section.
    assert_true("On_flush events:" in s, "on_flush events line")
    assert_true("Idle (boucle wait):" in s, "idle line")
    assert_true("Busy (in loop):" in s, "busy line")
    # Fan-out histogram header + bucket label.
    assert_true("Datagrams batched per flush" in s, "fan-out header")
    assert_true("size=1" in s, "size=1 label")
    assert_true("size=128+" in s, "size=128+ label")
    # Per-packet section.
    assert_true("Per-packet wall-clock" in s, "per-packet header")
    assert_true("header parse" in s, "header parse leg")
    assert_true("HP unprotect" in s, "HP leg")
    assert_true("AEAD decrypt" in s, "AEAD leg")
    assert_true("frame parse" in s, "frame_parse leg")
    assert_true("state machine" in s, "sm leg")
    assert_true("residual" in s, "residual leg")
    assert_true("shim FFI" in s, "shim FFI leg")
    assert_true("drain (bench)" in s, "drain leg")
    # Handshake section.
    assert_true("Handshake accounting:" in s, "handshake header")
    assert_true("Arrivals:" in s, "arrivals row")
    assert_true("Successful:" in s, "successful row")
    assert_true("Timed out:" in s, "timed-out row")
    # Latency section.
    assert_true("Successful handshake latency" in s, "latency header")
    # Numeric checks: avg = total / count, so for a single packet with ffi=78
    # avg should print as "avg= 78".
    assert_true("avg= 78" in s, "shim FFI avg=78 (single sample)")
    print("PASS: test_report_text_canned")


def main() raises:
    test_monotonic_us_increases()
    test_profile_accept_is_bool()
    test_default_init()
    test_record_idle_accumulates()
    test_record_flush_buckets_and_sums()
    test_per_pkt_bucket_assignment()
    test_record_pkt_sums_and_residual()
    test_record_pkt_overflow()
    test_record_pkt_residual_underflow_safe()
    test_record_drain_accumulates()
    test_handshake_records()
    test_exact_percentile_basic()
    test_exact_percentile_empty_returns_zero()
    test_exact_percentile_unsorted_input()
    test_bucket_percentile_uniform()
    test_bucket_percentile_overflow()
    test_report_text_canned()
    print("All Plan A tests passed.")
