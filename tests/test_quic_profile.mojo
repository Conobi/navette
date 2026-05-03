# tests/test_quic_profile.mojo
#
# Unit tests for src/quic/profile.mojo (Plan A).

from src.quic.profile import PROFILE_ACCEPT, monotonic_us
from testing import assert_true
from tests._test_util import assert_equal_int


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


def test_report_json_canned() raises:
    """Verify JSON contains all required keys with the right values."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_idle(UInt64(1000))
    p.record_flush(1, UInt64(500))
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
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))

    var j = p.report_json()

    # Top-level keys.
    assert_true('"schema_version": 1' in j, "schema_version=1")
    assert_true('"run_wall_clock_us":' in j, "run_wall_clock_us key")
    assert_true('"on_flush_events": 1' in j, "on_flush_events=1")
    assert_true('"idle_us_total": 1000' in j, "idle_us_total=1000")
    assert_true('"busy_us_total": 500' in j, "busy_us_total=500")
    # Histogram keys.
    assert_true('"pkts_per_flush_histogram":' in j, "fan-out histogram key")
    assert_true('"1": 1' in j, '"1" bucket = 1')
    assert_true('"128+": 0' in j, '"128+" bucket = 0')
    # Per-packet section.
    assert_true('"per_pkt_us":' in j, "per_pkt_us key")
    assert_true('"total":' in j, "total subkey")
    assert_true('"header_parse":' in j, "header_parse subkey")
    assert_true('"hp":' in j, "hp subkey")
    assert_true('"aead":' in j, "aead subkey")
    assert_true('"frame_parse":' in j, "frame_parse subkey")
    assert_true('"sm":' in j, "sm subkey")
    assert_true('"residual":' in j, "residual subkey")
    assert_true('"shim_ffi":' in j, "shim_ffi subkey")
    assert_true('"drain":' in j, "drain subkey")
    assert_true('"avg": 78' in j, "shim_ffi avg=78")
    # Handshake section.
    assert_true('"handshake":' in j, "handshake key")
    assert_true('"arrivals": 1' in j, "arrivals=1")
    assert_true('"successful": 1' in j, "successful=1")
    assert_true('"timed_out": 0' in j, "timed_out=0")
    assert_true('"latency_us":' in j, "latency_us subkey")
    print("PASS: test_report_json_canned")


def test_record_arrival_lat_buckets() raises:
    """Verify record_arrival_lat dispatches into 24-bucket histogram and accumulates total."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Cover several bucket boundaries (mirrors _per_pkt_bucket: bucket[0]={0}; bucket[i]=[2^(i-1), 2^i)).
    p.record_arrival_lat(UInt64(0))           # bucket 0
    p.record_arrival_lat(UInt64(1))           # bucket 1
    p.record_arrival_lat(UInt64(3))           # bucket 2
    p.record_arrival_lat(UInt64(100))         # bucket 7 ([64, 128))
    p.record_arrival_lat(UInt64(1_000_000))   # bucket 20 ([524288, 1048576))
    assert_true(p.arrival_lat_us_buckets[0] == UInt64(1), "bucket 0 = 1")
    assert_true(p.arrival_lat_us_buckets[1] == UInt64(1), "bucket 1 = 1")
    assert_true(p.arrival_lat_us_buckets[2] == UInt64(1), "bucket 2 = 1")
    assert_true(p.arrival_lat_us_buckets[7] == UInt64(1), "bucket 7 = 1")
    assert_true(p.arrival_lat_us_buckets[20] == UInt64(1), "bucket 20 = 1")
    assert_true(p.arrival_lat_us_total == UInt64(0 + 1 + 3 + 100 + 1_000_000), "total summed")
    assert_true(p.arrival_lat_us_overflow == UInt64(0), "no overflow")
    print("PASS: test_record_arrival_lat_buckets")


def test_record_arrival_lat_overflow() raises:
    """Verify values >= 2^23 us land in arrival_lat_us_overflow."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(8_388_608))   # 2^23 — overflow boundary
    p.record_arrival_lat(UInt64(10_000_000))  # > 2^23 — overflow
    assert_true(p.arrival_lat_us_overflow == UInt64(2), "overflow = 2")
    assert_true(p.arrival_lat_us_total == UInt64(8_388_608 + 10_000_000), "overflow values still summed in total")
    var sum_buckets: UInt64 = UInt64(0)
    for i in range(24):
        sum_buckets += p.arrival_lat_us_buckets[i]
    assert_true(sum_buckets == UInt64(0), "no closed bucket entries")
    print("PASS: test_record_arrival_lat_overflow")


def test_record_conn_pkt_increment() raises:
    """Verify record_conn_pkt increments addr_key counter."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("1.2.3.4:5000"))
    p.record_conn_pkt(String("9.9.9.9:6000"))
    assert_true(p.conn_pkt_counts[String("1.2.3.4:5000")] == UInt64(3), "addr1 = 3")
    assert_true(p.conn_pkt_counts[String("9.9.9.9:6000")] == UInt64(1), "addr2 = 1")
    assert_true(len(p.conn_pkt_counts) == 2, "two distinct keys")
    print("PASS: test_record_conn_pkt_increment")


def test_record_conn_hs_complete_idempotent() raises:
    """Verify record_conn_hs_complete dedupes and the no-complete scalar excludes it."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Conn A: 5 packets, completes handshake.
    for _ in range(5):
        p.record_conn_pkt(String("A:1"))
    p.record_conn_hs_complete(String("A:1"))
    p.record_conn_hs_complete(String("A:1"))   # idempotent
    p.record_conn_hs_complete(String("A:1"))
    # Conn B: 3 packets, never completes.
    for _ in range(3):
        p.record_conn_pkt(String("B:2"))
    # Conn C: 1 packet, never completes.
    p.record_conn_pkt(String("C:3"))
    assert_true(len(p.conn_hs_complete) == 1, "only A:1 in hs_complete")
    assert_true(p.conn_hs_complete[String("A:1")] == True, "A:1 marked True")
    # Compute scalar manually for now — formal API in Task 4.
    var no_hs: UInt64 = UInt64(0)
    for entry in p.conn_pkt_counts.items():
        if entry.key not in p.conn_hs_complete:
            no_hs += UInt64(1)
    assert_true(no_hs == UInt64(2), "B and C are no-hs-complete")
    print("PASS: test_record_conn_hs_complete_idempotent")


def test_report_json_arrival_latency_block() raises:
    """Verify report_json emits the arrival-latency block with correct keys + values."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(50))         # bucket 6 ([32, 64))
    p.record_arrival_lat(UInt64(50))         # bucket 6
    p.record_arrival_lat(UInt64(2_000_000))  # bucket 21 ([1048576, 2097152))
    p.record_arrival_lat(UInt64(20_000_000)) # overflow
    var j = p.report_json()
    assert_true('"arrival_lat_us_total":' in j, "arrival_lat_us_total key present")
    assert_true('"arrival_lat_us_buckets":' in j, "arrival_lat_us_buckets key present")
    assert_true('"arrival_lat_us_overflow":' in j, "arrival_lat_us_overflow key present")
    var expected_total = UInt64(50 + 50 + 2_000_000 + 20_000_000)
    assert_true(String('"arrival_lat_us_total": ') + String(expected_total) in j, "total value matches")
    assert_true('"arrival_lat_us_overflow": 1' in j, "overflow = 1")
    print("PASS: test_report_json_arrival_latency_block")


def test_report_json_per_conn_aggregated_block() raises:
    """Populate dict with conns of varying counts; verify 8-bucket histogram totals match."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Bucket 0 (size=1): 5 conns
    for i in range(5):
        p.record_conn_pkt(String("b0_") + String(i))
    # Bucket 1 (size=2-3): 4 conns x 2 packets each
    for i in range(4):
        var k = String("b1_") + String(i)
        p.record_conn_pkt(k)
        p.record_conn_pkt(k)
    # Bucket 2 (size=4-7): 3 conns x 5 packets each
    for i in range(3):
        var k = String("b2_") + String(i)
        for _ in range(5):
            p.record_conn_pkt(k)
    # Bucket 3 (size=8-15): 2 conns x 10 packets each
    for i in range(2):
        var k = String("b3_") + String(i)
        for _ in range(10):
            p.record_conn_pkt(k)
    # Mark some hs_complete: 2 from bucket 0, 1 from bucket 2
    p.record_conn_hs_complete(String("b0_0"))
    p.record_conn_hs_complete(String("b0_1"))
    p.record_conn_hs_complete(String("b2_0"))

    var j = p.report_json()
    assert_true('"per_conn_pkts_buckets":' in j, "per_conn_pkts_buckets key present")
    assert_true('"conns_total": 14' in j, "conns_total = 5+4+3+2 = 14")
    # 14 total, 3 hs_complete -> 11 without hs_complete
    assert_true('"conns_with_pkts_no_hs_complete": 11' in j, "no-hs scalar = 11")
    # Histogram totals: bucket[0]=5, bucket[1]=4, bucket[2]=3, bucket[3]=2, others=0
    assert_true('"per_conn_pkts_buckets": [5, 4, 3, 2, 0, 0, 0, 0]' in j, "8-bucket histogram matches")
    print("PASS: test_report_json_per_conn_aggregated_block")


def test_report_json_worst_conns() raises:
    """Populate 100 non-complete conns + 20 complete; verify top-50 sorted descending and capped."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # 100 non-complete conns: pkt_count = i+1 (1..100)
    for i in range(100):
        var k = String("nc_") + String(i)
        for _ in range(i + 1):
            p.record_conn_pkt(k)
    # 20 complete conns with very high counts (200+) — must be excluded from top-50
    for i in range(20):
        var k = String("c_") + String(i)
        for _ in range(200 + i):
            p.record_conn_pkt(k)
        p.record_conn_hs_complete(k)
    var j = p.report_json()
    assert_true('"worst_conns":' in j, "worst_conns key present")
    # Top entry must be nc_99 (100 packets, not complete)
    assert_true('"addr_key": "nc_99"' in j, "top offender is nc_99")
    assert_true('"pkt_count": 100' in j, "top pkt_count = 100")
    # No complete conn should appear
    assert_true('"addr_key": "c_19"' not in j, "complete conn excluded")
    # Verify cap at 50: count occurrences of '"addr_key":' — exactly 50
    var n_entries = 0
    var idx = 0
    var search = String('"addr_key":')
    var search_b = search.as_bytes()
    var j_b = j.as_bytes()
    while idx < len(j_b) - len(search_b):
        var matched = True
        for k in range(len(search_b)):
            if j_b[idx + k] != search_b[k]:
                matched = False
                break
        if matched:
            n_entries += 1
            idx += len(search_b)
        else:
            idx += 1
    assert_true(n_entries == 50, "exactly 50 worst_conns entries (cap)")
    print("PASS: test_report_json_worst_conns")


def test_report_text_new_sections() raises:
    """Verify report_text emits human-readable sections for the three new blocks."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(150))
    p.record_arrival_lat(UInt64(2_000_000))
    p.record_conn_pkt(String("X:1"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_pkt(String("Y:2"))
    p.record_conn_hs_complete(String("X:1"))
    var t = p.report_text()
    assert_true("Arrival-to-processing latency" in t, "arrival-lat section header")
    assert_true("Per-connection packet counts" in t, "per-conn section header")
    assert_true("Worst offenders" in t, "worst-offenders section header")
    # Sanity: Y:2 is not complete and has 3 packets — must surface in worst offenders
    assert_true("Y:2" in t, "non-complete addr_key surfaces in worst offenders")
    print("PASS: test_report_text_new_sections")


def test_record_dcid_mismatch_increments() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    if p.dcid_mismatch_pkts != UInt64(1):
        raise "expected dcid_mismatch_pkts=1, got " + String(p.dcid_mismatch_pkts)
    if p.addr_key_mismatch_counts[String("ip:port:34130")] != UInt64(1):
        raise "expected per-addr_key count=1"
    print("PASS: test_record_dcid_mismatch_increments")


def test_record_dcid_mismatch_accumulates() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34131"))
    if p.dcid_mismatch_pkts != UInt64(3):
        raise "expected total=3, got " + String(p.dcid_mismatch_pkts)
    if p.addr_key_mismatch_counts[String("ip:port:34130")] != UInt64(2):
        raise "expected key1=2"
    if p.addr_key_mismatch_counts[String("ip:port:34131")] != UInt64(1):
        raise "expected key2=1"
    print("PASS: test_record_dcid_mismatch_accumulates")


def test_report_json_dcid_mismatch_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34130"))
    p.record_dcid_mismatch(String("ip:port:34131"))
    var s = p.report_json()
    if "addr_key_dcid_mismatch" not in s:
        raise "missing addr_key_dcid_mismatch block"
    if "\"dcid_mismatch_pkts\": 3" not in s:
        raise "missing total counter"
    if "\"addr_keys_with_mismatch\": 2" not in s:
        raise "missing addr_keys_with_mismatch"
    if "ip:port:34130" not in s:
        raise "missing per_addr_key entry"
    print("PASS: test_report_json_dcid_mismatch_block")


def test_report_text_dcid_mismatch_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_dcid_mismatch(String("ip:port:34130"))
    var s = p.report_text()
    if "addr_key DCID mismatch" not in s:
        raise "missing text section heading"
    if "1" not in s:
        raise "expected count=1 to appear"
    print("PASS: test_report_text_dcid_mismatch_block")


def test_record_ffi_read_hs_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_read_hs(UInt64(150))
    p.record_ffi_read_hs(UInt64(50))
    if p.ffi_read_hs_us_total != UInt64(300):
        raise "expected ffi_read_hs_us_total=300, got " + String(p.ffi_read_hs_us_total)
    print("PASS: test_record_ffi_read_hs_increments_total")


def test_record_ffi_write_hs_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_write_hs(UInt64(300))
    if p.ffi_write_hs_us_total != UInt64(500):
        raise "expected ffi_write_hs_us_total=500, got " + String(p.ffi_write_hs_us_total)
    print("PASS: test_record_ffi_write_hs_increments_total")


def test_record_ffi_take_keys_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_take_keys(UInt64(40))
    p.record_ffi_take_keys(UInt64(60))
    if p.ffi_take_keys_us_total != UInt64(100):
        raise "expected ffi_take_keys_us_total=100, got " + String(p.ffi_take_keys_us_total)
    print("PASS: test_record_ffi_take_keys_increments_total")


def test_record_loop_pop_dispatch_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(50))
    p.record_loop_pop_dispatch(UInt64(75))
    if p.loop_pop_dispatch_us_total != UInt64(125):
        raise "expected loop_pop_dispatch_us_total=125, got " + String(p.loop_pop_dispatch_us_total)
    print("PASS: test_record_loop_pop_dispatch_increments_total")


def test_record_loop_post_pkt_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_post_pkt(UInt64(20))
    p.record_loop_post_pkt(UInt64(30))
    if p.loop_post_pkt_us_total != UInt64(50):
        raise "expected loop_post_pkt_us_total=50, got " + String(p.loop_post_pkt_us_total)
    print("PASS: test_record_loop_post_pkt_increments_total")


def test_record_loop_teardown_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_teardown(UInt64(8))
    p.record_loop_teardown(UInt64(12))
    if p.loop_teardown_us_total != UInt64(20):
        raise "expected loop_teardown_us_total=20, got " + String(p.loop_teardown_us_total)
    print("PASS: test_record_loop_teardown_increments_total")


def test_ffi_subleg_sum_matches_shim_ffi_within_tolerance() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Simulate 3 FFI calls within one pkt accumulating into shim_ffi via record_pkt.
    # Then directly populate sub-legs with the same per-call deltas.
    p.record_pkt(
        total_us=UInt64(120),
        ffi_us=UInt64(100),     # 30 + 50 + 20 = 100
        hp_us=UInt64(1),
        aead_us=UInt64(1),
        header_parse_us=UInt64(1),
        frame_parse_us=UInt64(5),
        sm_us=UInt64(60),
    )
    p.record_ffi_read_hs(UInt64(30))
    p.record_ffi_write_hs(UInt64(50))
    p.record_ffi_take_keys(UInt64(20))
    var subleg_sum = p.ffi_read_hs_us_total + p.ffi_write_hs_us_total + p.ffi_take_keys_us_total
    var diff: UInt64
    if subleg_sum >= p.ffi_shim_us_total:
        diff = subleg_sum - p.ffi_shim_us_total
    else:
        diff = p.ffi_shim_us_total - subleg_sum
    var tol = p.ffi_shim_us_total // UInt64(100)
    if tol < UInt64(1):
        tol = UInt64(1)
    if diff > tol:
        raise "ffi_subleg sum (" + String(subleg_sum) + ") differs from shim_ffi (" + String(p.ffi_shim_us_total) + ") by more than 1%"
    print("PASS: test_ffi_subleg_sum_matches_shim_ffi_within_tolerance")


def test_loop_budget_closure_zero_residual() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # busy = 1000us = 200 (per_pkt total) + 100 (drain) + 400 (pop_dispatch) + 200 (post_pkt) + 100 (teardown)
    p.busy_us_total = UInt64(1000)
    p.record_pkt(
        total_us=UInt64(200),
        ffi_us=UInt64(0),
        hp_us=UInt64(0),
        aead_us=UInt64(0),
        header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0),
        sm_us=UInt64(200),
    )
    p.record_drain(UInt64(100))
    p.record_loop_pop_dispatch(UInt64(400))
    p.record_loop_post_pkt(UInt64(200))
    p.record_loop_teardown(UInt64(100))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 0" not in s:
        raise "expected unaccounted_us_total=0; got snippet: " + s
    if "\"unaccounted_pct\": 0" not in s:
        raise "expected unaccounted_pct=0; got snippet: " + s
    print("PASS: test_loop_budget_closure_zero_residual")


def test_loop_budget_closure_nonzero_residual() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # busy = 10000us; sum of legs = 9900us; residual = 100us = 1% (integer-truncated).
    p.busy_us_total = UInt64(10000)
    p.record_pkt(
        total_us=UInt64(2000),
        ffi_us=UInt64(0),
        hp_us=UInt64(0),
        aead_us=UInt64(0),
        header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0),
        sm_us=UInt64(2000),
    )
    p.record_drain(UInt64(1000))
    p.record_loop_pop_dispatch(UInt64(4000))
    p.record_loop_post_pkt(UInt64(2000))
    p.record_loop_teardown(UInt64(900))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 100" not in s:
        raise "expected unaccounted_us_total=100; got snippet: " + s
    if "\"unaccounted_pct\": 1" not in s:
        raise "expected unaccounted_pct=1; got snippet: " + s
    print("PASS: test_loop_budget_closure_nonzero_residual")


def test_report_json_emits_ffi_subleg_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_take_keys(UInt64(50))
    var s = p.report_json()
    if "\"ffi_subleg_us\"" not in s:
        raise "missing ffi_subleg_us block"
    if "\"read_hs\"" not in s:
        raise "missing read_hs key"
    if "\"write_hs\"" not in s:
        raise "missing write_hs key"
    if "\"take_keys\"" not in s:
        raise "missing take_keys key"
    if "\"total\": 100" not in s:
        raise "missing read_hs total=100"
    if "\"total\": 200" not in s:
        raise "missing write_hs total=200"
    print("PASS: test_report_json_emits_ffi_subleg_block")


def test_report_json_emits_loop_phases_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(150))
    p.record_loop_post_pkt(UInt64(50))
    p.record_loop_teardown(UInt64(20))
    p.record_loop_iter()
    p.record_loop_iter()
    var s = p.report_json()
    if "\"loop_phases_us\"" not in s:
        raise "missing loop_phases_us block"
    if "\"pop_dispatch\"" not in s:
        raise "missing pop_dispatch key"
    if "\"post_pkt\"" not in s:
        raise "missing post_pkt key"
    if "\"teardown\"" not in s:
        raise "missing teardown key"
    if "\"loop_iter_count\": 2" not in s:
        raise "missing loop_iter_count=2"
    if "\"unaccounted_us_total\"" not in s:
        raise "missing unaccounted_us_total key"
    if "\"unaccounted_pct\"" not in s:
        raise "missing unaccounted_pct key"
    print("PASS: test_report_json_emits_loop_phases_block")


def test_loop_phase_avg_uses_loop_iter_count_divisor() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # 100 iters, 50 pkts (some continue'd). pop_dispatch total = 10000 us.
    # Expected avg = 10000 / 100 = 100 (NOT 10000 / 50 = 200).
    p.record_loop_pop_dispatch(UInt64(10000))
    for _ in range(100):
        p.record_loop_iter()
    # Synthetically populate pkt_count = 50 to ensure divisor is loop_iter_count.
    p.pkt_count = UInt64(50)
    var s = p.report_json()
    # Look for the pop_dispatch.avg = 100 (not 200).
    if "\"pop_dispatch\": {\"avg\": 100" not in s:
        raise "expected pop_dispatch.avg=100 (loop_iter_count divisor); got snippet: " + s
    print("PASS: test_loop_phase_avg_uses_loop_iter_count_divisor")


def test_record_h3_drain_resp_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(123))
    p.record_h3_drain_resp(UInt64(456))
    assert_equal_int(Int(p.h3_drain_resp_us_total), 579, "h3_drain_resp accumulates")
    print("PASS: test_record_h3_drain_resp_increments_total")


def test_record_quic_post_recv_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_quic_post_recv(UInt64(100))
    p.record_quic_post_recv(UInt64(200))
    assert_equal_int(Int(p.quic_post_recv_us_total), 300, "quic_post_recv accumulates")
    print("PASS: test_record_quic_post_recv_increments_total")


def test_record_h3_dispatch_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_h3_dispatch(UInt64(50))
    p.record_h3_dispatch(UInt64(75))
    assert_equal_int(Int(p.h3_dispatch_us_total), 125, "h3_dispatch accumulates")
    print("PASS: test_record_h3_dispatch_increments_total")


def test_report_json_emits_h3_phases_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(1000))
    p.record_quic_post_recv(UInt64(2000))
    p.record_h3_dispatch(UInt64(3000))
    var out = p.report_json()
    # Spot-check: the h3_phases_us block must appear with 3 named keys.
    assert_true('"h3_phases_us":' in out, "h3_phases_us block missing")
    assert_true('"drain_resp":' in out, "drain_resp key missing")
    assert_true('"post_recv":' in out, "post_recv key missing")
    assert_true('"dispatch":' in out, "dispatch key missing")
    assert_true('"total": 1000' in out, "drain_resp total missing")
    assert_true('"total": 2000' in out, "post_recv total missing")
    assert_true('"total": 3000' in out, "dispatch total missing")
    print("PASS: test_report_json_emits_h3_phases_block")


def test_h3_phase_legs_sum_within_unaccounted_bucket() raises:
    """Synthetic profile: 3 H3 legs cumulatively are bounded by the
    pre-existing unaccounted bucket. Catches bracket overlap (a future
    bug where two brackets time the same code path)."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Synthetic busy with known leg shapes:
    #   busy = 1000
    #   per_pkt = 200 (split equally across 6 legs)
    #   drain = 100
    #   loop = 100 (across 3 loop legs)
    #   ε bucket = busy - per_pkt - drain - loop = 600
    p.busy_us_total = UInt64(1000)
    p.header_parse_us_total = UInt64(33)
    p.hp_us_total = UInt64(33)
    p.aead_us_total = UInt64(33)
    p.frame_parse_us_total = UInt64(34)
    p.sm_us_total = UInt64(33)
    p.residual_us_total = UInt64(34)
    p.drain_us_total = UInt64(100)
    p.loop_pop_dispatch_us_total = UInt64(34)
    p.loop_post_pkt_us_total = UInt64(33)
    p.loop_teardown_us_total = UInt64(33)
    # Now introduce 3 H3 legs cumulatively summing to 500 (< 600 unacct bucket).
    p.record_h3_drain_resp(UInt64(300))
    p.record_quic_post_recv(UInt64(150))
    p.record_h3_dispatch(UInt64(50))
    var per_pkt = (p.header_parse_us_total + p.hp_us_total + p.aead_us_total
        + p.frame_parse_us_total + p.sm_us_total + p.residual_us_total)
    var loop_phases = (p.loop_pop_dispatch_us_total + p.loop_post_pkt_us_total + p.loop_teardown_us_total)
    var pre_h3_unacct = p.busy_us_total - per_pkt - p.drain_us_total - loop_phases
    var h3_sum = p.h3_drain_resp_us_total + p.quic_post_recv_us_total + p.h3_dispatch_us_total
    assert_true(h3_sum <= pre_h3_unacct, "h3 legs must fit within pre-h3 unaccounted bucket")
    print("PASS: test_h3_phase_legs_sum_within_unaccounted_bucket")


def test_budget_closure_subtracts_h3_legs() raises:
    """Synthetic profile with all leg types populated. Budget-closure ε must
    subtract h3 legs in addition to per_pkt + drain + loop."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.busy_us_total = UInt64(1000)
    p.header_parse_us_total = UInt64(50)
    p.hp_us_total = UInt64(50)
    p.aead_us_total = UInt64(50)
    p.frame_parse_us_total = UInt64(50)
    p.sm_us_total = UInt64(50)
    p.residual_us_total = UInt64(50)   # per_pkt sum = 300
    p.drain_us_total = UInt64(100)
    p.loop_pop_dispatch_us_total = UInt64(50)
    p.loop_post_pkt_us_total = UInt64(50)
    p.loop_teardown_us_total = UInt64(50)  # loop sum = 150
    p.record_h3_drain_resp(UInt64(200))
    p.record_quic_post_recv(UInt64(100))
    p.record_h3_dispatch(UInt64(50))   # h3 sum = 350

    var out = p.report_json()
    # Expected unaccounted = 1000 - 300 - 100 - 150 - 350 = 100
    assert_true('"unaccounted_us_total": 100,' in out, "unaccounted_us_total should be 100")
    # Expected unaccounted_pct = 100 / 1000 * 100 = 10
    assert_true('"unaccounted_pct": 10' in out, "unaccounted_pct should be 10")
    print("PASS: test_budget_closure_subtracts_h3_legs")


def test_record_drain_stream_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(123))
    p.record_drain_stream(UInt64(456))
    assert_equal_int(Int(p.drain_stream_us_total), 579, "drain_stream accumulates")
    print("PASS: test_record_drain_stream_increments_total")


def test_record_drain_recv_ffi_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_recv_ffi(UInt64(200))
    assert_equal_int(Int(p.drain_recv_ffi_us_total), 300, "drain_recv_ffi accumulates")
    print("PASS: test_record_drain_recv_ffi_increments_total")


def test_record_drain_buf_accumulate_increments_total() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    # Verify accumulation across multiple calls (B3a + B3b both call this method).
    p.record_drain_buf_accumulate(UInt64(11))
    p.record_drain_buf_accumulate(UInt64(22))
    p.record_drain_buf_accumulate(UInt64(33))
    assert_equal_int(Int(p.drain_buf_accumulate_us_total), 66,
        "drain_buf_accumulate accumulates across calls (B3a + B3b summed)")
    print("PASS: test_record_drain_buf_accumulate_increments_total")


def test_record_drain_frame_parse_and_qpack_decode_independent() raises:
    """Both methods on a fresh AcceptProfile target separate fields.
    Catches a future bug where frame_parse and qpack_decode aliased the same field."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_frame_parse(UInt64(50))
    p.record_drain_qpack_decode(UInt64(75))
    assert_equal_int(Int(p.drain_frame_parse_us_total), 50, "frame_parse field independent")
    assert_equal_int(Int(p.drain_qpack_decode_us_total), 75, "qpack_decode field independent")
    # Cross-check: each call did NOT touch the other field.
    p.record_drain_frame_parse(UInt64(10))
    assert_equal_int(Int(p.drain_qpack_decode_us_total), 75,
        "qpack_decode unchanged after second frame_parse call")
    print("PASS: test_record_drain_frame_parse_and_qpack_decode_independent")


def test_report_json_emits_drain_stream_subleg_block() raises:
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(10000))
    p.record_drain_recv_ffi(UInt64(1000))
    p.record_drain_buf_accumulate(UInt64(2000))
    p.record_drain_frame_parse(UInt64(500))
    p.record_drain_qpack_decode(UInt64(300))
    var out = p.report_json()
    # Spot-check: drain_stream_subleg block exists with all 8 keys.
    assert_true('"drain_stream_subleg":' in out, "drain_stream_subleg block missing")
    assert_true('"drain_stream_us_total":' in out, "drain_stream_us_total key missing")
    assert_true('"recv_ffi_us":' in out, "recv_ffi_us key missing")
    assert_true('"buf_accumulate_us":' in out, "buf_accumulate_us key missing")
    assert_true('"frame_parse_us":' in out, "frame_parse_us key missing")
    assert_true('"qpack_decode_us":' in out, "qpack_decode_us key missing")
    assert_true('"event_dispatch_us":' in out, "event_dispatch_us key missing")
    assert_true('"sum_legs_us":' in out, "sum_legs_us key missing")
    assert_true('"unaccounted_pct":' in out, "unaccounted_pct key missing")
    # Numeric spot-checks for raw fields.
    assert_true('"drain_stream_us_total": 10000' in out, "drain_stream value")
    assert_true('"recv_ffi_us": 1000' in out, "recv_ffi value")
    # Residual = 10000 - (1000+2000+500+300) = 6200.
    assert_true('"event_dispatch_us": 6200' in out, "event_dispatch residual=6200")
    # sum_legs = 1000+2000+500+300+6200 = 10000.
    assert_true('"sum_legs_us": 10000' in out, "sum_legs=10000")
    print("PASS: test_report_json_emits_drain_stream_subleg_block")


def test_drain_subleg_sum_invariant_residual() raises:
    """Synthetic profile: sum of measured legs <= parent; residual fills the gap."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    # Sum of measured legs = 800; total = 1000; residual = 200.
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 200, "event_dispatch residual = total - sum_legs = 200")
    var out = p.report_json()
    assert_true('"event_dispatch_us": 200' in out, "JSON event_dispatch=200")
    # sum_legs (with derived event_dispatch) == total exactly.
    assert_true('"sum_legs_us": 1000' in out, "sum_legs (with derived) = 1000")
    # unaccounted_pct after residual = 0.
    assert_true('"unaccounted_pct": 0' in out, "unaccounted_pct=0 (closed)")
    print("PASS: test_drain_subleg_sum_invariant_residual")


def test_drain_subleg_residual_clamp_overshoot() raises:
    """Synthetic profile: sum of measured legs > parent. Clamp residual to 0.
    Guards against UInt64 underflow-wrap regression (would surface as a huge
    spurious event_dispatch_us)."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(400))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    # Sum of measured legs = 1100; total = 1000 -> overshoot by 100.
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 0, "event_dispatch clamped to 0 on overshoot")
    var out_json = p.report_json()
    assert_true('"event_dispatch_us": 0' in out_json, "JSON event_dispatch=0 (clamped)")
    var out_text = p.report_text()
    assert_true("event_dispatch.derived: 0" in out_text, "text event_dispatch=0 (clamped)")
    print("PASS: test_drain_subleg_residual_clamp_overshoot")


def test_record_handshakes_full_resumed_increment() raises:
    """Verify handshakes_full and handshakes_resumed are independent counters."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    assert_true(p.handshakes_full_total == UInt64(0), "handshakes_full_total starts at 0")
    assert_true(p.handshakes_resumed_total == UInt64(0), "handshakes_resumed_total starts at 0")

    p.record_handshake_full()
    p.record_handshake_full()
    p.record_handshake_resumed()
    p.record_handshake_full()

    assert_true(p.handshakes_full_total == UInt64(3), "handshakes_full_total = 3")
    assert_true(p.handshakes_resumed_total == UInt64(1), "handshakes_resumed_total = 1")
    print("PASS: test_record_handshakes_full_resumed_increment")


def test_report_json_emits_handshakes_block() raises:
    """The JSON sidecar must include a `handshakes` key with full + resumed."""
    from src.quic.profile import AcceptProfile
    var p = AcceptProfile()
    p.record_handshake_full()
    p.record_handshake_resumed()
    p.record_handshake_resumed()

    var s = p.report_json()
    var i_handshakes = s.find('"handshakes"')
    assert_true(i_handshakes >= 0, '"handshakes" key present in JSON')
    var i_full = s.find('"full": 1', i_handshakes)
    assert_true(i_full >= 0, '"full": 1 present after "handshakes"')
    var i_resumed = s.find('"resumed": 2', i_handshakes)
    assert_true(i_resumed >= 0, '"resumed": 2 present after "handshakes"')
    print("PASS: test_report_json_emits_handshakes_block")


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
    test_report_json_canned()
    test_record_arrival_lat_buckets()
    test_record_arrival_lat_overflow()
    test_record_conn_pkt_increment()
    test_record_conn_hs_complete_idempotent()
    test_report_json_arrival_latency_block()
    test_report_json_per_conn_aggregated_block()
    test_report_json_worst_conns()
    test_report_text_new_sections()
    test_record_dcid_mismatch_increments()
    test_record_dcid_mismatch_accumulates()
    test_report_json_dcid_mismatch_block()
    test_report_text_dcid_mismatch_block()
    test_record_ffi_read_hs_increments_total()
    test_record_ffi_write_hs_increments_total()
    test_record_ffi_take_keys_increments_total()
    test_record_loop_pop_dispatch_increments_total()
    test_record_loop_post_pkt_increments_total()
    test_record_loop_teardown_increments_total()
    test_ffi_subleg_sum_matches_shim_ffi_within_tolerance()
    test_loop_budget_closure_zero_residual()
    test_loop_budget_closure_nonzero_residual()
    test_report_json_emits_ffi_subleg_block()
    test_report_json_emits_loop_phases_block()
    test_loop_phase_avg_uses_loop_iter_count_divisor()
    test_record_h3_drain_resp_increments_total()
    test_record_quic_post_recv_increments_total()
    test_record_h3_dispatch_increments_total()
    test_report_json_emits_h3_phases_block()
    test_h3_phase_legs_sum_within_unaccounted_bucket()
    test_budget_closure_subtracts_h3_legs()
    test_record_drain_stream_increments_total()
    test_record_drain_recv_ffi_increments_total()
    test_record_drain_buf_accumulate_increments_total()
    test_record_drain_frame_parse_and_qpack_decode_independent()
    test_report_json_emits_drain_stream_subleg_block()
    test_drain_subleg_sum_invariant_residual()
    test_drain_subleg_residual_clamp_overshoot()
    test_record_handshakes_full_resumed_increment()
    test_report_json_emits_handshakes_block()
    print("All Plan A tests passed.")
