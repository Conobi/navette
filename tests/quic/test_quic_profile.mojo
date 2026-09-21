# tests/test_quic_profile.mojo
#
# Unit tests for src/quic/profile.mojo (data-driven counter table).

from navette.quic.profile import (
    PROFILE_ACCEPT, AcceptProfile, CounterId, monotonic_us,
    _per_pkt_bucket, _exact_percentile, _bucket_percentile,
)
from std.testing import assert_true
from tests._test_util import assert_equal_int


def test_monotonic_us_increases() raises:
    var t0 = monotonic_us()
    var sink: UInt64 = 0
    for i in range(10000):
        sink = sink + UInt64(i)
    var t1 = monotonic_us()
    assert_true(t1 >= t0, "monotonic_us must be non-decreasing")
    assert_true(sink > 0, "sink used (defeat DCE)")
    print("PASS: test_monotonic_us_increases")


def test_profile_accept_is_bool() raises:
    comptime if PROFILE_ACCEPT:
        print("PROFILE_ACCEPT is True (on-build)")
    else:
        print("PROFILE_ACCEPT is False (off-build)")
    print("PASS: test_profile_accept_is_bool")


def test_default_init() raises:
    var p = AcceptProfile()
    assert_true(p.get(CounterId.IDLE_US_TOTAL) == UInt64(0), "idle_us_total starts at 0")
    assert_true(p.get(CounterId.BUSY_US_TOTAL) == UInt64(0), "busy_us_total starts at 0")
    assert_true(p.get(CounterId.ON_FLUSH_COUNT) == UInt64(0), "on_flush_count starts at 0")
    assert_true(p.get(CounterId.PKT_COUNT) == UInt64(0), "pkt_count starts at 0")
    assert_true(p.get(CounterId.FFI_SHIM_US_TOTAL) == UInt64(0), "ffi_shim starts at 0")
    assert_true(p.get(CounterId.HP_US_TOTAL) == UInt64(0), "hp starts at 0")
    assert_true(p.get(CounterId.AEAD_US_TOTAL) == UInt64(0), "aead starts at 0")
    assert_true(p.get(CounterId.HEADER_PARSE_US_TOTAL) == UInt64(0), "header_parse starts at 0")
    assert_true(p.get(CounterId.FRAME_PARSE_US_TOTAL) == UInt64(0), "frame_parse starts at 0")
    assert_true(p.get(CounterId.SM_US_TOTAL) == UInt64(0), "sm starts at 0")
    assert_true(p.get(CounterId.DRAIN_US_TOTAL) == UInt64(0), "drain starts at 0")
    assert_true(p.get(CounterId.RESIDUAL_US_TOTAL) == UInt64(0), "residual starts at 0")
    assert_true(p.get(CounterId.PER_PKT_TOTAL_OVERFLOW) == UInt64(0), "overflow starts at 0")
    assert_true(p.get(CounterId.HS_ARRIVALS) == UInt64(0), "hs_arrivals starts at 0")
    assert_true(p.get(CounterId.HS_COMPLETED) == UInt64(0), "hs_completed starts at 0")
    assert_true(p.get(CounterId.HS_TIMED_OUT) == UInt64(0), "hs_timed_out starts at 0")
    assert_true(len(p.pkts_per_flush_buckets) == 8, "fan-out has 8 buckets")
    assert_true(len(p.per_pkt_total_buckets) == 24, "per_pkt has 24 buckets")
    assert_true(len(p.hs_latency_us) == 0, "latency vector starts empty")
    assert_true(p.run_start_us > UInt64(0), "run_start_us stamped at construction")
    print("PASS: test_default_init")


def test_record_idle_accumulates() raises:
    var p = AcceptProfile()
    p.record_idle(UInt64(100))
    p.record_idle(UInt64(250))
    p.record_idle(UInt64(50))
    assert_true(p.get(CounterId.IDLE_US_TOTAL) == UInt64(400), "idle accumulates")
    print("PASS: test_record_idle_accumulates")


def test_record_flush_buckets_and_sums() raises:
    var p = AcceptProfile()
    p.record_flush(1, UInt64(10))
    p.record_flush(2, UInt64(20))
    p.record_flush(3, UInt64(30))
    p.record_flush(4, UInt64(40))
    p.record_flush(7, UInt64(50))
    p.record_flush(8, UInt64(60))
    p.record_flush(15, UInt64(70))
    p.record_flush(16, UInt64(80))
    p.record_flush(31, UInt64(90))
    p.record_flush(32, UInt64(100))
    p.record_flush(63, UInt64(110))
    p.record_flush(64, UInt64(120))
    p.record_flush(127, UInt64(130))
    p.record_flush(128, UInt64(140))
    p.record_flush(500, UInt64(150))
    assert_true(p.get(CounterId.ON_FLUSH_COUNT) == UInt64(15), "on_flush_count = 15")
    var expected_busy = UInt64(10 + 20 + 30 + 40 + 50 + 60 + 70 + 80 + 90 + 100 + 110 + 120 + 130 + 140 + 150)
    assert_true(p.get(CounterId.BUSY_US_TOTAL) == expected_busy, "busy_us accumulated")
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
    assert_true(_per_pkt_bucket(UInt64(0)) == 0, "0us -> bucket 0")
    assert_true(_per_pkt_bucket(UInt64(1)) == 1, "1us -> bucket 1")
    assert_true(_per_pkt_bucket(UInt64(2)) == 2, "2us -> bucket 2")
    assert_true(_per_pkt_bucket(UInt64(3)) == 2, "3us -> bucket 2")
    assert_true(_per_pkt_bucket(UInt64(4)) == 3, "4us -> bucket 3")
    assert_true(_per_pkt_bucket(UInt64(7)) == 3, "7us -> bucket 3")
    assert_true(_per_pkt_bucket(UInt64(8)) == 4, "8us -> bucket 4")
    assert_true(_per_pkt_bucket(UInt64(4_194_304)) == 23, "4.2Mus -> bucket 23")
    assert_true(_per_pkt_bucket(UInt64(8_388_607)) == 23, "<8.39s -> bucket 23")
    assert_true(_per_pkt_bucket(UInt64(8_388_608)) == 24, "8.39s -> overflow=24")
    assert_true(_per_pkt_bucket(UInt64(100_000_000)) == 24, "100s -> overflow=24")
    print("PASS: test_per_pkt_bucket_assignment")


def test_record_pkt_sums_and_residual() raises:
    var p = AcceptProfile()
    p.record_pkt(
        total_us=UInt64(120), ffi_us=UInt64(80), hp_us=UInt64(10),
        aead_us=UInt64(15), header_parse_us=UInt64(8),
        frame_parse_us=UInt64(12), sm_us=UInt64(25),
    )
    assert_true(p.get(CounterId.PKT_COUNT) == UInt64(1), "pkt_count = 1")
    assert_true(p.get(CounterId.FFI_SHIM_US_TOTAL) == UInt64(80), "ffi sum")
    assert_true(p.get(CounterId.HP_US_TOTAL) == UInt64(10), "hp sum")
    assert_true(p.get(CounterId.AEAD_US_TOTAL) == UInt64(15), "aead sum")
    assert_true(p.get(CounterId.HEADER_PARSE_US_TOTAL) == UInt64(8), "header_parse sum")
    assert_true(p.get(CounterId.FRAME_PARSE_US_TOTAL) == UInt64(12), "frame_parse sum")
    assert_true(p.get(CounterId.SM_US_TOTAL) == UInt64(25), "sm sum")
    assert_true(p.get(CounterId.RESIDUAL_US_TOTAL) == UInt64(50), "residual = 50")
    assert_true(p.per_pkt_total_buckets[7] == UInt64(1), "120us in bucket 7")
    assert_true(p.get(CounterId.PER_PKT_TOTAL_OVERFLOW) == UInt64(0), "no overflow")
    print("PASS: test_record_pkt_sums_and_residual")


def test_record_pkt_overflow() raises:
    var p = AcceptProfile()
    p.record_pkt(
        total_us=UInt64(10_000_000), ffi_us=UInt64(0), hp_us=UInt64(0),
        aead_us=UInt64(0), header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0), sm_us=UInt64(0),
    )
    assert_true(p.get(CounterId.PKT_COUNT) == UInt64(1), "pkt_count = 1")
    assert_true(p.get(CounterId.PER_PKT_TOTAL_OVERFLOW) == UInt64(1), "overflow = 1")
    for i in range(24):
        assert_true(p.per_pkt_total_buckets[i] == UInt64(0), "no closed-bucket bump")
    assert_true(p.get(CounterId.RESIDUAL_US_TOTAL) == UInt64(10_000_000), "residual = total when legs=0")
    print("PASS: test_record_pkt_overflow")


def test_record_pkt_residual_underflow_safe() raises:
    var p = AcceptProfile()
    p.record_pkt(
        total_us=UInt64(50), ffi_us=UInt64(0), hp_us=UInt64(20),
        aead_us=UInt64(20), header_parse_us=UInt64(20),
        frame_parse_us=UInt64(20), sm_us=UInt64(20),
    )
    assert_true(p.get(CounterId.RESIDUAL_US_TOTAL) == UInt64(0), "residual clamped to 0 on underflow")
    print("PASS: test_record_pkt_residual_underflow_safe")


def test_record_drain_accumulates() raises:
    var p = AcceptProfile()
    p.record_drain(UInt64(40))
    p.record_drain(UInt64(60))
    p.record_drain(UInt64(0))
    assert_true(p.get(CounterId.DRAIN_US_TOTAL) == UInt64(100), "drain accumulates")
    print("PASS: test_record_drain_accumulates")


def test_handshake_records() raises:
    var p = AcceptProfile()
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))
    p.record_handshake_complete(UInt64(46000))
    p.record_handshake_timeout(UInt64(7))
    p.record_handshake_timeout()
    assert_true(p.get(CounterId.HS_ARRIVALS) == UInt64(3), "3 arrivals")
    assert_true(p.get(CounterId.HS_COMPLETED) == UInt64(2), "2 completed")
    assert_true(p.get(CounterId.HS_TIMED_OUT) == UInt64(8), "7 + 1 = 8 timeouts")
    assert_true(len(p.hs_latency_us) == 2, "latency vector has 2 entries")
    assert_true(p.hs_latency_us[0] == UInt64(8400), "first latency")
    assert_true(p.hs_latency_us[1] == UInt64(46000), "second latency")
    print("PASS: test_handshake_records")


def test_exact_percentile_basic() raises:
    var v = List[UInt64]()
    for i in range(1, 101):
        v.append(UInt64(i))
    assert_true(_exact_percentile(v, 50.0) == UInt64(50), "p50 of 1..100 = 50")
    assert_true(_exact_percentile(v, 90.0) == UInt64(90), "p90 of 1..100 = 90")
    assert_true(_exact_percentile(v, 99.0) == UInt64(99), "p99 of 1..100 = 99")
    assert_true(_exact_percentile(v, 100.0) == UInt64(100), "p100 of 1..100 = 100")
    print("PASS: test_exact_percentile_basic")


def test_exact_percentile_empty_returns_zero() raises:
    var v = List[UInt64]()
    assert_true(_exact_percentile(v, 50.0) == UInt64(0), "empty -> 0")
    print("PASS: test_exact_percentile_empty_returns_zero")


def test_exact_percentile_unsorted_input() raises:
    var v = List[UInt64]()
    v.append(UInt64(50))
    v.append(UInt64(10))
    v.append(UInt64(30))
    v.append(UInt64(40))
    v.append(UInt64(20))
    assert_true(_exact_percentile(v, 50.0) == UInt64(30), "p50 of [50,10,30,40,20] = 30")
    print("PASS: test_exact_percentile_unsorted_input")


def test_bucket_percentile_uniform() raises:
    """Uniform [1us, 1ms): p50 ~ 500us, p90 ~ 900us, p99 ~ 990us, +/-25%."""
    var p = AcceptProfile()
    var seed: UInt64 = UInt64(0xdeadbeef)
    for _ in range(10000):
        seed = seed * UInt64(6364136223846793005) + UInt64(1442695040888963407)
        var us = UInt64(1) + (seed % UInt64(999))
        p.record_pkt(
            total_us=us, ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
            header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
        )
    var n_closed = p.get(CounterId.PKT_COUNT) - p.get(CounterId.PER_PKT_TOTAL_OVERFLOW)
    var p50 = _bucket_percentile(p.per_pkt_total_buckets, n_closed, 50.0)
    var p90 = _bucket_percentile(p.per_pkt_total_buckets, n_closed, 90.0)
    var p99 = _bucket_percentile(p.per_pkt_total_buckets, n_closed, 99.0)
    assert_true(p50 >= UInt64(375) and p50 <= UInt64(625), "p50 in [375, 625]")
    assert_true(p90 >= UInt64(675) and p90 <= UInt64(1125), "p90 in [675, 1125]")
    assert_true(p99 >= UInt64(742) and p99 <= UInt64(1238), "p99 in [742, 1238]")
    print("PASS: test_bucket_percentile_uniform")


def test_bucket_percentile_overflow() raises:
    """999 samples at 100us + 1 over the 2^23us cutoff."""
    var p = AcceptProfile()
    for _ in range(999):
        p.record_pkt(
            total_us=UInt64(100), ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
            header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
        )
    p.record_pkt(
        total_us=UInt64(10_000_000), ffi_us=UInt64(0), hp_us=UInt64(0), aead_us=UInt64(0),
        header_parse_us=UInt64(0), frame_parse_us=UInt64(0), sm_us=UInt64(0),
    )
    assert_true(p.get(CounterId.PER_PKT_TOTAL_OVERFLOW) == UInt64(1), "1 overflow sample")
    var n_closed = p.get(CounterId.PKT_COUNT) - p.get(CounterId.PER_PKT_TOTAL_OVERFLOW)
    var p50 = _bucket_percentile(p.per_pkt_total_buckets, n_closed, 50.0)
    assert_true(p50 >= UInt64(64) and p50 < UInt64(128), "p50 in bucket 7 range")
    print("PASS: test_bucket_percentile_overflow")


def test_report_text_canned() raises:
    """Assert key markers in text report."""
    var p = AcceptProfile()
    p.record_idle(UInt64(31_830_000))
    p.record_flush(1, UInt64(2_380_000))
    p.record_pkt(
        total_us=UInt64(120), ffi_us=UInt64(78), hp_us=UInt64(12),
        aead_us=UInt64(22), header_parse_us=UInt64(6),
        frame_parse_us=UInt64(11), sm_us=UInt64(14),
    )
    p.record_drain(UInt64(39))
    p.record_handshake_arrival()
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))
    p.record_handshake_timeout(UInt64(1))
    var s = p.report_text()
    assert_true("=== navette QUIC accept-loop profile ===" in s, "header present")
    assert_true("=== end ===" in s, "footer present")
    assert_true("On_flush events:" in s, "on_flush events line")
    assert_true("Idle (bouclette wait):" in s, "idle line")
    assert_true("Busy (in loop):" in s, "busy line")
    assert_true("Datagrams batched per flush" in s, "fan-out header")
    assert_true("size=1" in s, "size=1 label")
    assert_true("size=128+" in s, "size=128+ label")
    assert_true("Per-packet wall-clock" in s, "per-packet header")
    assert_true("header parse" in s, "header parse leg")
    assert_true("HP unprotect" in s, "HP leg")
    assert_true("AEAD decrypt" in s, "AEAD leg")
    assert_true("frame parse" in s, "frame_parse leg")
    assert_true("state machine" in s, "sm leg")
    assert_true("residual" in s, "residual leg")
    assert_true("shim FFI" in s, "shim FFI leg")
    assert_true("drain (bench)" in s, "drain leg")
    assert_true("Handshake accounting:" in s, "handshake header")
    assert_true("Arrivals:" in s, "arrivals row")
    assert_true("Successful:" in s, "successful row")
    assert_true("Timed out:" in s, "timed-out row")
    assert_true("Successful handshake latency" in s, "latency header")
    assert_true("avg= 78" in s, "shim FFI avg=78 (single sample)")
    print("PASS: test_report_text_canned")


def test_report_json_canned() raises:
    """Verify JSON contains all required keys with the right values."""
    var p = AcceptProfile()
    p.record_idle(UInt64(1000))
    p.record_flush(1, UInt64(500))
    p.record_pkt(
        total_us=UInt64(120), ffi_us=UInt64(78), hp_us=UInt64(12),
        aead_us=UInt64(22), header_parse_us=UInt64(6),
        frame_parse_us=UInt64(11), sm_us=UInt64(14),
    )
    p.record_drain(UInt64(39))
    p.record_handshake_arrival()
    p.record_handshake_complete(UInt64(8400))
    var j = p.report_json()
    assert_true('"schema_version": 7' in j, "schema_version=7")
    assert_true('"run_wall_clock_us":' in j, "run_wall_clock_us key")
    assert_true('"on_flush_events": 1' in j, "on_flush_events=1")
    assert_true('"idle_us_total": 1000' in j, "idle_us_total=1000")
    assert_true('"busy_us_total": 500' in j, "busy_us_total=500")
    assert_true('"pkts_per_flush_histogram":' in j, "fan-out histogram key")
    assert_true('"1": 1' in j, '"1" bucket = 1')
    assert_true('"128+": 0' in j, '"128+" bucket = 0')
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
    assert_true('"handshake":' in j, "handshake key")
    assert_true('"arrivals": 1' in j, "arrivals=1")
    assert_true('"successful": 1' in j, "successful=1")
    assert_true('"timed_out": 0' in j, "timed_out=0")
    assert_true('"latency_us":' in j, "latency_us subkey")
    print("PASS: test_report_json_canned")


def test_record_arrival_lat_buckets() raises:
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(0))
    p.record_arrival_lat(UInt64(1))
    p.record_arrival_lat(UInt64(3))
    p.record_arrival_lat(UInt64(100))
    p.record_arrival_lat(UInt64(1_000_000))
    assert_true(p.arrival_lat_us_buckets[0] == UInt64(1), "bucket 0 = 1")
    assert_true(p.arrival_lat_us_buckets[1] == UInt64(1), "bucket 1 = 1")
    assert_true(p.arrival_lat_us_buckets[2] == UInt64(1), "bucket 2 = 1")
    assert_true(p.arrival_lat_us_buckets[7] == UInt64(1), "bucket 7 = 1")
    assert_true(p.arrival_lat_us_buckets[20] == UInt64(1), "bucket 20 = 1")
    assert_true(p.get(CounterId.ARRIVAL_LAT_US_TOTAL) == UInt64(0 + 1 + 3 + 100 + 1_000_000), "total summed")
    assert_true(p.get(CounterId.ARRIVAL_LAT_US_OVERFLOW) == UInt64(0), "no overflow")
    print("PASS: test_record_arrival_lat_buckets")


def test_record_arrival_lat_overflow() raises:
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(8_388_608))
    p.record_arrival_lat(UInt64(10_000_000))
    assert_true(p.get(CounterId.ARRIVAL_LAT_US_OVERFLOW) == UInt64(2), "overflow = 2")
    assert_true(p.get(CounterId.ARRIVAL_LAT_US_TOTAL) == UInt64(8_388_608 + 10_000_000), "overflow values still summed")
    var sum_buckets: UInt64 = UInt64(0)
    for i in range(24):
        sum_buckets += p.arrival_lat_us_buckets[i]
    assert_true(sum_buckets == UInt64(0), "no closed bucket entries")
    print("PASS: test_record_arrival_lat_overflow")


def test_report_json_arrival_latency_block() raises:
    var p = AcceptProfile()
    p.record_arrival_lat(UInt64(50))
    p.record_arrival_lat(UInt64(50))
    p.record_arrival_lat(UInt64(2_000_000))
    p.record_arrival_lat(UInt64(20_000_000))
    var j = p.report_json()
    assert_true('"arrival_lat_us_total":' in j, "arrival_lat_us_total key present")
    assert_true('"arrival_lat_us_buckets":' in j, "arrival_lat_us_buckets key present")
    assert_true('"arrival_lat_us_overflow":' in j, "arrival_lat_us_overflow key present")
    var expected_total = UInt64(50 + 50 + 2_000_000 + 20_000_000)
    assert_true(String('"arrival_lat_us_total": ') + String(expected_total) in j, "total value matches")
    assert_true('"arrival_lat_us_overflow": 1' in j, "overflow = 1")
    print("PASS: test_report_json_arrival_latency_block")


def test_record_dcid_mismatch_scalar() raises:
    var p = AcceptProfile()
    assert_true(p.get(CounterId.DCID_MISMATCH_PKTS) == UInt64(0), "dcid_mismatch_pkts starts at 0")
    p.record_dcid_mismatch()
    p.record_dcid_mismatch()
    p.record_dcid_mismatch()
    assert_true(p.get(CounterId.DCID_MISMATCH_PKTS) == UInt64(3), "3 calls -> total=3")
    var j = p.report_json()
    assert_true('"dcid_mismatch_pkts": 3' in j, "JSON emits scalar")
    var t = p.report_text()
    assert_true("dcid_mismatch_pkts: 3" in t, "text emits scalar")
    print("PASS: test_record_dcid_mismatch_scalar")


def test_record_ffi_read_hs_increments_total() raises:
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_read_hs(UInt64(150))
    p.record_ffi_read_hs(UInt64(50))
    if p.get(CounterId.FFI_READ_HS_US_TOTAL) != UInt64(300):
        raise "expected ffi_read_hs_us_total=300, got " + String(p.get(CounterId.FFI_READ_HS_US_TOTAL))
    print("PASS: test_record_ffi_read_hs_increments_total")


def test_record_ffi_write_hs_increments_total() raises:
    var p = AcceptProfile()
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_write_hs(UInt64(300))
    if p.get(CounterId.FFI_WRITE_HS_US_TOTAL) != UInt64(500):
        raise "expected ffi_write_hs_us_total=500"
    print("PASS: test_record_ffi_write_hs_increments_total")


def test_record_ffi_take_keys_increments_total() raises:
    var p = AcceptProfile()
    p.record_ffi_take_keys(UInt64(40))
    p.record_ffi_take_keys(UInt64(60))
    if p.get(CounterId.FFI_TAKE_KEYS_US_TOTAL) != UInt64(100):
        raise "expected ffi_take_keys_us_total=100"
    print("PASS: test_record_ffi_take_keys_increments_total")


def test_record_loop_pop_dispatch_increments_total() raises:
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(50))
    p.record_loop_pop_dispatch(UInt64(75))
    if p.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL) != UInt64(125):
        raise "expected 125"
    print("PASS: test_record_loop_pop_dispatch_increments_total")


def test_record_loop_post_pkt_increments_total() raises:
    var p = AcceptProfile()
    p.record_loop_post_pkt(UInt64(20))
    p.record_loop_post_pkt(UInt64(30))
    if p.get(CounterId.LOOP_POST_PKT_US_TOTAL) != UInt64(50):
        raise "expected 50"
    print("PASS: test_record_loop_post_pkt_increments_total")


def test_record_loop_teardown_increments_total() raises:
    var p = AcceptProfile()
    p.record_loop_teardown(UInt64(8))
    p.record_loop_teardown(UInt64(12))
    if p.get(CounterId.LOOP_TEARDOWN_US_TOTAL) != UInt64(20):
        raise "expected 20"
    print("PASS: test_record_loop_teardown_increments_total")


def test_ffi_subleg_sum_matches_shim_ffi_within_tolerance() raises:
    var p = AcceptProfile()
    p.record_pkt(
        total_us=UInt64(120), ffi_us=UInt64(100), hp_us=UInt64(1),
        aead_us=UInt64(1), header_parse_us=UInt64(1),
        frame_parse_us=UInt64(5), sm_us=UInt64(60),
    )
    p.record_ffi_read_hs(UInt64(30))
    p.record_ffi_write_hs(UInt64(50))
    p.record_ffi_take_keys(UInt64(20))
    var subleg_sum = p.get(CounterId.FFI_READ_HS_US_TOTAL) + p.get(CounterId.FFI_WRITE_HS_US_TOTAL) + p.get(CounterId.FFI_TAKE_KEYS_US_TOTAL)
    var shim = p.get(CounterId.FFI_SHIM_US_TOTAL)
    var diff: UInt64
    if subleg_sum >= shim:
        diff = subleg_sum - shim
    else:
        diff = shim - subleg_sum
    var tol = shim // UInt64(100)
    if tol < UInt64(1):
        tol = UInt64(1)
    if diff > tol:
        raise "ffi_subleg sum differs from shim_ffi by more than 1%"
    print("PASS: test_ffi_subleg_sum_matches_shim_ffi_within_tolerance")


def test_loop_budget_closure_zero_residual() raises:
    var p = AcceptProfile()
    p.set(CounterId.BUSY_US_TOTAL, UInt64(1000))
    p.record_pkt(
        total_us=UInt64(200), ffi_us=UInt64(0), hp_us=UInt64(0),
        aead_us=UInt64(0), header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0), sm_us=UInt64(200),
    )
    p.record_drain(UInt64(100))
    p.record_loop_pop_dispatch(UInt64(400))
    p.record_loop_post_pkt(UInt64(200))
    p.record_loop_teardown(UInt64(100))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 0" not in s:
        raise "expected unaccounted_us_total=0"
    if "\"unaccounted_pct\": 0" not in s:
        raise "expected unaccounted_pct=0"
    print("PASS: test_loop_budget_closure_zero_residual")


def test_loop_budget_closure_nonzero_residual() raises:
    var p = AcceptProfile()
    p.set(CounterId.BUSY_US_TOTAL, UInt64(10000))
    p.record_pkt(
        total_us=UInt64(2000), ffi_us=UInt64(0), hp_us=UInt64(0),
        aead_us=UInt64(0), header_parse_us=UInt64(0),
        frame_parse_us=UInt64(0), sm_us=UInt64(2000),
    )
    p.record_drain(UInt64(1000))
    p.record_loop_pop_dispatch(UInt64(4000))
    p.record_loop_post_pkt(UInt64(2000))
    p.record_loop_teardown(UInt64(900))
    var s = p.report_json()
    if "\"unaccounted_us_total\": 100" not in s:
        raise "expected unaccounted_us_total=100"
    if "\"unaccounted_pct\": 1" not in s:
        raise "expected unaccounted_pct=1"
    print("PASS: test_loop_budget_closure_nonzero_residual")


def test_report_json_emits_ffi_subleg_block() raises:
    var p = AcceptProfile()
    p.record_ffi_read_hs(UInt64(100))
    p.record_ffi_write_hs(UInt64(200))
    p.record_ffi_take_keys(UInt64(50))
    var s = p.report_json()
    if "\"ffi_subleg_us\"" not in s: raise "missing ffi_subleg_us block"
    if "\"read_hs\"" not in s: raise "missing read_hs key"
    if "\"write_hs\"" not in s: raise "missing write_hs key"
    if "\"take_keys\"" not in s: raise "missing take_keys key"
    if "\"total\": 100" not in s: raise "missing read_hs total=100"
    if "\"total\": 200" not in s: raise "missing write_hs total=200"
    print("PASS: test_report_json_emits_ffi_subleg_block")


def test_report_json_emits_loop_phases_block() raises:
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(150))
    p.record_loop_post_pkt(UInt64(50))
    p.record_loop_teardown(UInt64(20))
    p.record_loop_iter()
    p.record_loop_iter()
    var s = p.report_json()
    if "\"loop_phases_us\"" not in s: raise "missing loop_phases_us block"
    if "\"pop_dispatch\"" not in s: raise "missing pop_dispatch key"
    if "\"post_pkt\"" not in s: raise "missing post_pkt key"
    if "\"teardown\"" not in s: raise "missing teardown key"
    if "\"loop_iter_count\": 2" not in s: raise "missing loop_iter_count=2"
    if "\"unaccounted_us_total\"" not in s: raise "missing unaccounted_us_total key"
    if "\"unaccounted_pct\"" not in s: raise "missing unaccounted_pct key"
    print("PASS: test_report_json_emits_loop_phases_block")


def test_loop_phase_avg_uses_loop_iter_count_divisor() raises:
    var p = AcceptProfile()
    p.record_loop_pop_dispatch(UInt64(10000))
    for _ in range(100):
        p.record_loop_iter()
    p.set(CounterId.PKT_COUNT, UInt64(50))
    var s = p.report_json()
    if "\"pop_dispatch\": {\"avg\": 100" not in s:
        raise "expected pop_dispatch.avg=100 (loop_iter_count divisor)"
    print("PASS: test_loop_phase_avg_uses_loop_iter_count_divisor")


def test_record_h3_drain_resp_increments_total() raises:
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(123))
    p.record_h3_drain_resp(UInt64(456))
    assert_equal_int(Int(p.get(CounterId.H3_DRAIN_RESP_US_TOTAL)), 579, "h3_drain_resp accumulates")
    print("PASS: test_record_h3_drain_resp_increments_total")


def test_record_quic_post_recv_increments_total() raises:
    var p = AcceptProfile()
    p.record_quic_post_recv(UInt64(100))
    p.record_quic_post_recv(UInt64(200))
    assert_equal_int(Int(p.get(CounterId.QUIC_POST_RECV_US_TOTAL)), 300, "quic_post_recv accumulates")
    print("PASS: test_record_quic_post_recv_increments_total")


def test_record_h3_dispatch_increments_total() raises:
    var p = AcceptProfile()
    p.record_h3_dispatch(UInt64(50))
    p.record_h3_dispatch(UInt64(75))
    assert_equal_int(Int(p.get(CounterId.H3_DISPATCH_US_TOTAL)), 125, "h3_dispatch accumulates")
    print("PASS: test_record_h3_dispatch_increments_total")


def test_report_json_emits_h3_phases_block() raises:
    var p = AcceptProfile()
    p.record_h3_drain_resp(UInt64(1000))
    p.record_quic_post_recv(UInt64(2000))
    p.record_h3_dispatch(UInt64(3000))
    var out = p.report_json()
    assert_true('"h3_phases_us":' in out, "h3_phases_us block missing")
    assert_true('"drain_resp":' in out, "drain_resp key missing")
    assert_true('"post_recv":' in out, "post_recv key missing")
    assert_true('"dispatch":' in out, "dispatch key missing")
    assert_true('"total": 1000' in out, "drain_resp total missing")
    assert_true('"total": 2000' in out, "post_recv total missing")
    assert_true('"total": 3000' in out, "dispatch total missing")
    print("PASS: test_report_json_emits_h3_phases_block")


def test_h3_phase_legs_sum_within_unaccounted_bucket() raises:
    var p = AcceptProfile()
    p.set(CounterId.BUSY_US_TOTAL, UInt64(1000))
    p.set(CounterId.HEADER_PARSE_US_TOTAL, UInt64(33))
    p.set(CounterId.HP_US_TOTAL, UInt64(33))
    p.set(CounterId.AEAD_US_TOTAL, UInt64(33))
    p.set(CounterId.FRAME_PARSE_US_TOTAL, UInt64(34))
    p.set(CounterId.SM_US_TOTAL, UInt64(33))
    p.set(CounterId.RESIDUAL_US_TOTAL, UInt64(34))
    p.set(CounterId.DRAIN_US_TOTAL, UInt64(100))
    p.set(CounterId.LOOP_POP_DISPATCH_US_TOTAL, UInt64(34))
    p.set(CounterId.LOOP_POST_PKT_US_TOTAL, UInt64(33))
    p.set(CounterId.LOOP_TEARDOWN_US_TOTAL, UInt64(33))
    p.record_h3_drain_resp(UInt64(300))
    p.record_quic_post_recv(UInt64(150))
    p.record_h3_dispatch(UInt64(50))
    var per_pkt = (p.get(CounterId.HEADER_PARSE_US_TOTAL) + p.get(CounterId.HP_US_TOTAL)
        + p.get(CounterId.AEAD_US_TOTAL) + p.get(CounterId.FRAME_PARSE_US_TOTAL)
        + p.get(CounterId.SM_US_TOTAL) + p.get(CounterId.RESIDUAL_US_TOTAL))
    var loop_phases = (p.get(CounterId.LOOP_POP_DISPATCH_US_TOTAL)
        + p.get(CounterId.LOOP_POST_PKT_US_TOTAL) + p.get(CounterId.LOOP_TEARDOWN_US_TOTAL))
    var pre_h3_unacct = p.get(CounterId.BUSY_US_TOTAL) - per_pkt - p.get(CounterId.DRAIN_US_TOTAL) - loop_phases
    var h3_sum = (p.get(CounterId.H3_DRAIN_RESP_US_TOTAL) + p.get(CounterId.QUIC_POST_RECV_US_TOTAL)
        + p.get(CounterId.H3_DISPATCH_US_TOTAL))
    assert_true(h3_sum <= pre_h3_unacct, "h3 legs must fit within pre-h3 unaccounted bucket")
    print("PASS: test_h3_phase_legs_sum_within_unaccounted_bucket")


def test_budget_closure_subtracts_h3_legs() raises:
    var p = AcceptProfile()
    p.set(CounterId.BUSY_US_TOTAL, UInt64(1000))
    p.set(CounterId.HEADER_PARSE_US_TOTAL, UInt64(50))
    p.set(CounterId.HP_US_TOTAL, UInt64(50))
    p.set(CounterId.AEAD_US_TOTAL, UInt64(50))
    p.set(CounterId.FRAME_PARSE_US_TOTAL, UInt64(50))
    p.set(CounterId.SM_US_TOTAL, UInt64(50))
    p.set(CounterId.RESIDUAL_US_TOTAL, UInt64(50))
    p.set(CounterId.DRAIN_US_TOTAL, UInt64(100))
    p.set(CounterId.LOOP_POP_DISPATCH_US_TOTAL, UInt64(50))
    p.set(CounterId.LOOP_POST_PKT_US_TOTAL, UInt64(50))
    p.set(CounterId.LOOP_TEARDOWN_US_TOTAL, UInt64(50))
    p.record_h3_drain_resp(UInt64(200))
    p.record_quic_post_recv(UInt64(100))
    p.record_h3_dispatch(UInt64(50))
    var out = p.report_json()
    assert_true('"unaccounted_us_total": 100,' in out, "unaccounted_us_total should be 100")
    assert_true('"unaccounted_pct": 10' in out, "unaccounted_pct should be 10")
    print("PASS: test_budget_closure_subtracts_h3_legs")


def test_record_drain_stream_increments_total() raises:
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(123))
    p.record_drain_stream(UInt64(456))
    assert_equal_int(Int(p.get(CounterId.DRAIN_STREAM_US_TOTAL)), 579, "drain_stream accumulates")
    print("PASS: test_record_drain_stream_increments_total")


def test_record_drain_recv_ffi_increments_total() raises:
    var p = AcceptProfile()
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_recv_ffi(UInt64(200))
    assert_equal_int(Int(p.get(CounterId.DRAIN_RECV_FFI_US_TOTAL)), 300, "drain_recv_ffi accumulates")
    print("PASS: test_record_drain_recv_ffi_increments_total")


def test_record_drain_buf_accumulate_increments_total() raises:
    var p = AcceptProfile()
    p.record_drain_buf_accumulate(UInt64(11))
    p.record_drain_buf_accumulate(UInt64(22))
    p.record_drain_buf_accumulate(UInt64(33))
    assert_equal_int(Int(p.get(CounterId.DRAIN_BUF_ACCUMULATE_US_TOTAL)), 66,
        "drain_buf_accumulate accumulates across calls")
    print("PASS: test_record_drain_buf_accumulate_increments_total")


def test_record_drain_frame_parse_and_qpack_decode_independent() raises:
    var p = AcceptProfile()
    p.record_drain_frame_parse(UInt64(50))
    p.record_drain_qpack_decode(UInt64(75))
    assert_equal_int(Int(p.get(CounterId.DRAIN_FRAME_PARSE_US_TOTAL)), 50, "frame_parse field independent")
    assert_equal_int(Int(p.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL)), 75, "qpack_decode field independent")
    p.record_drain_frame_parse(UInt64(10))
    assert_equal_int(Int(p.get(CounterId.DRAIN_QPACK_DECODE_US_TOTAL)), 75,
        "qpack_decode unchanged after second frame_parse call")
    print("PASS: test_record_drain_frame_parse_and_qpack_decode_independent")


def test_report_json_emits_drain_stream_subleg_block() raises:
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(10000))
    p.record_drain_recv_ffi(UInt64(1000))
    p.record_drain_buf_accumulate(UInt64(2000))
    p.record_drain_frame_parse(UInt64(500))
    p.record_drain_qpack_decode(UInt64(300))
    var out = p.report_json()
    assert_true('"drain_stream_subleg":' in out, "drain_stream_subleg block missing")
    assert_true('"drain_stream_us_total":' in out, "drain_stream_us_total key missing")
    assert_true('"recv_ffi_us":' in out, "recv_ffi_us key missing")
    assert_true('"buf_accumulate_us":' in out, "buf_accumulate_us key missing")
    assert_true('"frame_parse_us":' in out, "frame_parse_us key missing")
    assert_true('"qpack_decode_us":' in out, "qpack_decode_us key missing")
    assert_true('"event_dispatch_us":' in out, "event_dispatch_us key missing")
    assert_true('"sum_legs_us":' in out, "sum_legs_us key missing")
    assert_true('"unaccounted_pct":' in out, "unaccounted_pct key missing")
    assert_true('"drain_stream_us_total": 10000' in out, "drain_stream value")
    assert_true('"recv_ffi_us": 1000' in out, "recv_ffi value")
    assert_true('"event_dispatch_us": 6200' in out, "event_dispatch residual=6200")
    assert_true('"sum_legs_us": 10000' in out, "sum_legs=10000")
    print("PASS: test_report_json_emits_drain_stream_subleg_block")


def test_drain_subleg_sum_invariant_residual() raises:
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(100))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 200, "event_dispatch residual = 200")
    var out = p.report_json()
    assert_true('"event_dispatch_us": 200' in out, "JSON event_dispatch=200")
    assert_true('"sum_legs_us": 1000' in out, "sum_legs (with derived) = 1000")
    assert_true('"unaccounted_pct": 0' in out, "unaccounted_pct=0 (closed)")
    print("PASS: test_drain_subleg_sum_invariant_residual")


def test_drain_subleg_residual_clamp_overshoot() raises:
    var p = AcceptProfile()
    p.record_drain_stream(UInt64(1000))
    p.record_drain_recv_ffi(UInt64(400))
    p.record_drain_buf_accumulate(UInt64(400))
    p.record_drain_frame_parse(UInt64(200))
    p.record_drain_qpack_decode(UInt64(100))
    var de = p._compute_drain_event_dispatch_us()
    assert_equal_int(Int(de), 0, "event_dispatch clamped to 0 on overshoot")
    var out_json = p.report_json()
    assert_true('"event_dispatch_us": 0' in out_json, "JSON event_dispatch=0 (clamped)")
    var out_text = p.report_text()
    assert_true("event_dispatch.derived: 0" in out_text, "text event_dispatch=0 (clamped)")
    print("PASS: test_drain_subleg_residual_clamp_overshoot")


def test_record_handshakes_full_resumed_increment() raises:
    var p = AcceptProfile()
    assert_true(p.get(CounterId.HANDSHAKES_FULL_TOTAL) == UInt64(0), "starts at 0")
    assert_true(p.get(CounterId.HANDSHAKES_RESUMED_TOTAL) == UInt64(0), "starts at 0")
    p.record_handshake_full()
    p.record_handshake_full()
    p.record_handshake_resumed()
    p.record_handshake_full()
    assert_true(p.get(CounterId.HANDSHAKES_FULL_TOTAL) == UInt64(3), "full = 3")
    assert_true(p.get(CounterId.HANDSHAKES_RESUMED_TOTAL) == UInt64(1), "resumed = 1")
    print("PASS: test_record_handshakes_full_resumed_increment")


def test_report_json_emits_handshakes_block() raises:
    var p = AcceptProfile()
    p.record_handshake_full()
    p.record_handshake_resumed()
    p.record_handshake_resumed()
    var s = p.report_json()
    var i_handshakes = s.find('"handshakes"')
    assert_true(i_handshakes >= 0, '"handshakes" key present')
    var i_full = s.find('"full": 1', i_handshakes)
    assert_true(i_full >= 0, '"full": 1 present')
    var i_resumed = s.find('"resumed": 2', i_handshakes)
    assert_true(i_resumed >= 0, '"resumed": 2 present')
    print("PASS: test_report_json_emits_handshakes_block")


def test_record_fresh_conn_ffi_us_dispatches_into_buckets() raises:
    var p = AcceptProfile()
    for i in range(24):
        assert_true(p.fresh_conn_ffi_us_buckets[i] == UInt64(0), "bucket starts at 0")
    assert_true(p.get(CounterId.FRESH_CONN_FFI_US_OVERFLOW) == UInt64(0), "overflow starts at 0")
    p.record_fresh_conn_ffi_us(UInt64(0))
    assert_true(p.fresh_conn_ffi_us_buckets[0] == UInt64(1), "0us -> bucket 0")
    p.record_fresh_conn_ffi_us(UInt64(1024))
    assert_true(p.fresh_conn_ffi_us_buckets[11] == UInt64(1), "1024us -> bucket 11")
    p.record_fresh_conn_ffi_us(UInt64(1 << 23))
    assert_true(p.get(CounterId.FRESH_CONN_FFI_US_OVERFLOW) == UInt64(1), "2^23 -> overflow")
    print("PASS: test_record_fresh_conn_ffi_us_dispatches_into_buckets")


def test_record_recv_batch_dispatches_into_8_buckets() raises:
    var p = AcceptProfile()
    p.record_recv_batch(1)
    p.record_recv_batch(1)
    p.record_recv_batch(1)
    p.record_recv_batch(5)
    p.record_recv_batch(200)
    assert_true(p.recv_batch_size_buckets[0] == UInt64(3), "size=1 -> 3")
    assert_true(p.recv_batch_size_buckets[2] == UInt64(1), "size=5 -> 1")
    assert_true(p.recv_batch_size_buckets[7] == UInt64(1), "size=200 -> 1")
    print("PASS: test_record_recv_batch_dispatches_into_8_buckets")


def test_report_json_emits_fresh_conn_blocks() raises:
    var p = AcceptProfile()
    p.record_fresh_conn_ffi_us(UInt64(15000))
    p.record_recv_batch(1)
    p.record_recv_batch(1)
    var s = p.report_json()
    assert_true(s.find('"fresh_conn_ffi_us"') >= 0, "fresh_conn_ffi_us key")
    assert_true(s.find('"recv_batch_size_buckets"') >= 0, "recv_batch_size_buckets key")
    var i_recv = s.find('"recv_batch_size_buckets"')
    assert_true(s.find('"1": 2', i_recv) >= 0, '"1": 2 present')
    print("PASS: test_report_json_emits_fresh_conn_blocks")


def test_record_read_hs_per_handshake_count_dispatches_into_8_buckets() raises:
    var p = AcceptProfile()
    p.record_read_hs_per_handshake_count(1)
    p.record_read_hs_per_handshake_count(1)
    p.record_read_hs_per_handshake_count(3)
    p.record_read_hs_per_handshake_count(9)
    p.record_read_hs_per_handshake_count(200)
    assert_true(p.read_hs_per_handshake_count_buckets[0] == UInt64(2), "bucket 0 = 2")
    assert_true(p.read_hs_per_handshake_count_buckets[1] == UInt64(1), "bucket 1 = 1")
    assert_true(p.read_hs_per_handshake_count_buckets[3] == UInt64(1), "bucket 3 = 1")
    assert_true(p.read_hs_per_handshake_count_buckets[7] == UInt64(1), "bucket 7 = 1")
    print("PASS: test_record_read_hs_per_handshake_count_dispatches_into_8_buckets")


def test_record_read_hs_us_per_call_dispatches_into_24_buckets() raises:
    var p = AcceptProfile()
    assert_true(p.get(CounterId.READ_HS_US_PER_CALL_OVERFLOW) == UInt64(0), "overflow starts at 0")
    p.record_read_hs_us_per_call(UInt64(0))
    assert_true(p.read_hs_us_per_call_buckets[0] == UInt64(1), "0us -> bucket 0")
    p.record_read_hs_us_per_call(UInt64(1024))
    assert_true(p.read_hs_us_per_call_buckets[11] == UInt64(1), "1024us -> bucket 11")
    p.record_read_hs_us_per_call(UInt64(1 << 23))
    assert_true(p.get(CounterId.READ_HS_US_PER_CALL_OVERFLOW) == UInt64(1), "2^23 -> overflow")
    print("PASS: test_record_read_hs_us_per_call_dispatches_into_24_buckets")


def test_report_json_emits_read_hs_blocks() raises:
    var p = AcceptProfile()
    p.record_read_hs_per_handshake_count(1)
    p.record_read_hs_per_handshake_count(1)
    p.record_read_hs_us_per_call(UInt64(150))
    var s = p.report_json()
    assert_true(s.find('"read_hs_per_handshake_count_buckets"') >= 0, "count buckets key")
    assert_true(s.find('"read_hs_us_per_call"') >= 0, "per_call key")
    print("PASS: test_report_json_emits_read_hs_blocks")


def test_q6_read_hs_sublegs_dispatch() raises:
    var p = AcceptProfile()
    p.record_read_hs_input_marshalling_us(UInt64(5))
    p.record_read_hs_state_machine_us(UInt64(50))
    p.record_read_hs_output_alloc_us(UInt64(0))
    p.record_read_hs_output_marshalling_us(UInt64(0))
    assert_true(p.read_hs_input_marshalling_us_buckets[3] == UInt64(1), "5us -> bucket 3")
    assert_true(p.read_hs_state_machine_us_buckets[6] == UInt64(1), "50us -> bucket 6")
    assert_true(p.read_hs_output_alloc_us_buckets[0] == UInt64(1), "0us -> bucket 0")
    assert_true(p.read_hs_output_marshalling_us_buckets[0] == UInt64(1), "0us -> bucket 0")
    p.record_read_hs_input_marshalling_us(UInt64(1 << 23))
    assert_true(p.get(CounterId.READ_HS_INPUT_MARSHALLING_US_OVERFLOW) == UInt64(1), "2^23 -> overflow")
    var j = p.report_json()
    assert_true(j.find('"read_hs_input_marshalling_us"') >= 0, "input_marshalling key")
    assert_true(j.find('"read_hs_state_machine_us"') >= 0, "state_machine key")
    assert_true(j.find('"read_hs_output_alloc_us"') >= 0, "output_alloc key")
    assert_true(j.find('"read_hs_output_marshalling_us"') >= 0, "output_marshalling key")
    print("PASS: test_q6_read_hs_sublegs_dispatch")


def test_alloc_tls_handle_us_dispatch() raises:
    var p = AcceptProfile()
    p.record_alloc_tls_handle_us(UInt64(50))
    assert_true(p.alloc_tls_handle_us_buckets[6] == UInt64(1), "50us -> bucket 6")
    p.record_alloc_tls_handle_us(UInt64(1 << 23))
    assert_true(p.get(CounterId.ALLOC_TLS_HANDLE_US_OVERFLOW) == UInt64(1), "2^23 -> overflow")
    assert_true(p.report_json().find('"alloc_tls_handle_us"') >= 0, "key in JSON")
    print("PASS: test_alloc_tls_handle_us_dispatch")


def test_q7_gauge_sampling() raises:
    var p = AcceptProfile()
    assert_true(len(p.active_bouclette_count_samples) == 0, "samples start empty")
    assert_true(len(p.in_flight_handshake_count_samples) == 0, "in_flight start empty")
    p.active_drive_count = UInt32(2)
    p.tick_profile_gauges(UInt64(0))
    p.tick_profile_gauges(UInt64(50_000))
    p.tick_profile_gauges(UInt64(150_000))
    assert_true(len(p.active_bouclette_count_samples) == 2, "cadence gate yields 2 samples")
    assert_true(len(p.in_flight_handshake_count_samples) == 2, "in_flight mirrors cadence")
    assert_true(p.active_bouclette_count_samples[0] == UInt32(2), "first sample = 2")
    assert_true(p.active_bouclette_count_samples[1] == UInt32(2), "third sample = 2")
    print("PASS: test_q7_gauge_sampling")


def test_q7_batch_histogram_dispatch() raises:
    var p = AcceptProfile()
    p.record_sendmsg_batch_size(1)
    p.record_sendmsg_batch_size(5)
    p.record_sendmsg_batch_size(1024)
    p.record_recvmsg_batch_size(1)
    p.record_recvmsg_batch_size(1)
    assert_true(p.sendmsg_batch_size_buckets[0] == UInt64(1), "sendmsg n=1 -> 1")
    assert_true(p.sendmsg_batch_size_buckets[2] == UInt64(1), "sendmsg n=5 -> 1")
    assert_true(p.sendmsg_batch_size_buckets[7] == UInt64(1), "sendmsg n=1024 -> 1")
    assert_true(p.recvmsg_batch_size_buckets[0] == UInt64(2), "recvmsg n=1 -> 2")
    assert_true(p.sendmsg_batch_size_buckets[0] == UInt64(1), "sendmsg unaffected by recvmsg")
    print("PASS: test_q7_batch_histogram_dispatch")


def test_iouring_park_us_record() raises:
    var p = AcceptProfile()
    assert_true(p.get(CounterId.IOURING_PARK_US_TOTAL) == UInt64(0), "starts at 0")
    p.record_iouring_park_us(UInt64(2_000_000))
    assert_true(p.get(CounterId.IOURING_PARK_US_TOTAL) == UInt64(2_000_000), "total=2M")
    p.record_iouring_park_us(UInt64(500_000))
    assert_true(p.get(CounterId.IOURING_PARK_US_TOTAL) == UInt64(2_500_000), "total=2.5M")
    print("PASS: test_iouring_park_us_record")


def test_zero_rtt_drain_dropped_counter_and_reporters() raises:
    var p = AcceptProfile()
    assert_equal_int(Int(p.get(CounterId.ZERO_RTT_DRAIN_DROPPED)), 0, "defaults 0")
    p.record_zero_rtt_drain_dropped()
    p.record_zero_rtt_drain_dropped()
    assert_equal_int(Int(p.get(CounterId.ZERO_RTT_DRAIN_DROPPED)), 2, "+2")
    assert_equal_int(Int(p.get(CounterId.ZERO_RTT_INSTALL_ATTEMPTS)), 0, "install untouched")
    var t = p.report_text()
    assert_true("zero_rtt_drain:" in t, "text block header")
    assert_true("  dropped:" in t, "text dropped line")
    var j = p.report_json()
    assert_true('"zero_rtt_drain"' in j, "json key")
    assert_true('"dropped"' in j, "json dropped key")
    print("PASS: test_zero_rtt_drain_dropped_counter_and_reporters")


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
    test_report_json_arrival_latency_block()
    test_record_dcid_mismatch_scalar()
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
    test_record_fresh_conn_ffi_us_dispatches_into_buckets()
    test_record_recv_batch_dispatches_into_8_buckets()
    test_report_json_emits_fresh_conn_blocks()
    test_record_read_hs_per_handshake_count_dispatches_into_8_buckets()
    test_record_read_hs_us_per_call_dispatches_into_24_buckets()
    test_report_json_emits_read_hs_blocks()
    test_q6_read_hs_sublegs_dispatch()
    test_alloc_tls_handle_us_dispatch()
    test_q7_gauge_sampling()
    test_q7_batch_histogram_dispatch()
    test_iouring_park_us_record()
    test_zero_rtt_drain_dropped_counter_and_reporters()
    print("All Plan A tests passed.")
