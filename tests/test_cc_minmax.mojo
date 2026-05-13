from std.testing import assert_true
from mojo_net.quic.cc.minmax import MinMax, MinMaxSample

comptime WIN_10MS: UInt64 = 10_000  # 10 ms in microseconds


def test_minmax_single_sample() raises:
    var m = MinMax(window_us=WIN_10MS)
    var v = m.running_min(WIN_10MS, UInt64(1000), UInt64(500))
    assert_true(v == UInt64(500), "single sample returns itself")
    assert_true(m.get() == UInt64(500), "get() returns same")
    print("PASS: test_minmax_single_sample")


def test_minmax_tracks_minimum() raises:
    var m = MinMax(window_us=WIN_10MS)
    _ = m.running_min(WIN_10MS, UInt64(1000), UInt64(100))
    _ = m.running_min(WIN_10MS, UInt64(2000), UInt64(200))
    _ = m.running_min(WIN_10MS, UInt64(3000), UInt64(300))
    assert_true(m.get() == UInt64(100), "min maintained across rising measurements")
    print("PASS: test_minmax_tracks_minimum")


def test_minmax_expires_old_samples() raises:
    var m = MinMax(window_us=WIN_10MS)
    _ = m.running_min(WIN_10MS, UInt64(1000), UInt64(100))
    # Advance past window (1000 + 10000 + 1 = 11001).
    var v = m.running_min(WIN_10MS, UInt64(12000), UInt64(250))
    assert_true(v == UInt64(250), "expired window adopts new minimum")
    print("PASS: test_minmax_expires_old_samples")


def test_minmax_constant_stream() raises:
    var m = MinMax(window_us=WIN_10MS)
    for i in range(5):
        var t = UInt64(i) * UInt64(1000)
        _ = m.running_min(WIN_10MS, t, UInt64(42))
    assert_true(m.get() == UInt64(42), "constant input returns constant min")
    print("PASS: test_minmax_constant_stream")


def main() raises:
    test_minmax_single_sample()
    test_minmax_tracks_minimum()
    test_minmax_expires_old_samples()
    test_minmax_constant_stream()
    print("All MinMax tests passed.")
