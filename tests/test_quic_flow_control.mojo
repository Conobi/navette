# tests/test_quic_flow_control.mojo
# Tests for FlowControl: dual-counter flow control tracker (RFC 9000 §4).

from tests._test_util import assert_true
from mojo_net.quic.flow_control import FlowControl


def test_initial_state() raises:
    var fc = FlowControl(limit=1048576, window=1048576)
    assert_true(fc.available() == 1048576, "initial available")
    assert_true(not fc.should_update(), "should not update initially")
    assert_true(fc.check_limit(100), "can receive 100 bytes")
    print("PASS: test_initial_state")


def test_add_received_and_available() raises:
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(600)
    assert_true(fc.available() == 400, "available after 600 received")
    fc.add_received(400)
    assert_true(fc.available() == 0, "available after 1000 received")
    print("PASS: test_add_received_and_available")


def test_check_limit_enforcement() raises:
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(900)
    assert_true(fc.check_limit(100), "exactly at limit")
    assert_true(not fc.check_limit(101), "over limit by 1")
    print("PASS: test_check_limit_enforcement")


def test_should_update_threshold() raises:
    var fc = FlowControl(limit=1000, window=1000)
    assert_true(not fc.should_update(), "no update at start")
    fc.add_consumed(400)
    assert_true(not fc.should_update(), "no update at 400 consumed (remaining=600 > 333)")
    fc.add_consumed(268)  # total=668, remaining=332 < window//3=333
    assert_true(fc.should_update(), "should update at 668 consumed (remaining=332 < 333)")
    print("PASS: test_should_update_threshold")


def test_update_limit() raises:
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_consumed(600)
    var new_limit = fc.update_limit()
    assert_true(new_limit == 1600, "new limit is 1600")
    assert_true(not fc.should_update(), "should not update after update_limit")
    print("PASS: test_update_limit")


def test_ensure_limit_monotonic() raises:
    var fc = FlowControl(limit=1000, window=1000)
    fc.ensure_limit(2000)
    assert_true(fc.available() == 2000, "limit raised to 2000")
    fc.ensure_limit(1500)
    assert_true(fc.available() == 2000, "limit not lowered")
    fc.ensure_limit(3000)
    assert_true(fc.available() == 3000, "limit raised to 3000")
    print("PASS: test_ensure_limit_monotonic")


def test_received_consumed_split() raises:
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_received(800)
    fc.add_consumed(200)
    assert_true(fc.available() == 200, "available based on received")
    assert_true(not fc.should_update(), "should_update based on consumed (remaining=800)")
    fc.add_consumed(468)  # total=668, remaining=332 < 333
    assert_true(fc.should_update(), "should_update triggers at consumed threshold")
    print("PASS: test_received_consumed_split")


def test_phantom_bytes() raises:
    var fc = FlowControl(limit=10485760, window=10485760)
    fc.add_received(500)
    fc.add_consumed(200)
    var phantom = UInt64(4500)
    fc.add_received(phantom)
    fc.add_consumed(phantom)
    assert_true(fc.received == 5000, "received accounts for phantom")
    assert_true(fc.consumed == 4700, "consumed accounts for phantom")
    print("PASS: test_phantom_bytes")


def test_blocked_at_tracking() raises:
    var fc = FlowControl(limit=1000, window=1000)
    assert_true(fc.blocked_at == 0, "not blocked initially")
    fc.blocked_at = fc.limit
    assert_true(fc.blocked_at == 1000, "blocked at limit")
    print("PASS: test_blocked_at_tracking")


def test_should_update_no_underflow() raises:
    """Guard: should_update() must not wrap on UInt64 when consumed >= limit."""
    # consumed == limit: remaining would be 0, which is < window//2, so True
    var fc = FlowControl(limit=500, window=1000)
    fc.add_consumed(500)
    assert_true(fc.should_update(), "should update when consumed == limit")

    # consumed > limit (pathological / bug state): without the guard this would
    # wrap to a huge UInt64 and return False incorrectly.
    var fc2 = FlowControl(limit=500, window=1000)
    fc2.add_consumed(600)  # consumed > limit
    assert_true(fc2.should_update(), "should update when consumed > limit (no underflow)")
    print("PASS: test_should_update_no_underflow")


def test_fc_doubles_on_update() raises:
    var fc = FlowControl(limit=1000000, window=1000000, max_window=8000000)
    fc.add_consumed(700000)  # remaining=300000 < 1000000//3=333333 → should_update=True
    assert_true(fc.should_update(), "should update at 700000 consumed")
    var new_limit = fc.update_limit()
    assert_true(fc.window == 2000000, "window doubled to 2 MiB equivalent")
    assert_true(new_limit == 2700000, "new_limit = consumed + new_window = 700000 + 2000000")
    assert_true(not fc.should_update(), "no update immediately after update_limit")
    print("PASS: test_fc_doubles_on_update")


def test_fc_doubles_to_cap() raises:
    var fc = FlowControl(limit=1000000, window=1000000, max_window=4000000)
    # Force multiple updates to hit cap
    fc.add_consumed(700000)
    _ = fc.update_limit()  # window: 1M → 2M, limit = 700000+2M = 2700000
    assert_true(fc.window == 2000000, "window 2M after first update")
    fc.add_consumed(2000000)  # total=2700000, remaining=0 → should_update
    assert_true(fc.should_update(), "should update when consumed reaches new limit")
    _ = fc.update_limit()  # window: 2M → 4M (cap), limit = 2700000+4M = 6700000
    assert_true(fc.window == 4000000, "window 4M after second update (at cap)")
    fc.add_consumed(3000000)  # force another update opportunity
    _ = fc.update_limit()  # window: stays at 4M (already at cap)
    assert_true(fc.window == 4000000, "window stays at cap on subsequent updates")
    print("PASS: test_fc_doubles_to_cap")


def test_fc_no_growth_without_max_window() raises:
    # FlowControl(limit, window) without max_window → max_window defaults to window → no growth
    var fc = FlowControl(limit=1000, window=1000)
    fc.add_consumed(668)
    assert_true(fc.should_update(), "should update at 668 consumed")
    var new_limit = fc.update_limit()
    assert_true(fc.window == 1000, "window unchanged when max_window == window")
    assert_true(new_limit == 1668, "new_limit = consumed + window = 668 + 1000")
    print("PASS: test_fc_no_growth_without_max_window")


def main() raises:
    test_initial_state()
    test_add_received_and_available()
    test_check_limit_enforcement()
    test_should_update_threshold()
    test_update_limit()
    test_ensure_limit_monotonic()
    test_received_consumed_split()
    test_phantom_bytes()
    test_blocked_at_tracking()
    test_should_update_no_underflow()
    test_fc_doubles_on_update()
    test_fc_doubles_to_cap()
    test_fc_no_growth_without_max_window()
    print("All flow_control tests passed.")
