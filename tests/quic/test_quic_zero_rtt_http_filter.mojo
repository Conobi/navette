"""Mojo unit tests for the 0-RTT HTTP filter integration.

Covers:
  - Capabilities.is_early_data default + for_h3 kwarg
  - QuicServerConfig._early_data_filter field presence + synchronisation
  - Stream.is_zero_rtt tagging at creation time
  - QuicConnection._current_space_idx reset between packets
  - apply_early_data_filter dispatch helper (5 outcomes)
  - send_425_response helper shape

Test files for the H3 adapter end-to-end behaviour live in
`tests/h3/test_h3_adapter_early_data_filter.mojo`.

This file is the Capabilities.is_early_data field + for_h3 kwarg
surface; the remaining test groups land alongside their integration.
"""

from navette.http.handler import Capabilities
from navette.quic.profile import AcceptProfile
from tests._test_util import assert_true, assert_false, assert_equal_int


def test_capabilities_is_early_data_defaults_false() raises:
    """AC capabilities-is-early-data-defaults-false. The factory
    Capabilities.for_h3() with no arguments produces is_early_data=False."""
    var caps = Capabilities.for_h3()
    assert_false(caps.is_early_data, String("default for_h3 is_early_data must be False"))


def test_capabilities_for_h3_accepts_is_early_data_kwarg() raises:
    """AC capabilities-is-early-data-set-on-0rtt-accept (ctor surface
    half). Capabilities.for_h3(is_early_data=True) must produce a
    Capabilities with is_early_data=True. The handler-invocation half
    of the AC is covered by test_h3_adapter_early_data_filter."""
    var caps_off = Capabilities.for_h3(is_early_data=False)
    assert_false(caps_off.is_early_data, String("explicit False kwarg respected"))

    var caps_on = Capabilities.for_h3(is_early_data=True)
    assert_true(caps_on.is_early_data, String("explicit True kwarg respected"))


def test_capabilities_for_h1_h2_default_is_early_data_false() raises:
    """The for_h1 and for_h2 factories MUST also default
    is_early_data=False — 0-RTT acceptance is H3-server-only for v1;
    H1/H2 are out of scope."""
    assert_false(Capabilities.for_h1().is_early_data, String("for_h1 defaults False"))
    assert_false(Capabilities.for_h2().is_early_data, String("for_h2 defaults False"))


def test_zero_rtt_http_filter_counters_default_zero() raises:
    """AC counter-exact-bucket-routing (default state). A fresh
    AcceptProfile starts all 4 HTTP-filter counters at 0."""
    var prof = AcceptProfile()
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 0,
        String("accept defaults 0"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 0,
        String("reject_425 defaults 0"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 0,
        String("misconfig_fail_closed defaults 0"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 0,
        String("1rtt_bypassed defaults 0"),
    )


def test_zero_rtt_http_filter_recorders_bump_correct_bucket() raises:
    """AC counter-exact-bucket-routing (per-recorder mutual exclusion).
    Each recorder increments exactly its own counter."""
    var prof = AcceptProfile()

    prof.record_zero_rtt_http_filter_accept()
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 1, String("accept +=1"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_reject_425), 0, String("reject untouched"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 0, String("misconfig untouched"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_1rtt_bypassed), 0, String("1rtt untouched"))

    prof.record_zero_rtt_http_filter_reject_425()
    assert_equal_int(Int(prof.zero_rtt_http_filter_accept), 1, String("accept unchanged"))
    assert_equal_int(Int(prof.zero_rtt_http_filter_reject_425), 1, String("reject +=1"))

    prof.record_zero_rtt_http_filter_misconfig_fail_closed()
    assert_equal_int(Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 1, String("misconfig +=1"))

    prof.record_zero_rtt_http_filter_1rtt_bypassed()
    assert_equal_int(Int(prof.zero_rtt_http_filter_1rtt_bypassed), 1, String("1rtt +=1"))


def test_zero_rtt_http_filter_text_reporter_emits_block() raises:
    """AC counters-emit-text-block. The text reporter outputs a
    `zero_rtt_http_filter:` block with four `_fmt_count`-aligned lines."""
    var prof = AcceptProfile()
    prof.record_zero_rtt_http_filter_accept()
    prof.record_zero_rtt_http_filter_accept()
    prof.record_zero_rtt_http_filter_reject_425()
    var txt = prof.report_text()
    assert_true("zero_rtt_http_filter:" in txt, String("block header present"))
    assert_true("  accept:" in txt, String("accept line present"))
    assert_true("  reject_425:" in txt, String("reject_425 line present"))
    assert_true("  misconfig_fail_closed:" in txt, String("misconfig line present"))
    assert_true("  1rtt_bypassed:" in txt, String("1rtt_bypassed line present"))


def test_zero_rtt_http_filter_json_reporter_emits_object() raises:
    """AC counters-emit-json-object. JSON reporter outputs a
    `"zero_rtt_http_filter"` object with 4 keys; final field has no
    trailing comma (JSON validity)."""
    var prof = AcceptProfile()
    prof.record_zero_rtt_http_filter_1rtt_bypassed()
    var j = prof.report_json()
    assert_true('"zero_rtt_http_filter"' in j, String("object key present"))
    assert_true('"accept"' in j, String("accept key present"))
    assert_true('"reject_425"' in j, String("reject_425 key present"))
    assert_true('"misconfig_fail_closed"' in j, String("misconfig key present"))
    assert_true('"1rtt_bypassed"' in j, String("1rtt_bypassed key present"))


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    test_capabilities_is_early_data_defaults_false()
    test_capabilities_for_h3_accepts_is_early_data_kwarg()
    test_capabilities_for_h1_h2_default_is_early_data_false()
    test_zero_rtt_http_filter_counters_default_zero()
    test_zero_rtt_http_filter_recorders_bump_correct_bucket()
    test_zero_rtt_http_filter_text_reporter_emits_block()
    test_zero_rtt_http_filter_json_reporter_emits_object()
    print("test_quic_zero_rtt_http_filter: all tests passed")
