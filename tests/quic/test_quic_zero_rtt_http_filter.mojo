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
from tests._test_util import assert_true, assert_false


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


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    test_capabilities_is_early_data_defaults_false()
    test_capabilities_for_h3_accepts_is_early_data_kwarg()
    test_capabilities_for_h1_h2_default_is_early_data_false()
    print("test_quic_zero_rtt_http_filter: all tests passed")
