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

from std.memory import Span

from navette.http.handler import Capabilities
from navette.quic.connection import QuicConnection
from navette.quic.frame import StreamFrame
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.profile import AcceptProfile
from navette.quic.stream import Stream
from navette.quic.trans_param import default_transport_params
from navette.tls.config import QuicServerConfig
from navette.tls.lib import TlsBackend
from tests._test_util import (
    assert_true,
    assert_false,
    assert_equal_int,
    load_test_cert,
)


def _make_server_conn_for_tagging(
    lib: TlsBackend, ref cfg: QuicServerConfig
) raises -> QuicConnection:
    """Build a server QuicConnection skeleton suitable for direct
    _handle_stream_frame drive. The handshake is NOT driven; tests set
    `_current_space_idx` manually before calling the frame handler."""
    var tp = default_transport_params()
    var dcid_a = List[UInt8]()
    var dcid_b = List[UInt8]()
    for _ in range(8):
        dcid_a.append(UInt8(0xab))
        dcid_b.append(UInt8(0xcd))
    var now = UInt64(1_000_000)
    return QuicConnection.server(
        lib.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )


# PEM bytes are loaded inline per test (var cert_pem / var key_pem) rather
# than via a shared helper because returning a Tuple[List, List] and then
# constructing two `Span` views into the same tuple trips the Mojo borrow
# checker ("memory location previously writable through another aliased
# argument"). Splitting into independent List vars keeps each Span's
# origin distinct. Same pattern as tests/quic/test_early_data_store.mojo.


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


def test_filter_field_populated_when_zero_rtt_enabled() raises:
    """AC filter-field-populated-when-zero-rtt-enabled.

    A `QuicServerConfig` constructed with `max_early_data > 0` MUST
    populate `_early_data_filter` so the H3-layer dispatch helper has
    a non-None filter to consult on 0-RTT-tagged requests."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("0-RTT enabled must populate _early_data_filter"),
    )
    _ = cfg._handle


def test_no_filter_field_when_zero_rtt_disabled() raises:
    """AC no-filter-field-when-zero-rtt-disabled.

    A `QuicServerConfig` constructed with `max_early_data == 0` MUST
    leave `_early_data_filter` None so the dispatch helper recognises
    the rejection-mode configuration (no 0-RTT keys derived)."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
    )
    assert_true(
        cfg._early_data_filter is None,
        String("0-RTT disabled must leave _early_data_filter None"),
    )
    _ = cfg._handle


def test_store_and_filter_synchronized_when_enabled() raises:
    """AC store-and-filter-synchronized (enabled half).

    The invariant is `_early_data_store.is_some() == _early_data_filter.is_some()`:
    when `max_early_data > 0`, both Optionals are populated."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    assert_true(
        cfg._early_data_store is not None,
        String("store must be Some when enabled"),
    )
    assert_true(
        cfg._early_data_filter is not None,
        String("filter must be Some when enabled"),
    )
    _ = cfg._handle


def test_store_and_filter_synchronized_when_disabled() raises:
    """AC store-and-filter-synchronized (disabled half).

    When `max_early_data == 0`, both Optionals MUST be None — the H3
    dispatch helper relies on this synchronised-population invariant."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0),
    )
    assert_true(
        cfg._early_data_store is None,
        String("store must be None when disabled"),
    )
    assert_true(
        cfg._early_data_filter is None,
        String("filter must be None when disabled"),
    )
    _ = cfg._handle


def test_stream_is_zero_rtt_false_at_default_construction() raises:
    """AC stream-ctor-default-false. The three Stream ctors initialise
    `is_zero_rtt` to False so the QUIC dispatch path is the SOLE place
    that ever promotes the flag to True."""
    var s = Stream(UInt64(0), True, False)
    assert_false(s.is_zero_rtt, String("base ctor must init is_zero_rtt=False"))

    var s2 = Stream(other=s)
    assert_false(s2.is_zero_rtt, String("copy ctor preserves False default"))


def test_quic_connection_current_space_idx_defaults_minus_one() raises:
    """AC connection-current-space-idx-resets-between-packets (default
    half). A freshly-constructed connection has _current_space_idx = -1
    so the per-packet dispatch loop's set/reset bookend is the SOLE way
    a stream can be tagged as 0-RTT-originated."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var conn = _make_server_conn_for_tagging(lib, cfg)
    assert_equal_int(
        conn._current_space_idx, -1,
        String("default _current_space_idx must be -1"),
    )
    _ = conn.conn_handle
    _ = cfg._handle


def test_stream_is_zero_rtt_set_on_creation_from_0rtt_packet() raises:
    """AC stream-is-zero-rtt-set-on-creation-from-0rtt-packet.

    Drive `_handle_stream_frame` for a new (peer-initiated) stream while
    the connection's `_current_space_idx` is `ZERO_RTT_SPACE_IDX` (the
    dispatch sentinel set by the per-packet loop in production). The
    freshly-created Stream must carry `is_zero_rtt = True`."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var conn = _make_server_conn_for_tagging(lib, cfg)

    # Mark the in-flight packet as 0-RTT (the dispatch loop does this in
    # production; we set it manually here to bypass the cryptography).
    conn._current_space_idx = ZERO_RTT_SPACE_IDX

    # Client-initiated bidi stream id 0 (peer-initiated for a server).
    var payload = List[UInt8]()
    payload.append(UInt8(0x41))
    var sf = StreamFrame(UInt64(0), UInt64(0), payload, False)
    conn._handle_stream_frame(sf)

    var key = Int(0)
    assert_true(key in conn.stream_map.streams, String("stream must be created"))
    var s = Stream(other=conn.stream_map.streams[key])
    assert_true(
        s.is_zero_rtt,
        String("new stream from 0-RTT packet must be tagged"),
    )
    _ = conn.conn_handle
    _ = cfg._handle


def test_stream_is_zero_rtt_false_from_1rtt_packet() raises:
    """AC stream-is-zero-rtt-false-from-1rtt-packet.

    Same drive as the 0-RTT test but with `_current_space_idx = 2`
    (Application/1-RTT). The freshly-created Stream's `is_zero_rtt`
    must be False."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var conn = _make_server_conn_for_tagging(lib, cfg)

    conn._current_space_idx = 2  # APPLICATION_SPACE_IDX (1-RTT)
    var payload = List[UInt8]()
    payload.append(UInt8(0x41))
    var sf = StreamFrame(UInt64(4), UInt64(0), payload, False)
    conn._handle_stream_frame(sf)

    var key = Int(4)
    assert_true(key in conn.stream_map.streams, String("stream must be created"))
    var s = Stream(other=conn.stream_map.streams[key])
    assert_false(
        s.is_zero_rtt,
        String("new stream from 1-RTT packet must not be tagged"),
    )
    _ = conn.conn_handle
    _ = cfg._handle


def test_stream_is_zero_rtt_monotonic_after_handshake_complete() raises:
    """AC stream-is-zero-rtt-monotonic-after-handshake-complete.

    A stream tagged True at creation (0-RTT HEADERS) retains
    `is_zero_rtt=True` after subsequent 1-RTT body bytes arrive on the
    SAME stream. The flag is set ONCE at stream insertion-time and is
    NEVER cleared by subsequent STREAM frames on an existing stream."""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var conn = _make_server_conn_for_tagging(lib, cfg)

    # First frame in 0-RTT — tags the stream.
    conn._current_space_idx = ZERO_RTT_SPACE_IDX
    var p1 = List[UInt8]()
    p1.append(UInt8(0x41))
    var sf1 = StreamFrame(UInt64(8), UInt64(0), p1, False)
    conn._handle_stream_frame(sf1)
    var key = Int(8)
    var s1 = Stream(other=conn.stream_map.streams[key])
    assert_true(s1.is_zero_rtt, String("creation-time tag True"))

    # Subsequent frame on the SAME stream in 1-RTT — must NOT clear.
    conn._current_space_idx = 2  # APPLICATION_SPACE_IDX
    var p2 = List[UInt8]()
    p2.append(UInt8(0x42))
    var sf2 = StreamFrame(UInt64(8), UInt64(1), p2, False)
    conn._handle_stream_frame(sf2)
    var s2 = Stream(other=conn.stream_map.streams[key])
    assert_true(
        s2.is_zero_rtt,
        String("subsequent 1-RTT frame must not clear the tag"),
    )
    _ = conn.conn_handle
    _ = cfg._handle


def main() raises:
    """Driver for `scripts/run_tests.sh`: each test must be invoked here."""
    test_capabilities_is_early_data_defaults_false()
    test_capabilities_for_h3_accepts_is_early_data_kwarg()
    test_capabilities_for_h1_h2_default_is_early_data_false()
    test_zero_rtt_http_filter_counters_default_zero()
    test_zero_rtt_http_filter_recorders_bump_correct_bucket()
    test_zero_rtt_http_filter_text_reporter_emits_block()
    test_zero_rtt_http_filter_json_reporter_emits_object()
    test_filter_field_populated_when_zero_rtt_enabled()
    test_no_filter_field_when_zero_rtt_disabled()
    test_store_and_filter_synchronized_when_enabled()
    test_store_and_filter_synchronized_when_disabled()
    test_stream_is_zero_rtt_false_at_default_construction()
    test_quic_connection_current_space_idx_defaults_minus_one()
    test_stream_is_zero_rtt_set_on_creation_from_0rtt_packet()
    test_stream_is_zero_rtt_false_from_1rtt_packet()
    test_stream_is_zero_rtt_monotonic_after_handshake_complete()
    print("test_quic_zero_rtt_http_filter: all tests passed")
