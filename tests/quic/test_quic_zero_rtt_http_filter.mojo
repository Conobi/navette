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

from std.collections import Optional
from std.memory import Span, UnsafePointer

from navette.h3.connection import H3Connection
from navette.h3.early_data_filter_dispatch import (
    FilterDispatchOutcome,
    apply_early_data_filter,
    send_425_response,
)
from navette.http.handler import Capabilities
from navette.http.headers import Headers
from navette.quic.connection import QuicConnection
from navette.quic.frame import StreamFrame
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.profile import AcceptProfile
from navette.quic.stream import Stream
from navette.quic.trans_param import default_transport_params
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import IdempotentOnlyFilter
from navette.tls.lib import TlsBackend
from tests._test_util import (
    assert_true,
    assert_false,
    assert_equal_int,
    load_test_cert,
)


def _splitmix64(mut state: UInt64) -> UInt64:
    """Inline SplitMix64 step. Mirrors `tests/fuzz/lib/prng.mojo` to
    avoid pulling the full PRNG dependency into the http-filter test
    file (`tests/fuzz/lib/` requires a Python import that this test
    family does not need)."""
    state = state + UInt64(0x9E3779B97F4A7C15)
    var z = state
    z = (z ^ (z >> UInt64(30))) * UInt64(0xBF58476D1CE4E5B9)
    z = (z ^ (z >> UInt64(27))) * UInt64(0x94D049BB133111EB)
    return z ^ (z >> UInt64(31))


def _make_filter_ptr_some(
    mut filter: IdempotentOnlyFilter,
) -> Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]]:
    """Return Some(ptr) wrapping a stack-rooted filter. Caller MUST
    keep `filter` alive past the helper call."""
    return Optional[UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]](
        UnsafePointer(to=filter)
    )


def _make_profile_ptr_some(
    mut prof: AcceptProfile,
) -> Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]]:
    """Return Some(ptr) wrapping a stack-rooted AcceptProfile."""
    return Optional[UnsafePointer[AcceptProfile, MutAnyOrigin]](
        UnsafePointer(to=prof)
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


def test_filter_helper_1rtt_proceeds_no_injection() raises:
    """AC filter-helper-1rtt-proceeds-no-injection."""
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var fp = _make_filter_ptr_some(filter)
    var pp = _make_profile_ptr_some(prof)
    var headers = Headers()

    var outcome = apply_early_data_filter(
        String("POST"), False, fp, headers, pp,
    )
    assert_true(outcome.should_proceed(), String("1-RTT must proceed"))
    assert_false(
        headers.has(String("early-data")),
        String("no Early-Data injection on 1-RTT"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 1,
        String("1rtt_bypassed += 1"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 0,
        String("accept untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 0,
        String("reject untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 0,
        String("misconfig untouched"),
    )
    _ = filter
    _ = prof


def test_filter_helper_0rtt_get_injects_and_proceeds() raises:
    """AC filter-helper-0rtt-get-injects-and-proceeds."""
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var fp = _make_filter_ptr_some(filter)
    var pp = _make_profile_ptr_some(prof)
    var headers = Headers()

    var outcome = apply_early_data_filter(
        String("GET"), True, fp, headers, pp,
    )
    assert_true(outcome.should_proceed(), String("0-RTT GET must proceed"))
    assert_true(
        headers.has(String("early-data")),
        String("Early-Data header injected"),
    )
    var got = headers.get(String("early-data"))
    assert_true(
        got == String("1"),
        String("Early-Data value is '1'"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 1,
        String("accept += 1"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 0,
        String("1rtt untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 0,
        String("reject untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 0,
        String("misconfig untouched"),
    )
    _ = filter
    _ = prof


def test_filter_helper_0rtt_post_emits_425() raises:
    """AC filter-helper-0rtt-post-emits-425."""
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var fp = _make_filter_ptr_some(filter)
    var pp = _make_profile_ptr_some(prof)
    var headers = Headers()

    var outcome = apply_early_data_filter(
        String("POST"), True, fp, headers, pp,
    )
    assert_true(
        outcome.should_send_425(), String("0-RTT POST must reject"),
    )
    assert_false(
        headers.has(String("early-data")),
        String("no header on reject"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 1,
        String("reject_425 += 1"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 0,
        String("accept untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 0,
        String("1rtt untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 0,
        String("misconfig untouched"),
    )
    _ = filter
    _ = prof


def test_filter_helper_0rtt_filter_none_fails_closed() raises:
    """AC filter-helper-0rtt-filter-none-fails-closed.

    Even GET fails-closed when filter_ptr is None on a 0-RTT request."""
    var prof = AcceptProfile()
    var pp = _make_profile_ptr_some(prof)
    var headers = Headers()
    var none_ptr: Optional[
        UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
    ] = None

    var outcome = apply_early_data_filter(
        String("GET"), True, none_ptr, headers, pp,
    )
    assert_true(
        outcome.should_send_425(),
        String("filter_ptr=None must fail-closed even on GET"),
    )
    assert_false(
        headers.has(String("early-data")),
        String("no header on fail-closed"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_misconfig_fail_closed), 1,
        String("misconfig_fail_closed += 1"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_accept), 0,
        String("accept untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_reject_425), 0,
        String("reject untouched"),
    )
    assert_equal_int(
        Int(prof.zero_rtt_http_filter_1rtt_bypassed), 0,
        String("1rtt untouched"),
    )
    _ = prof


def test_filter_helper_counter_mutual_exclusion() raises:
    """AC filter-helper-counter-mutual-exclusion.

    Across 100 deterministic random triples, each call bumps exactly
    ONE counter; sum of deltas == call count."""
    var filter = IdempotentOnlyFilter()
    var prof = AcceptProfile()
    var fp = _make_filter_ptr_some(filter)
    var pp = _make_profile_ptr_some(prof)
    var state = UInt64(0xCAFEBABEC0DEFEED)
    var calls = 100
    for _ in range(calls):
        var headers = Headers()
        var r = _splitmix64(state)
        var is_zr = (r % UInt64(2)) == UInt64(1)
        var method_pick = Int(_splitmix64(state) % UInt64(4))
        var method: String
        if method_pick == 0:
            method = String("GET")
        elif method_pick == 1:
            method = String("POST")
        elif method_pick == 2:
            method = String("OPTIONS")
        else:
            method = String("PATCH")
        var none_or_some = _splitmix64(state) % UInt64(10)
        if none_or_some == UInt64(0) and is_zr:
            # Mostly Some; rare None for fail-closed coverage when 0-RTT.
            var none_ptr: Optional[
                UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
            ] = None
            _ = apply_early_data_filter(method, is_zr, none_ptr, headers, pp)
        else:
            _ = apply_early_data_filter(method, is_zr, fp, headers, pp)

    var total = (
        Int(prof.zero_rtt_http_filter_accept)
        + Int(prof.zero_rtt_http_filter_reject_425)
        + Int(prof.zero_rtt_http_filter_misconfig_fail_closed)
        + Int(prof.zero_rtt_http_filter_1rtt_bypassed)
    )
    assert_equal_int(
        total, calls,
        String("sum of bucket deltas equals call count"),
    )
    _ = filter
    _ = prof


def test_send_425_emits_status_only_fin() raises:
    """AC send-425-emits-status-only-fin.

    Drive send_425_response against a server-side H3Connection; assert
    the response stream has FIN queued. (Wire-bytes decode is not
    asserted here because QPACK-decode requires a paired decoder; the
    HEADERS-frame-with-`:status=425` content is covered downstream
    where a client-side connection is available.)"""
    var lib = TlsBackend("lib/librustls_mojo.so")
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=UInt32(0xFFFFFFFF),
    )
    var quic = _make_server_conn_for_tagging(lib, cfg)
    var h3 = H3Connection.server(quic^)

    # Synthesise a peer-initiated request stream the same way the
    # adapter would observe it. Set _current_space_idx so the stream
    # tag matches a real 0-RTT-arrived request (the field is reset
    # between packets by the dispatch loop in production).
    h3._quic._current_space_idx = ZERO_RTT_SPACE_IDX
    var probe = List[UInt8]()
    probe.append(UInt8(0x00))  # arbitrary
    var sf = StreamFrame(UInt64(0), UInt64(0), probe, False)
    h3._quic._handle_stream_frame(sf)

    send_425_response(UInt64(0), h3)

    # The send_stream_data path appends to the outgoing buffer; we
    # don't decode bytes here (QPACK-decode requires a paired
    # decoder). Instead we assert the side-effects observable on the
    # H3 layer: a buffer is queued with FIN set on stream 0.
    # `SendBuf.fin` is the post-send_stream_data invariant — the
    # `fin_offset` (frame-emission timestamp) is set only once
    # `make_frame` actually slices the FIN onto the wire, which
    # requires a flush pass that this test deliberately skips.
    var s = Stream(other=h3._quic.stream_map.streams[Int(0)])
    assert_true(
        s.send_buf is not None,
        String("send-side buffer must exist on the request stream"),
    )
    var sb = s.send_buf.value().copy()
    assert_true(
        sb.fin,
        String("FIN must be queued on the response stream"),
    )
    assert_true(
        len(sb.data) > 0,
        String("HEADERS frame bytes must be queued"),
    )
    _ = h3._quic.conn_handle
    _ = cfg._handle


def test_filter_dispatch_outcome_equality_and_helpers() raises:
    """The two FilterDispatchOutcome variants must satisfy variant
    identity (proceed != send_425; proceed == proceed) so callers can
    `==`-match without reaching into `kind`."""
    var p1 = FilterDispatchOutcome.proceed()
    var p2 = FilterDispatchOutcome.proceed()
    var r1 = FilterDispatchOutcome.send_425()
    assert_true(p1 == p2, String("proceed == proceed"))
    assert_true(p1 != r1, String("proceed != send_425"))
    assert_true(p1.should_proceed(), String("proceed.should_proceed"))
    assert_false(p1.should_send_425(), String("proceed not send_425"))
    assert_true(r1.should_send_425(), String("send_425.should_send_425"))
    assert_false(r1.should_proceed(), String("send_425 not proceed"))


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
    test_filter_helper_1rtt_proceeds_no_injection()
    test_filter_helper_0rtt_get_injects_and_proceeds()
    test_filter_helper_0rtt_post_emits_425()
    test_filter_helper_0rtt_filter_none_fails_closed()
    test_filter_helper_counter_mutual_exclusion()
    test_send_425_emits_status_only_fin()
    test_filter_dispatch_outcome_equality_and_helpers()
    print("test_quic_zero_rtt_http_filter: all tests passed")
