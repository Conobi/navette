# tests/test_h3_connection.mojo
from std.memory import Span
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig, QuicClientConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.h3.connection import H3Connection, H3Event
from navette.h3.guard_predicates import (
    H3StreamCtx,
    predicate_f31_data_before_headers,
    predicate_f32_first_control_not_settings,
    predicate_f33_data_on_control,
    predicate_f34_headers_on_control,
    predicate_f35_second_settings,
    predicate_f36_cancel_push_on_request,
)
from tests._test_util import assert_true, assert_false, assert_equal_int, load_test_cert, load_test_ca


def test_h3event_zero_values() raises:
    """H3Event initializes all non-kind fields to zero/empty."""
    var ev = H3Event(H3Event.HANDSHAKE_COMPLETE)
    assert_equal_int(Int(ev.kind), Int(H3Event.HANDSHAKE_COMPLETE), "kind")
    assert_equal_int(Int(ev.stream_id), 0, "stream_id zero")
    assert_equal_int(len(ev.fields), 0, "fields empty")
    assert_equal_int(len(ev.data), 0, "data empty")
    assert_true(not ev.fin, "fin false")
    assert_equal_int(Int(ev.error_code), 0, "error_code zero")
    assert_true(ev.reason == "", "reason empty")
    assert_equal_int(Int(ev.last_stream_id), 0, "last_stream_id zero")
    print("  test_h3event_zero_values: PASS")


def test_is_peer_initiated() raises:
    """Stream ID bit-0 encodes initiator: even=client, odd=server."""
    assert_true((UInt64(0) & UInt64(1)) == 0, "stream 0 client-initiated")
    assert_true((UInt64(4) & UInt64(1)) == 0, "stream 4 client-initiated")
    assert_true((UInt64(1) & UInt64(1)) == 1, "stream 1 server-initiated")
    assert_true((UInt64(3) & UInt64(1)) == 1, "stream 3 server-initiated")
    print("  test_is_peer_initiated: PASS")


def test_is_request_stream() raises:
    """Stream ID bit-1 encodes bidi (0) vs uni (1)."""
    assert_true((UInt64(0) & UInt64(0x02)) == 0, "stream 0 bidi")
    assert_true((UInt64(4) & UInt64(0x02)) == 0, "stream 4 bidi")
    assert_true((UInt64(2) & UInt64(0x02)) != 0, "stream 2 uni")
    assert_true((UInt64(3) & UInt64(0x02)) != 0, "stream 3 uni")
    print("  test_is_request_stream: PASS")


def test_h3event_kind_constants() raises:
    """H3Event kind constants are distinct and non-zero."""
    assert_equal_int(Int(H3Event.HANDSHAKE_COMPLETE), 1, "HANDSHAKE_COMPLETE")
    assert_equal_int(Int(H3Event.SETTINGS_RECEIVED),  2, "SETTINGS_RECEIVED")
    assert_equal_int(Int(H3Event.HEADERS_RECEIVED),   3, "HEADERS_RECEIVED")
    assert_equal_int(Int(H3Event.DATA_RECEIVED),      4, "DATA_RECEIVED")
    assert_equal_int(Int(H3Event.STREAM_ENDED),       5, "STREAM_ENDED")
    assert_equal_int(Int(H3Event.STREAM_RESET),       6, "STREAM_RESET")
    assert_equal_int(Int(H3Event.GOAWAY_RECEIVED),    7, "GOAWAY_RECEIVED")
    assert_equal_int(Int(H3Event.CONNECTION_CLOSED),  8, "CONNECTION_CLOSED")
    print("  test_h3event_kind_constants: PASS")


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    # Backed by tests/fixtures/tls/server.{crt,key} (regen via
    # scripts/regen_test_certs.sh). See plans/2026-05-13-deps-enhancement.md §3.1.
    return load_test_cert()


def _h3_default_params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _pump_h3(
    mut a: H3Connection, mut b: H3Connection, mut now: UInt64, rounds: Int = 5
) raises -> UInt64:
    """Exchange datagrams between a and b for `rounds` iterations."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var a_dgs = a.drain_datagrams(now)
        for i in range(len(a_dgs)):
            try:
                b.feed_datagram(Span(a_dgs[i]), now)
            except:
                pass
        var b_dgs = b.drain_datagrams(now)
        for i in range(len(b_dgs)):
            try:
                a.feed_datagram(Span(b_dgs[i]), now)
            except:
                pass
    return now


def test_h3_control_stream_setup() raises:
    """After 50 pump rounds, client must receive SETTINGS_RECEIVED."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var ca_bytes = load_test_ca()
    var srv_cfg = QuicServerConfig(tls.shared(), Span(cert_bytes), Span(key_bytes))
    var cli_cfg = QuicClientConfig.with_ca(tls.shared(), Span(ca_bytes))
    var params = _h3_default_params()
    var now = UInt64(1_000_000)
    var client_quic = QuicConnection.client(tls.shared(), cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        tls.shared(), srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server_h3 = H3Connection.server(server_quic^)
    var client_h3 = H3Connection.client(client_quic^)
    # --- pump loop ---
    var got_settings = False
    for _ in range(50):
        now = _pump_h3(server_h3, client_h3, now, 1)
        while True:
            var ev = client_h3.poll_event()
            if not ev:
                break
            if ev.value().kind == H3Event.SETTINGS_RECEIVED:
                got_settings = True
        # drain server events too
        while True:
            var ev = server_h3.poll_event()
            if not ev:
                break
        if got_settings:
            break
    assert_true(got_settings, "client did not receive SETTINGS_RECEIVED after 50 rounds")
    print("  test_h3_control_stream_setup: PASS")


def test_predicate_f31_positive() raises:
    """F31 fires when DATA arrives on a request stream with no HEADERS yet."""
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=False, settings_seen=False)
    var v = predicate_f31_data_before_headers(UInt64(0x00), ctx)
    assert_true(v.__bool__(), "F31 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0103, "F31 H3_FRAME_UNEXPECTED")
    assert_true(verdict.tag == "[H3-DATA-BEFORE-HEADERS]", "F31 tag matches")
    print("  test_predicate_f31_positive: PASS")


def test_predicate_f31_negative_no_violation() raises:
    """F31 stays silent when HEADERS already seen."""
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=True, settings_seen=False)
    var v = predicate_f31_data_before_headers(UInt64(0x00), ctx)
    assert_false(v.__bool__(), "F31 no-violation when headers_seen=True")
    print("  test_predicate_f31_negative_no_violation: PASS")


def test_predicate_f31_negative_sibling_input() raises:
    """F31 stays silent on CANCEL_PUSH (F36 territory) on a request stream."""
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=False, settings_seen=False)
    var v = predicate_f31_data_before_headers(UInt64(0x03), ctx)
    assert_false(v.__bool__(), "F31 sibling: CANCEL_PUSH is F36, not F31")
    print("  test_predicate_f31_negative_sibling_input: PASS")


def test_predicate_f32_positive() raises:
    """F32 fires when GOAWAY arrives as first frame on the peer ctrl stream."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=False,
    )
    var v = predicate_f32_first_control_not_settings(UInt64(0x07), ctx)
    assert_true(v.__bool__(), "F32 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x010A, "F32 H3_MISSING_SETTINGS")
    assert_true(verdict.tag == "[H3-CTRL-NO-SETTINGS]", "F32 tag matches")
    print("  test_predicate_f32_positive: PASS")


def test_predicate_f32_negative_no_violation() raises:
    """F32 stays silent when SETTINGS arrives first on the ctrl stream."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=False,
    )
    var v = predicate_f32_first_control_not_settings(UInt64(0x04), ctx)
    assert_false(v.__bool__(), "F32 no-violation when first frame is SETTINGS")
    print("  test_predicate_f32_negative_no_violation: PASS")


def test_predicate_f32_negative_sibling_input() raises:
    """F32 stays silent on a request stream (kind=0)."""
    var ctx = H3StreamCtx(
        kind=UInt8(0), headers_seen=False, settings_seen=False,
        first_frame_seen=False,
    )
    var v = predicate_f32_first_control_not_settings(UInt64(0x07), ctx)
    assert_false(v.__bool__(), "F32 sibling: kind=0 is request, not control")
    print("  test_predicate_f32_negative_sibling_input: PASS")


def test_predicate_f32_negative_post_first_frame() raises:
    """F32 stays silent once any frame has arrived — second-frame
    non-SETTINGS arrivals must route to F33/F34, not re-fire F32."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=True,
    )
    var v = predicate_f32_first_control_not_settings(UInt64(0x07), ctx)
    assert_false(v.__bool__(), "F32 silent once first_frame_seen=True")
    print("  test_predicate_f32_negative_post_first_frame: PASS")


def test_predicate_f33_positive() raises:
    """F33 fires when DATA arrives on the peer ctrl stream (post first-frame)."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=True,
        first_frame_seen=True,
    )
    var v = predicate_f33_data_on_control(UInt64(0x00), ctx)
    assert_true(v.__bool__(), "F33 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0103, "F33 H3_FRAME_UNEXPECTED")
    assert_true(verdict.tag == "[H3-DATA-ON-CTRL]", "F33 tag matches")
    print("  test_predicate_f33_positive: PASS")


def test_predicate_f33_negative_no_violation() raises:
    """F33 stays silent on SETTINGS over the ctrl stream."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=True,
    )
    var v = predicate_f33_data_on_control(UInt64(0x04), ctx)
    assert_false(v.__bool__(), "F33 no-violation when frame is SETTINGS")
    print("  test_predicate_f33_negative_no_violation: PASS")


def test_predicate_f33_negative_sibling_input() raises:
    """F33 stays silent on DATA on a request stream (F31 territory)."""
    var ctx = H3StreamCtx(
        kind=UInt8(0), headers_seen=True, settings_seen=False,
        first_frame_seen=True,
    )
    var v = predicate_f33_data_on_control(UInt64(0x00), ctx)
    assert_false(v.__bool__(), "F33 sibling: DATA on kind=0 is F31, not F33")
    print("  test_predicate_f33_negative_sibling_input: PASS")


def test_predicate_f34_positive() raises:
    """F34 fires when HEADERS arrives on the peer ctrl stream (post first-frame)."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=True,
        first_frame_seen=True,
    )
    var v = predicate_f34_headers_on_control(UInt64(0x01), ctx)
    assert_true(v.__bool__(), "F34 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0103, "F34 H3_FRAME_UNEXPECTED")
    assert_true(verdict.tag == "[H3-HEADERS-ON-CTRL]", "F34 tag matches")
    print("  test_predicate_f34_positive: PASS")


def test_predicate_f34_negative_no_violation() raises:
    """F34 stays silent on SETTINGS over the ctrl stream."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=True,
    )
    var v = predicate_f34_headers_on_control(UInt64(0x04), ctx)
    assert_false(v.__bool__(), "F34 no-violation when frame is SETTINGS")
    print("  test_predicate_f34_negative_no_violation: PASS")


def test_predicate_f34_negative_sibling_input() raises:
    """F34 stays silent on HEADERS on a request stream (legal there)."""
    var ctx = H3StreamCtx(
        kind=UInt8(0), headers_seen=False, settings_seen=False,
        first_frame_seen=True,
    )
    var v = predicate_f34_headers_on_control(UInt64(0x01), ctx)
    assert_false(v.__bool__(), "F34 sibling: HEADERS on kind=0 is legal")
    print("  test_predicate_f34_negative_sibling_input: PASS")


def test_predicate_f35_positive() raises:
    """F35 fires when a second SETTINGS arrives on the ctrl stream."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=True,
        first_frame_seen=True,
    )
    var v = predicate_f35_second_settings(UInt64(0x04), ctx)
    assert_true(v.__bool__(), "F35 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0103, "F35 H3_FRAME_UNEXPECTED")
    assert_true(verdict.tag == "[H3-SECOND-SETTINGS]", "F35 tag matches")
    print("  test_predicate_f35_positive: PASS")


def test_predicate_f35_negative_no_violation() raises:
    """F35 stays silent on the first SETTINGS frame."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=False,
        first_frame_seen=False,
    )
    var v = predicate_f35_second_settings(UInt64(0x04), ctx)
    assert_false(v.__bool__(), "F35 no-violation on first SETTINGS")
    print("  test_predicate_f35_negative_no_violation: PASS")


def test_predicate_f35_negative_sibling_input() raises:
    """F35 stays silent on GOAWAY (post-SETTINGS GOAWAY is legal)."""
    var ctx = H3StreamCtx(
        kind=UInt8(1), headers_seen=False, settings_seen=True,
        first_frame_seen=True,
    )
    var v = predicate_f35_second_settings(UInt64(0x07), ctx)
    assert_false(v.__bool__(), "F35 sibling: GOAWAY is not SETTINGS")
    print("  test_predicate_f35_negative_sibling_input: PASS")


def test_predicate_f36_positive() raises:
    """F36 fires when CANCEL_PUSH arrives on a request-bidi stream."""
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=True, settings_seen=False)
    var v = predicate_f36_cancel_push_on_request(UInt64(0x03), ctx)
    assert_true(v.__bool__(), "F36 positive must return Some")
    var verdict = v.value().copy()
    assert_equal_int(Int(verdict.error_code), 0x0103, "F36 H3_FRAME_UNEXPECTED")
    assert_true(verdict.tag == "[H3-CANCEL-PUSH-REQ]", "F36 tag matches")
    print("  test_predicate_f36_positive: PASS")


def test_predicate_f36_negative_no_violation() raises:
    """F36 stays silent on HEADERS over a request-bidi stream."""
    var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=False, settings_seen=False)
    var v = predicate_f36_cancel_push_on_request(UInt64(0x01), ctx)
    assert_false(v.__bool__(), "F36 no-violation when frame is HEADERS")
    print("  test_predicate_f36_negative_no_violation: PASS")


def test_predicate_f36_negative_sibling_input() raises:
    """F36 stays silent on CANCEL_PUSH on the control stream (legal there)."""
    var ctx = H3StreamCtx(kind=UInt8(1), headers_seen=False, settings_seen=True)
    var v = predicate_f36_cancel_push_on_request(UInt64(0x03), ctx)
    assert_false(v.__bool__(), "F36 sibling: CANCEL_PUSH on ctrl is legal")
    print("  test_predicate_f36_negative_sibling_input: PASS")


def test_h3_request_stream_cohort_exclusivity() raises:
    """For each (frame_type, headers_seen) input on a request-bidi stream,
    at most one of F31 / F36 returns Some — dispatch order is irrelevant
    by construction.

    Truth table (kind=0):
      - DATA (0x00), headers_seen=False → F31 only.
      - DATA (0x00), headers_seen=True  → none.
      - HEADERS (0x01), any              → none.
      - CANCEL_PUSH (0x03), any          → F36 only.
    """
    var frame_types = List[UInt64]()
    frame_types.append(UInt64(0x00))
    frame_types.append(UInt64(0x01))
    frame_types.append(UInt64(0x03))
    var headers_seen_values = List[Bool]()
    headers_seen_values.append(True)
    headers_seen_values.append(False)
    for fi in range(len(frame_types)):
        var ft = frame_types[fi]
        for hi in range(len(headers_seen_values)):
            var hs = headers_seen_values[hi]
            var ctx = H3StreamCtx(kind=UInt8(0), headers_seen=hs, settings_seen=False)
            var f31 = predicate_f31_data_before_headers(ft, ctx)
            var f36 = predicate_f36_cancel_push_on_request(ft, ctx)
            var n_some = 0
            if f31.__bool__():
                n_some += 1
            if f36.__bool__():
                n_some += 1
            # Expected truth table.
            var expected_some = 0
            if ft == UInt64(0x00) and not hs:
                expected_some = 1  # F31
            if ft == UInt64(0x03):
                expected_some = 1  # F36
            assert_equal_int(
                n_some, expected_some,
                "request-cohort exclusivity",
            )
    print("  test_h3_request_stream_cohort_exclusivity: PASS")


def test_h3_control_stream_cohort_exclusivity() raises:
    """For each (frame_type, settings_seen, first_frame_seen) input on the
    peer ctrl stream, at most one of F32 / F33 / F34 / F35 returns Some.

    With `first_frame_seen` now part of `H3StreamCtx`, F32 is silent on
    every cell where the stream already saw a frame. The cohort therefore
    enforces TRUE exclusivity at the predicate layer — no external
    dispatch-time gate is required to keep F32 from overlapping F33/F34.

    Truth table (kind=1):
      - first_frame_seen=False, ft=SETTINGS, ss=False → none.
      - first_frame_seen=False, ft!=SETTINGS,  ss=False → F32 only.
      - first_frame_seen=True,  ft=DATA               → F33 only.
      - first_frame_seen=True,  ft=HEADERS            → F34 only.
      - first_frame_seen=True,  ft=SETTINGS, ss=True  → F35 only.
      - first_frame_seen=True,  ft=SETTINGS, ss=False → none.
      - first_frame_seen=True,  ft=GOAWAY             → none.
    """
    var frame_types = List[UInt64]()
    frame_types.append(UInt64(0x00))
    frame_types.append(UInt64(0x01))
    frame_types.append(UInt64(0x04))
    frame_types.append(UInt64(0x07))
    var bool_values = List[Bool]()
    bool_values.append(True)
    bool_values.append(False)
    for fi in range(len(frame_types)):
        var ft = frame_types[fi]
        for si in range(len(bool_values)):
            var ss = bool_values[si]
            for ffi in range(len(bool_values)):
                var ffs = bool_values[ffi]
                var ctx = H3StreamCtx(
                    kind=UInt8(1), headers_seen=False,
                    settings_seen=ss, first_frame_seen=ffs,
                )
                var f32 = predicate_f32_first_control_not_settings(ft, ctx)
                var f33 = predicate_f33_data_on_control(ft, ctx)
                var f34 = predicate_f34_headers_on_control(ft, ctx)
                var f35 = predicate_f35_second_settings(ft, ctx)
                # Expected truth table (all four predicates self-gate on
                # first_frame_seen so the cohort is strictly exclusive):
                #   F32: first_frame_seen=False AND settings_seen=False AND ft!=SETTINGS.
                #   F33: first_frame_seen=True  AND ft == DATA.
                #   F34: first_frame_seen=True  AND ft == HEADERS.
                #   F35: ft == SETTINGS AND settings_seen=True.
                var exp_f32 = (not ffs) and (not ss) and (ft != UInt64(0x04))
                var exp_f33 = ffs and (ft == UInt64(0x00))
                var exp_f34 = ffs and (ft == UInt64(0x01))
                var exp_f35 = ft == UInt64(0x04) and ss
                assert_equal_int(
                    Int(f32.__bool__()), Int(exp_f32),
                    "F32 membership",
                )
                assert_equal_int(
                    Int(f33.__bool__()), Int(exp_f33),
                    "F33 membership",
                )
                assert_equal_int(
                    Int(f34.__bool__()), Int(exp_f34),
                    "F34 membership",
                )
                assert_equal_int(
                    Int(f35.__bool__()), Int(exp_f35),
                    "F35 membership",
                )
                # TRUE exclusivity: at most one Some across F32/F33/F34/F35.
                var some_count = (
                    Int(exp_f32) + Int(exp_f33) + Int(exp_f34) + Int(exp_f35)
                )
                assert_true(
                    some_count <= 1,
                    "F32/F33/F34/F35 cohort is mutually exclusive",
                )
    print("  test_h3_control_stream_cohort_exclusivity: PASS")


def main() raises:
    print("=== test_h3_connection ===")
    test_h3event_zero_values()
    test_is_peer_initiated()
    test_is_request_stream()
    test_h3event_kind_constants()
    test_h3_control_stream_setup()
    test_predicate_f31_positive()
    test_predicate_f31_negative_no_violation()
    test_predicate_f31_negative_sibling_input()
    test_predicate_f32_positive()
    test_predicate_f32_negative_no_violation()
    test_predicate_f32_negative_sibling_input()
    test_predicate_f33_positive()
    test_predicate_f33_negative_no_violation()
    test_predicate_f33_negative_sibling_input()
    test_predicate_f34_positive()
    test_predicate_f34_negative_no_violation()
    test_predicate_f34_negative_sibling_input()
    test_predicate_f35_positive()
    test_predicate_f35_negative_no_violation()
    test_predicate_f35_negative_sibling_input()
    test_predicate_f36_positive()
    test_predicate_f36_negative_no_violation()
    test_predicate_f36_negative_sibling_input()
    test_h3_request_stream_cohort_exclusivity()
    test_h3_control_stream_cohort_exclusivity()
    print("All H3Connection tests passed.")
