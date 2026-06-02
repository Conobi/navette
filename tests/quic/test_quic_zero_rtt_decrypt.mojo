# tests/quic/test_quic_zero_rtt_decrypt.mojo
#
# 0-RTT decrypt path + reorder buffer property tests.
#
# Properties proven here (one test function each):
#   - decrypt-0rtt-stream (scoped to direct-dispatch)
#   - decrypt-0rtt-crypto-violates-f30
#   - lazy-install-on-first-detect (scoped to direct-counter-manipulation)
#   - buffer-respects-pkt-cap
#   - buffer-respects-byte-cap
#   - buffer-drains-on-keys-available (scoped to direct drain call)
#   - buffer-clears-on-handshake-complete
#   - buffer-clears-on-disconnect
#
# The F30 scenario binary exercises wire-format end-to-end; these unit
# tests cover the Mojo-side invariants. Tests scope down from full
# wire-format AEAD-encrypted 0-RTT packets to direct-dispatch /
# direct-buffer manipulation where the wire-format path requires
# AEAD encryption that the F30 scenario harness already covers.

from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection, QuicEvent
from navette.quic.frame import Frame, StreamFrame, CryptoFrame
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.guard_tags import GUARD_TAG_CRYPTO_IN_ZERO_RTT
from navette.quic.profile import AcceptProfile
from navette.quic.trans_param import default_transport_params
from tests._test_util import (
    assert_true, assert_false, assert_equal_int, load_test_cert,
)


def _synth_dcid() -> List[UInt8]:
    """Return the canonical RFC 9001 §A test DCID for synthetic key derivation.

    Returns:
        An 8-byte List with the canonical sample DCID.
    """
    var dcid: List[UInt8] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    return dcid^


def _make_server_conn(
    lib: TlsBackend, max_early_data: UInt32
) raises -> QuicConnection:
    """Construct a server QuicConnection with the given 0-RTT opt-in level.

    `max_early_data=UInt32(0xFFFFFFFF)` enables 0-RTT (rustls QUIC constraint
    per RFC 9001 §4.6.1); `UInt32(0)` keeps the connection in rejection mode.
    """
    var ck = load_test_cert()
    var cert_pem = ck[0].copy()
    var key_pem = ck[1].copy()
    var cfg = QuicServerConfig(
        lib.shared(), Span(cert_pem), Span(key_pem),
        max_early_data=max_early_data,
    )
    var tp = default_transport_params()
    var dcid_a = _synth_dcid()
    var dcid_b = _synth_dcid()
    var now = UInt64(1_000_000)
    return QuicConnection.server(
        lib.shared(), cfg, tp, Span(dcid_a), Span(dcid_b), now,
    )


def test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer() raises:
    """A STREAM frame dispatched with `space_idx=ZERO_RTT_SPACE_IDX` MUST
    reach `_handle_stream_frame` (not the F30 guard) and land in the
    per-stream recv_buf with FIN observed.

    Scope: direct dispatch via `_dispatch_frame` rather than driving an
    AEAD-encrypted 0-RTT packet through `recv_from_buffer`. The
    wire-format path is covered by the F30 scenario harness.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    assert_true(
        conn.zero_rtt_enabled,
        "zero_rtt_enabled must be True when max_early_data != 0",
    )

    # Client-initiated bidi stream id 0 — legal peer stream on a server.
    var sid = UInt64(0)
    var payload: List[UInt8] = [
        UInt8(0x68), UInt8(0x65), UInt8(0x6c), UInt8(0x6c), UInt8(0x6f),
    ]  # b"hello"
    var sf = StreamFrame(sid, UInt64(0), payload, True)
    var frame = Frame.stream(sf)

    var now = UInt64(2_000_000)
    conn._dispatch_frame(frame, ZERO_RTT_SPACE_IDX, now)

    # The F30 guard must NOT fire for STREAM in 0-RTT — connection still alive.
    assert_false(
        Bool(conn.pending_close),
        "STREAM in 0-RTT must NOT trip the F30 guard",
    )

    # Per-stream recv_buf received the bytes; FIN observed.
    var key = Int(sid)
    assert_true(
        key in conn.stream_map.streams,
        "stream 0 must be created on the server after 0-RTT STREAM dispatch",
    )
    var stream = conn.stream_map.get_stream(key)
    assert_true(stream.recv_buf.__bool__(), "stream 0 must have a recv_buf")
    assert_true(stream.fin_offset.__bool__(), "fin_offset must be set after FIN")
    assert_equal_int(
        Int(stream.fin_offset.value()), 5,
        "fin_offset must equal payload length",
    )
    # Extend conn lifetime past the assertion section so ASAP-destruction
    # doesn't fire __del__ during the stream_map read.
    _ = conn.is_server
    print("  test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer: PASS")


def test_decrypt_zero_rtt_crypto_trips_f30_guard() raises:
    """A CRYPTO frame dispatched with `space_idx=ZERO_RTT_SPACE_IDX` MUST
    trip the F30 guard (RFC 9001 §8.3) — the connection enters CLOSING
    with PROTOCOL_VIOLATION (0x0A) and the [QUIC-CRYPTO-IN-0RTT] tag.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var data: List[UInt8] = [UInt8(0x16), UInt8(0x03), UInt8(0x03)]
    var cf = CryptoFrame(UInt64(0), data)
    var frame = Frame.crypto(cf)

    var now = UInt64(2_000_000)
    conn._dispatch_frame(frame, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn.pending_close),
        "F30 guard must fire — pending_close must be set",
    )
    var cc = conn.pending_close.value().copy()
    assert_equal_int(
        Int(cc.error_code), 0x0A,
        "F30 closes with PROTOCOL_VIOLATION (0x0A)",
    )
    assert_true(cc.is_transport, "F30 emits a transport-CC frame")

    var reason_str = String("")
    for i in range(len(cc.reason)):
        reason_str = reason_str + chr(Int(cc.reason[i]))
    assert_true(
        String(GUARD_TAG_CRYPTO_IN_ZERO_RTT) in reason_str,
        "F30 reason carries [QUIC-CRYPTO-IN-0RTT]; got " + reason_str,
    )
    _ = conn.is_server
    print("  test_decrypt_zero_rtt_crypto_trips_f30_guard: PASS")


def test_lazy_install_success_counter_increments_once_per_install() raises:
    """`AcceptProfile.record_zero_rtt_install` accumulates SUCCESS into
    `zero_rtt_install_successes` and FAILURE into `zero_rtt_install_attempts`.

    Scope: PROFILE_ACCEPT is a `comptime` flag that is False at unit-test
    build time, so the production install site's counter call is
    dead-stripped. This test exercises the counter mechanism directly
    via a synthetic AcceptProfile — the lazy-install invariant under
    test is "exactly one SUCCESS per connection lifecycle".
    """
    var prof = AcceptProfile()
    assert_equal_int(
        Int(prof.zero_rtt_install_attempts), 0,
        "attempts must start at 0",
    )
    assert_equal_int(
        Int(prof.zero_rtt_install_successes), 0,
        "successes must start at 0",
    )

    # Simulate two failed lazy-install attempts followed by one success
    # (the wire-format lifecycle when a 0-RTT packet races the Initial).
    prof.record_zero_rtt_install(False)
    prof.record_zero_rtt_install(False)
    prof.record_zero_rtt_install(True)

    assert_equal_int(
        Int(prof.zero_rtt_install_attempts), 2,
        "exactly two failed attempts recorded",
    )
    assert_equal_int(
        Int(prof.zero_rtt_install_successes), 1,
        "exactly one success recorded — install is one-shot per conn",
    )

    # Subsequent SUCCESS calls would also increment, but production wires
    # `install_zero_rtt_read_keys` behind `has_keys(3) == False`, so the
    # success branch is taken at most once per connection lifetime. The
    # counter discipline is the contract proved here.
    print("  test_lazy_install_success_counter_increments_once_per_install: PASS")


def test_zero_rtt_buffer_respects_packet_cap() raises:
    """`_buffer_zero_rtt_or_drop` accepts at most ZERO_RTT_BUFFER_MAX_PKTS
    (16) packets, even when each is small enough to never trip the byte
    cap. The 17th call returns False and the buffer length stays at 16."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var small: List[UInt8] = [UInt8(0xAA), UInt8(0xBB), UInt8(0xCC), UInt8(0xDD)]

    for i in range(16):
        var ok = conn._buffer_zero_rtt_or_drop(Span(small))
        assert_true(ok, "packet #" + String(i) + " must be buffered (under cap)")

    var seventeenth = conn._buffer_zero_rtt_or_drop(Span(small))
    assert_false(
        seventeenth,
        "17th packet must be dropped — packet cap is 16",
    )
    assert_equal_int(
        len(conn.zero_rtt_buffer), 16,
        "buffer length must stay at 16 after over-cap call",
    )
    _ = conn.is_server
    print("  test_zero_rtt_buffer_respects_packet_cap: PASS")


def test_zero_rtt_buffer_respects_byte_cap_boundary() raises:
    """Boundary test for the ZERO_RTT_BUFFER_MAX_BYTES (32 KiB) cap.

    Sub-case A: 16 packets of exactly 2048 B → 16 × 2048 = 32768, the
                check is strict `>`, so all 16 fit.
    Sub-case B: 16 packets of 2049 B → packet 16 would push to 32784
                bytes (> 32768), so it is dropped (15 buffered).
    """
    var tls = TlsBackend("lib/librustls_mojo.so")

    # Sub-case A — exact-fit at 32768 bytes.
    var conn_a = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    var pkt2048 = List[UInt8](capacity=2048)
    for _ in range(2048):
        pkt2048.append(UInt8(0x5A))
    for i in range(16):
        var ok = conn_a._buffer_zero_rtt_or_drop(Span(pkt2048))
        assert_true(
            ok,
            "exact-fit packet #" + String(i) + " must be buffered (16 × 2048 = 32768)",
        )
    assert_equal_int(
        len(conn_a.zero_rtt_buffer), 16,
        "all 16 exact-fit packets must be buffered",
    )
    assert_equal_int(
        conn_a.zero_rtt_buffer_bytes, 32768,
        "byte total must equal 16 × 2048 at the exact-fit boundary",
    )
    _ = conn_a.is_server

    # Sub-case B — 2049 B packets trip the byte cap before the packet cap.
    var conn_b = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    var pkt2049 = List[UInt8](capacity=2049)
    for _ in range(2049):
        pkt2049.append(UInt8(0x5B))
    for i in range(15):
        var ok = conn_b._buffer_zero_rtt_or_drop(Span(pkt2049))
        assert_true(
            ok,
            "byte-cap packet #" + String(i) + " must be buffered",
        )
    var sixteenth = conn_b._buffer_zero_rtt_or_drop(Span(pkt2049))
    assert_false(
        sixteenth,
        "16th 2049-byte packet must be dropped — 15×2049 + 2049 = 32784 > 32768",
    )
    assert_equal_int(
        len(conn_b.zero_rtt_buffer), 15,
        "exactly 15 packets buffered before the byte cap fires",
    )
    _ = conn_b.is_server
    print("  test_zero_rtt_buffer_respects_byte_cap_boundary: PASS")


def test_zero_rtt_buffer_drains_idempotently() raises:
    """`_drain_zero_rtt_buffer` empties the buffer in one call. Subsequent
    calls are no-ops (buffer already empty). The drained packets re-enter
    `recv_from_buffer`; since they are synthetic non-AEAD-encrypted
    payloads, they are dropped silently — but the buffer empties either
    way.

    Scope: direct call to the drain helper rather than driving a real
    Initial that triggers `_drive_handshake`. The post-handshake drain
    invocation is covered by the per-handshake-drive wiring tested in
    upstream integration tests.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    # First byte 0x00 hits `recv_from_buffer`'s datagram-level zero-padding
    # silent-break (RFC 9000 §12.4) — keeps the test focused on buffer
    # state and avoids the wire-format parse path that needs AEAD.
    var small: List[UInt8] = [UInt8(0x00), UInt8(0x22), UInt8(0x33)]
    for _ in range(3):
        _ = conn._buffer_zero_rtt_or_drop(Span(small))
    assert_equal_int(
        len(conn.zero_rtt_buffer), 3,
        "pre-drain: 3 packets buffered",
    )
    assert_equal_int(
        conn.zero_rtt_buffer_bytes, 9,
        "pre-drain: 9 bytes buffered",
    )

    var now = UInt64(1_000_000)
    var ecn_mark = UInt8(0)
    conn._drain_zero_rtt_buffer(now, ecn_mark)

    assert_equal_int(
        len(conn.zero_rtt_buffer), 0,
        "post-drain: buffer must be empty",
    )
    assert_equal_int(
        conn.zero_rtt_buffer_bytes, 0,
        "post-drain: zero_rtt_buffer_bytes must be 0",
    )

    # Idempotent: second call is a no-op (early return on empty buffer).
    conn._drain_zero_rtt_buffer(now, ecn_mark)
    assert_equal_int(
        len(conn.zero_rtt_buffer), 0,
        "second drain call must be a no-op",
    )
    _ = conn.is_server
    print("  test_zero_rtt_buffer_drains_idempotently: PASS")


def test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys() raises:
    """Once `_discard_zero_rtt_keys` runs (RFC 9001 §4.1.2/§4.1.3
    handshake-confirmed eviction), any pending reorder buffer is
    undecryptable forever and MUST be freed.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var pkt: List[UInt8] = [UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)]
    var ok = conn._buffer_zero_rtt_or_drop(Span(pkt))
    assert_true(ok, "pre-discard packet must be buffered")
    assert_equal_int(
        len(conn.zero_rtt_buffer), 1,
        "pre-discard: 1 packet buffered",
    )

    conn._discard_zero_rtt_keys()

    assert_equal_int(
        len(conn.zero_rtt_buffer), 0,
        "post-discard: buffer must be empty",
    )
    assert_equal_int(
        conn.zero_rtt_buffer_bytes, 0,
        "post-discard: zero_rtt_buffer_bytes must be 0",
    )
    _ = conn.is_server
    print("  test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys: PASS")


def test_zero_rtt_buffer_cleared_at_connection_destroy() raises:
    """When a QuicConnection holding a populated reorder buffer goes out
    of scope, `__del__` must run without crash. Mojo's destructor chain
    frees the `List[List[UInt8]]` allocations transitively — this test
    asserts only that the destructor runs (no probe counter for List
    free).
    """
    var tls = TlsBackend("lib/librustls_mojo.so")

    # Scope-bounded conn: __del__ fires at block exit.
    if True:
        var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))
        var pkt: List[UInt8] = [UInt8(0xAB), UInt8(0xCD)]
        for _ in range(4):
            _ = conn._buffer_zero_rtt_or_drop(Span(pkt))
        assert_equal_int(
            len(conn.zero_rtt_buffer), 4,
            "pre-destroy: 4 packets buffered",
        )
        # Extend conn lifetime past the length read so ASAP-destruction
        # doesn't fire __del__ early.
        _ = conn.is_server
    # End of scope — conn.__del__ fires. zero_rtt_buffer's nested Lists
    # are freed transitively. No crash = pass.

    print("  test_zero_rtt_buffer_cleared_at_connection_destroy: PASS")


def main() raises:
    test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer()
    test_decrypt_zero_rtt_crypto_trips_f30_guard()
    test_lazy_install_success_counter_increments_once_per_install()
    test_zero_rtt_buffer_respects_packet_cap()
    test_zero_rtt_buffer_respects_byte_cap_boundary()
    test_zero_rtt_buffer_drains_idempotently()
    test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys()
    test_zero_rtt_buffer_cleared_at_connection_destroy()
