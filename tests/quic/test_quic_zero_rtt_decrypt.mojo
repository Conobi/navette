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
from navette.quic.frame import Frame, StreamFrame, CryptoFrame, AckFrame
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.guard_tags import (
    GUARD_TAG_CRYPTO_IN_ZERO_RTT,
    GUARD_TAG_ACK_IN_ZERO_RTT,
)
from navette.quic.packet_protect import PacketProtect
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


def _build_ping_initial(
    client_protect: PacketProtect, pn: UInt64
) raises -> List[UInt8]:
    """Build an AEAD-encrypted, header-protected, PING-only Initial packet.

    Layout mirrors test_quic_connection.mojo::test_batch_crypto_roundtrip:
    18-byte clear header (first byte 0xC3: Initial, pn_len=4, reserved
    bits 0) + 4-byte PN + 32-byte payload (PING 0x01 + 31 PADDING) +
    16-byte AEAD tag = 70 bytes. DCID is the canonical `_synth_dcid()`,
    matching the server fixture's Initial-keys derivation. The packet is
    conn-handle-free: no CRYPTO frames, so processing it never touches
    `conn_handle` (decrypt uses slot-0 keys handles only) — which is what
    keeps it processable under the negative-handle pinned fault.

    Args:
        client_protect: A PacketProtect with client-side Initial keys
            derived from `_synth_dcid()`.
        pn: Packet number (must be <= 255; written into the low PN byte).

    Returns:
        The 70-byte wire-format packet.
    """
    var buf = _heap_alloc[UInt8](70).as_unsafe_any_origin()
    for i in range(70):
        buf[i] = UInt8(0)
    buf[0] = UInt8(0xC3)  # long header | fixed bit | Initial | pn_len=4
    buf[1] = UInt8(0x00)  # version 0x00000001
    buf[2] = UInt8(0x00)
    buf[3] = UInt8(0x00)
    buf[4] = UInt8(0x01)
    buf[5] = UInt8(8)     # DCID len
    var dcid = _synth_dcid()
    for i in range(8):
        buf[6 + i] = dcid[i]
    buf[14] = UInt8(0)    # SCID len = 0
    buf[15] = UInt8(0)    # token length varint = 0
    buf[16] = UInt8(0x40) # payload length varint (2-byte form), hi
    buf[17] = UInt8(52)   # 4 PN + 32 payload + 16 tag
    # PN bytes 18..21 (big-endian; pn <= 255 so only the low byte is set).
    buf[21] = UInt8(Int(pn) & 0xFF)
    # Payload at 22..53: PING (0x01) then 31 PADDING (0x00).
    buf[22] = UInt8(0x01)

    var ct_len = client_protect.encrypt_payload_in_place(
        0, pn, buf, 22, 32, 70
    )
    assert_equal_int(ct_len, 48, "ciphertext = payload 32 + tag 16")
    client_protect.protect_header_ptr(0, buf, 70, 18, 4)

    var out = List[UInt8](capacity=70)
    for i in range(70):
        out.append(buf[i])
    buf.free()
    return out^


def _build_zero_rtt_stub() raises -> List[UInt8]:
    """Build a parseable — never decrypted — 0-RTT long-header packet.

    Path B (lazy key install) fires on the 0-RTT packet *type* before any
    decrypt, so the payload is arbitrary non-zero filler; only the header
    must parse and `pn_offset + payload_length` must fit the buffer.
    Layout: first byte 0xD3 (long | fixed | 0-RTT | pn_len=4), version 1,
    8-byte `_synth_dcid()` DCID, empty SCID, payload-length varint 52,
    then 52 filler bytes = 69 bytes total (0-RTT has no token field).

    Returns:
        The 69-byte parseable 0-RTT packet.
    """
    var out = List[UInt8](capacity=69)
    out.append(UInt8(0xD3))  # long header | fixed bit | 0-RTT | pn_len=4
    out.append(UInt8(0x00))  # version 0x00000001
    out.append(UInt8(0x00))
    out.append(UInt8(0x00))
    out.append(UInt8(0x01))
    out.append(UInt8(8))     # DCID len
    var dcid = _synth_dcid()
    for i in range(8):
        out.append(dcid[i])
    out.append(UInt8(0))     # SCID len = 0
    out.append(UInt8(0x40))  # payload length varint (2-byte form), hi
    out.append(UInt8(52))
    for _ in range(52):
        out.append(UInt8(0x5A))  # "PN" + filler — never decrypted
    return out^


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


def test_decrypt_zero_rtt_ack_trips_guard_not_oob() raises:
    """An ACK frame dispatched with `space_idx=ZERO_RTT_SPACE_IDX` MUST
    close the connection with PROTOCOL_VIOLATION (RFC 9000 §12.4 — ACK
    is forbidden in 0-RTT packets) instead of indexing `spaces[3]` out
    of bounds in `_handle_ack`.

    Sub-case A covers ACK (type 0x02); sub-case B covers ACK_ECN (type
    0x03). Each sub-case uses a fresh connection because `pending_close`
    is sticky — once set, a second dispatch on the same conn would
    vacuously see an already-closed connection.
    """
    # Sub-case A: plain ACK (0x02).
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var af = AckFrame()
    af.largest_ack = UInt64(0)
    var frame = Frame.ack(af)

    var now = UInt64(2_000_000)
    conn._dispatch_frame(frame, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn.pending_close),
        "ACK-in-0-RTT guard must fire — pending_close must be set",
    )
    var cc = conn.pending_close.value().copy()
    assert_equal_int(
        Int(cc.error_code), 0x0A,
        "ACK-in-0-RTT closes with PROTOCOL_VIOLATION (0x0A)",
    )
    assert_true(cc.is_transport, "ACK-in-0-RTT emits a transport-CC frame")
    var reason_str = String("")
    for i in range(len(cc.reason)):
        reason_str = reason_str + chr(Int(cc.reason[i]))
    assert_true(
        String(GUARD_TAG_ACK_IN_ZERO_RTT) in reason_str,
        "reason carries [QUIC-ACK-IN-0RTT]; got " + reason_str,
    )
    _ = conn.is_server

    # Sub-case B: ACK_ECN (0x03) — fresh connection, same guard must fire.
    # `AckFrame.has_ecn = True` causes `Frame.ack` to set `type_id = 0x03`.
    var conn2 = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    var af_ecn = AckFrame()
    af_ecn.largest_ack = UInt64(0)
    af_ecn.has_ecn = True
    var frame_ecn = Frame.ack(af_ecn)

    conn2._dispatch_frame(frame_ecn, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn2.pending_close),
        "ACK_ECN-in-0-RTT guard must fire — pending_close must be set",
    )
    var cc_ecn = conn2.pending_close.value().copy()
    assert_equal_int(
        Int(cc_ecn.error_code), 0x0A,
        "ACK_ECN-in-0-RTT closes with PROTOCOL_VIOLATION (0x0A)",
    )
    assert_true(
        cc_ecn.is_transport, "ACK_ECN-in-0-RTT emits a transport-CC frame"
    )
    var reason_str2 = String("")
    for i in range(len(cc_ecn.reason)):
        reason_str2 = reason_str2 + chr(Int(cc_ecn.reason[i]))
    assert_true(
        String(GUARD_TAG_ACK_IN_ZERO_RTT) in reason_str2,
        "ACK_ECN reason carries [QUIC-ACK-IN-0RTT]; got " + reason_str2,
    )
    _ = conn2.is_server
    print("  test_decrypt_zero_rtt_ack_trips_guard_not_oob: PASS")


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


def test_accept_profile_replay_counters_increment_independently() raises:
    """5 replay counters initialise to 0 and each record_* method
    increments only its bucket. Establishes the AcceptProfile contract
    that QuicConnection._record_replay_* wrappers will consume."""
    var prof = AcceptProfile()
    assert_equal_int(Int(prof.zero_rtt_replay_accept), 0, "accept starts 0")
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_duplicate), 0, "dup starts 0"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_per_key_quota), 0, "per_key starts 0"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_global_ceiling), 0, "ceiling starts 0"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_no_authenticator), 0, "no_auth starts 0"
    )

    prof.record_zero_rtt_replay_accept()
    prof.record_zero_rtt_replay_accept()
    prof.record_zero_rtt_replay_reject_duplicate()
    prof.record_zero_rtt_replay_reject_per_key_quota()
    prof.record_zero_rtt_replay_reject_global_ceiling()
    prof.record_zero_rtt_replay_reject_no_authenticator()
    prof.record_zero_rtt_replay_reject_no_authenticator()

    assert_equal_int(Int(prof.zero_rtt_replay_accept), 2, "accept +2")
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_duplicate), 1, "dup +1"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_per_key_quota), 1, "per_key +1"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_global_ceiling), 1, "ceiling +1"
    )
    assert_equal_int(
        Int(prof.zero_rtt_replay_reject_no_authenticator), 2, "no_auth +2"
    )
    print("  test_accept_profile_replay_counters_increment_independently: PASS")


def test_drain_survives_mid_packet_raise() raises:
    """AC drain-survives-mid-packet-raise: the drain continues past a
    silently-dropped middle 0-RTT packet — packets one and three still
    replay, and `_draining_zero_rtt` resets to False.

    What this test actually exercises (Fix-2 drain-mode containment):
    the middle 0-RTT packet is dropped at the Path B install-fold
    *inside* recv_from_buffer (drain-mode silent drop), NOT at the
    drain's own `except e:` / `_record_zero_rtt_drain_dropped()` branch.
    That branch executes zero times in this test. Its purpose is
    defense-in-depth against UNCLASSIFIED raises (internal errors,
    future bugs); it is exercised in isolation by the recorder/reporter
    unit test in test_quic_profile.mojo, not by this integration test.

    The proof: packets one AND three advance `largest_recv_pn` to 1,
    and `ack_ranges[0].start == 0` proves packet one (pn=0) really
    replayed (a lone pn=1 receipt would leave start=1).

    White-box mixed-buffer injection with the pinned negative-handle
    fault: `rlsm_quic_server_conn_zero_rtt_keys` returns -1 for an
    invalid conn handle, so overwriting `conn.conn_handle` with -1
    makes the middle 0-RTT packet hit the Path B failure fold in drain
    mode. The two encrypted PING-only Initials are conn-handle-free
    (slot-0 keys handles only) and stay processable under the fault.
    The handle is saved and restored in a `finally` so a failing
    assertion cannot leak the QUIC_CONN_TABLE entry (`__del__` skips
    quic_conn_free when conn_handle < 0).
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var client_protect = PacketProtect(tls.shared())
    var dcid = _synth_dcid()
    client_protect.derive_initial_keys(Span(dcid), True)

    var initial_pn0 = _build_ping_initial(client_protect, UInt64(0))
    var zero_rtt = _build_zero_rtt_stub()
    var initial_pn1 = _build_ping_initial(client_protect, UInt64(1))

    assert_true(
        conn._buffer_zero_rtt_or_drop(Span(initial_pn0)),
        "packet one (Initial pn=0) buffered",
    )
    assert_true(
        conn._buffer_zero_rtt_or_drop(Span(zero_rtt)),
        "packet two (0-RTT) buffered",
    )
    assert_true(
        conn._buffer_zero_rtt_or_drop(Span(initial_pn1)),
        "packet three (Initial pn=1) buffered",
    )
    assert_equal_int(
        conn.spaces[0].largest_recv_pn, -1,
        "pre-drain: no Initial received yet",
    )

    var real_handle = conn.conn_handle
    conn.conn_handle = Int32(-1)
    try:
        conn._drain_zero_rtt_buffer(UInt64(2_000_000), UInt8(0))
    finally:
        conn.conn_handle = real_handle

    assert_equal_int(
        conn.spaces[0].largest_recv_pn, 1,
        "packets one AND three replayed (largest_recv_pn = 1) — the"
        " mid-drain raise was contained to packet two",
    )
    assert_equal_int(
        Int(conn.spaces[0].ack_ranges[0].start), 0,
        "ack range covers pn 0 — packet one really replayed, not just"
        " packet three (a lone pn=1 receipt would leave start=1)",
    )
    assert_false(
        conn._draining_zero_rtt,
        "_draining_zero_rtt must be False after the drain",
    )
    assert_equal_int(
        len(conn.zero_rtt_buffer), 0,
        "buffer fully drained",
    )
    _ = conn.is_server
    print("  test_drain_survives_mid_packet_raise: PASS")


def test_install_raise_folds_into_failure_path() raises:
    """AC install-raise-folds-into-failure-path: with the pinned
    negative-handle fault, `recv_from_buffer` does NOT raise on a 0-RTT
    packet whose key install fails with rc=-1, and the packet lands in
    `zero_rtt_buffer` (pre-drain mode), exactly like the rc=1
    keys-not-yet-available path.

    The datagram contains ONLY the 0-RTT packet — with no successfully
    processed packet in the datagram, the post-handshake-drive drain
    never runs, so the buffer-length observable survives the call.
    Handle saved and restored in a `finally` (a failing assertion must
    not leak the QUIC_CONN_TABLE entry).
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    var zero_rtt = _build_zero_rtt_stub()

    var real_handle = conn.conn_handle
    conn.conn_handle = Int32(-1)
    var buf_ptr = _heap_alloc[UInt8](len(zero_rtt)).as_unsafe_any_origin()
    for i in range(len(zero_rtt)):
        buf_ptr[i] = zero_rtt[i]
    try:
        conn.recv_from_buffer(
            buf_ptr, len(zero_rtt), UInt64(2_000_000), UInt8(0)
        )
    finally:
        conn.conn_handle = real_handle
        buf_ptr.free()

    assert_equal_int(
        len(conn.zero_rtt_buffer), 1,
        "0-RTT packet lands in zero_rtt_buffer after the contained"
        " install raise (buffer-or-drop path, pre-drain mode)",
    )
    _ = conn.is_server
    print("  test_install_raise_folds_into_failure_path: PASS")


def test_coalesced_survivors_still_processed() raises:
    """AC coalesced-survivors-still-processed: a datagram of
    [0-RTT packet that triggers the install fault, PING-only Initial]
    still processes the Initial — `spaces[0].largest_recv_pn` advances
    to the survivor's packet number. The survivor is conn-handle-free
    (PING-only, no CRYPTO frames) so it stays processable under the
    negative-handle fault.

    Note on the buffer: the surviving Initial triggers the
    post-handshake-drive drain, which replays the just-buffered 0-RTT
    packet in drain mode and silently drops it — so the buffer ends
    empty here; the buffer-length observable lives in
    test_install_raise_folds_into_failure_path instead.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var client_protect = PacketProtect(tls.shared())
    var dcid = _synth_dcid()
    client_protect.derive_initial_keys(Span(dcid), True)

    var zero_rtt = _build_zero_rtt_stub()
    var initial_pn0 = _build_ping_initial(client_protect, UInt64(0))

    var total = len(zero_rtt) + len(initial_pn0)
    var buf_ptr = _heap_alloc[UInt8](total).as_unsafe_any_origin()
    for i in range(len(zero_rtt)):
        buf_ptr[i] = zero_rtt[i]
    for i in range(len(initial_pn0)):
        buf_ptr[len(zero_rtt) + i] = initial_pn0[i]

    assert_equal_int(
        conn.spaces[0].largest_recv_pn, -1,
        "pre-feed: no Initial received yet",
    )

    var real_handle = conn.conn_handle
    conn.conn_handle = Int32(-1)
    try:
        conn.recv_from_buffer(buf_ptr, total, UInt64(2_000_000), UInt8(0))
    finally:
        conn.conn_handle = real_handle
        buf_ptr.free()

    assert_equal_int(
        conn.spaces[0].largest_recv_pn, 0,
        "survivor Initial processed — largest_recv_pn advanced to 0"
        " despite the preceding 0-RTT install raise",
    )
    assert_false(
        conn._draining_zero_rtt,
        "_draining_zero_rtt must be False after the feed",
    )
    _ = conn.is_server
    print("  test_coalesced_survivors_still_processed: PASS")


def test_one_rtt_ack_dispatch_unaffected_by_guard() raises:
    """AC one-rtt-acks-unaffected: an ACK frame dispatched with
    `space_idx=2` (1-RTT / Application space) MUST NOT trip the
    ACK-in-0-RTT guard — `pending_close` stays unset after dispatch.

    Scope: the 0-RTT guard is checked BEFORE `_handle_ack`; if `_handle_ack`
    subsequently raises (e.g. "ACK for unsent packet" when the sent-pkt table
    is empty), that raise originates downstream of the guard and does not
    contradict the guard's non-firing. The test wraps `_dispatch_frame` in
    a try/except so it can inspect `pending_close` after the call regardless
    of whether `_handle_ack` itself raises. A `pending_close` that is unset
    when the except branch is entered confirms the guard did not run — no
    close_transport call was made before the handler raised.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var af = AckFrame()
    af.largest_ack = UInt64(0)
    var frame = Frame.ack(af)

    var now = UInt64(2_000_000)
    # space_idx=2 is the 1-RTT Application space; the 0-RTT guard must not fire.
    try:
        conn._dispatch_frame(frame, 2, now)
    except:
        # _handle_ack may raise on an empty sent-packet table — that is a
        # downstream handler concern, not the guard. Check guard state below.
        pass

    assert_false(
        Bool(conn.pending_close),
        "ACK in 1-RTT space MUST NOT trip the 0-RTT guard — connection must stay open",
    )
    _ = conn.is_server
    print("  test_one_rtt_ack_dispatch_unaffected_by_guard: PASS")


def main() raises:
    test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer()
    test_decrypt_zero_rtt_crypto_trips_f30_guard()
    test_decrypt_zero_rtt_ack_trips_guard_not_oob()
    test_one_rtt_ack_dispatch_unaffected_by_guard()
    test_lazy_install_success_counter_increments_once_per_install()
    test_zero_rtt_buffer_respects_packet_cap()
    test_zero_rtt_buffer_respects_byte_cap_boundary()
    test_zero_rtt_buffer_drains_idempotently()
    test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys()
    test_zero_rtt_buffer_cleared_at_connection_destroy()
    test_accept_profile_replay_counters_increment_independently()
    test_drain_survives_mid_packet_raise()
    test_install_raise_folds_into_failure_path()
    test_coalesced_survivors_still_processed()
