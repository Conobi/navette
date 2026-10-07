# tests/quic/test_quic_zero_rtt_decrypt.mojo
#
# 0-RTT decrypt path + reorder buffer property tests.
#
# Properties proven here (one test function each):
#   - decrypt-0rtt-stream (scoped to direct-dispatch)
#   - decrypt-0rtt-crypto-violates-f30
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

from std.memory import Pointer
from std.collections import Span

from navette.util.owned_alloc import Owned
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.event import QuicEvent
from std.collections import Span
from navette.quic.codec import ByteWriter
from navette.quic.frame import (
    Frame, StreamFrame, CryptoFrame, AckFrame, FrameCursor, serialize_frame,
)
from navette.quic.guard_predicates import ZERO_RTT_SPACE_IDX
from navette.quic.guard_tags import (
    GUARD_TAG_CRYPTO_IN_ZERO_RTT,
    GUARD_TAG_ACK_IN_ZERO_RTT,
)
from navette.quic.packet_protect import PacketProtect
from navette.quic.trans_param import default_transport_params
from tests._test_util import (
    assert_true, assert_false, assert_equal_int, load_test_cert,
)


def _synth_dcid() -> List[Byte]:
    """Return the canonical RFC 9001 §A test DCID for synthetic key derivation.

    Returns:
        An 8-byte List with the canonical sample DCID.
    """
    var dcid: List[Byte] = [
        UInt8(0x83), UInt8(0x94), UInt8(0xc8), UInt8(0xf0),
        UInt8(0x3e), UInt8(0x51), UInt8(0x57), UInt8(0x08),
    ]
    return dcid^


def _dispatch_encoded(
    mut conn: QuicConnection, frame: Frame, space_idx: Int, now: UInt64,
) raises:
    """Serialize `frame` and route it through `_dispatch_frame` via a
    FrameCursor, exactly as the packet-receive loop does after decryption.
    """
    var w = ByteWriter()
    serialize_frame(frame, w)
    var buf = w.finish()
    var cursor = FrameCursor(Span(buf))
    var tid = cursor.next()
    assert_true(Bool(tid), "encoded frame must parse back")
    # STREAM (0x08-0x0f) encodes OFF/LEN/FIN in the low 3 type bits.
    var got = Int(tid.value())
    var want = Int(frame.type_id)
    if want >= 0x08 and want <= 0x0F:
        got = got & ~0x07
        want = want & ~0x07
    assert_equal_int(got, want, "cursor type_id must match the encoded frame")
    conn._dispatch_frame(cursor, space_idx, now)
    assert_false(Bool(cursor.next()), "exactly one frame per dispatch")


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


comptime _INITIAL_LEN = 1200
"""RFC 9000 Section 14.1 minimum: a server drops Initials in smaller datagrams."""
comptime _INITIAL_PAYLOAD_LEN = _INITIAL_LEN - 22 - 16
"""PING + PADDING plaintext between the 22-byte header+PN and the AEAD tag."""


def _build_ping_initial(
    client_protect: PacketProtect, pn: UInt64
) raises -> List[Byte]:
    """Build an AEAD-encrypted, header-protected, PING-only Initial packet.

    Layout mirrors test_quic_connection.mojo::test_batch_crypto_roundtrip:
    18-byte clear header (first byte 0xC3: Initial, pn_len=4, reserved
    bits 0) + 4-byte PN + PING and PADDING up to 1200 bytes + 16-byte AEAD
    tag. The packet is padded to the 1200-byte minimum because the server
    skips Initials in smaller datagrams, including replays from the 0-RTT
    buffer. DCID is the canonical `_synth_dcid()`, matching the server
    fixture's Initial-keys derivation. The packet is conn-handle-free: no
    CRYPTO frames, so processing it never touches `conn_handle` (decrypt
    uses slot-0 keys handles only), which keeps it processable under the
    negative-handle pinned fault.

    Args:
        client_protect: A PacketProtect with client-side Initial keys
            derived from `_synth_dcid()`.
        pn: Packet number (must be <= 255; written into the low PN byte).
    """
    var buf_owned = Owned[UInt8](_INITIAL_LEN)
    var buf = buf_owned.ptr()
    for i in range(_INITIAL_LEN):
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
    # Payload length varint (2-byte form): 4 PN + payload + 16 tag.
    var length_field = 4 + _INITIAL_PAYLOAD_LEN + 16
    buf[16] = UInt8(0x40 | (length_field >> 8))
    buf[17] = UInt8(length_field & 0xFF)
    # PN bytes 18..21 (big-endian; pn <= 255 so only the low byte is set).
    buf[21] = UInt8(Int(pn) & 0xFF)
    # Payload at 22..: PING (0x01) then PADDING (0x00).
    buf[22] = UInt8(0x01)

    var ct_len = client_protect.encrypt_payload_in_place(
        0, pn, buf, 22, _INITIAL_PAYLOAD_LEN, _INITIAL_LEN
    )
    assert_equal_int(
        ct_len, _INITIAL_PAYLOAD_LEN + 16, "ciphertext = payload + tag 16"
    )
    client_protect.protect_header_ptr(0, buf, _INITIAL_LEN, 18, 4)

    var out = List[Byte](capacity=_INITIAL_LEN)
    for i in range(_INITIAL_LEN):
        out.append(buf[i])
    _ = buf_owned
    return out^


def _build_zero_rtt_stub() raises -> List[Byte]:
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
    var out = List[Byte](capacity=69)
    out.append(UInt8(0xD3))  # long header | fixed bit | 0-RTT | pn_len=4
    out.append(UInt8(0x00))  # version 0x00000001
    out.append(UInt8(0x00))
    out.append(UInt8(0x00))
    out.append(UInt8(0x01))
    out.append(UInt8(8))     # DCID len
    var dcid = _synth_dcid()
    for i in range(8):
        out.append(dcid[i])
    out.append(Byte(0))     # SCID len = 0
    out.append(UInt8(0x40))  # payload length varint (2-byte form), hi
    out.append(UInt8(52))
    for _ in range(52):
        out.append(UInt8(0x5A))  # "PN" + filler — never decrypted
    return out^


def test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer() raises:
    """A STREAM frame dispatched with `space_idx=ZERO_RTT_SPACE_IDX` MUST
    reach `_handle_stream_frame` (not the F30 guard) and land in the
    per-stream recv_buf with FIN observed.

    Scope: direct dispatch via `_dispatch_frame` (FrameCursor over the
    encoded frame) rather than driving an
    AEAD-encrypted 0-RTT packet through `recv_from_buffer`. The
    wire-format path is covered by the F30 scenario harness.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    assert_true(
        conn.zrtt.enabled,
        "zrtt.enabled must be True when max_early_data != 0",
    )

    # Client-initiated bidi stream id 0 — legal peer stream on a server.
    var sid = UInt64(0)
    var payload: List[Byte] = [
        UInt8(0x68), UInt8(0x65), UInt8(0x6c), UInt8(0x6c), UInt8(0x6f),
    ]  # b"hello"
    var sf = StreamFrame(sid, UInt64(0), payload, True)
    var frame = Frame.stream(sf)

    var now = UInt64(2_000_000)
    _dispatch_encoded(conn, frame, ZERO_RTT_SPACE_IDX, now)

    # The F30 guard must NOT fire for STREAM in 0-RTT — connection still alive.
    assert_false(
        Bool(conn.close.pending),
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

    var data: List[Byte] = [UInt8(0x16), UInt8(0x03), UInt8(0x03)]
    var cf = CryptoFrame(UInt64(0), data)
    var frame = Frame.crypto(cf)

    var now = UInt64(2_000_000)
    _dispatch_encoded(conn, frame, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn.close.pending),
        "F30 guard must fire — close.pending must be set",
    )
    var cc = conn.close.pending.value().copy()
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
    0x03). Each sub-case uses a fresh connection because `close.pending`
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
    _dispatch_encoded(conn, frame, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn.close.pending),
        "ACK-in-0-RTT guard must fire — close.pending must be set",
    )
    var cc = conn.close.pending.value().copy()
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

    _dispatch_encoded(conn2, frame_ecn, ZERO_RTT_SPACE_IDX, now)

    assert_true(
        Bool(conn2.close.pending),
        "ACK_ECN-in-0-RTT guard must fire — close.pending must be set",
    )
    var cc_ecn = conn2.close.pending.value().copy()
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


def test_zero_rtt_buffer_respects_packet_cap() raises:
    """`_buffer_zero_rtt_or_drop` accepts at most ZERO_RTT_BUFFER_MAX_PKTS
    (16) packets, even when each is small enough to never trip the byte
    cap. The 17th call returns False and the buffer length stays at 16."""
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var small: List[Byte] = [UInt8(0xAA), UInt8(0xBB), UInt8(0xCC), UInt8(0xDD)]

    for i in range(16):
        var ok = conn._buffer_zero_rtt_or_drop(Span(small))
        assert_true(ok, "packet #" + String(i) + " must be buffered (under cap)")

    var seventeenth = conn._buffer_zero_rtt_or_drop(Span(small))
    assert_false(
        seventeenth,
        "17th packet must be dropped — packet cap is 16",
    )
    assert_equal_int(
        len(conn.zrtt.buffer), 16,
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
    var pkt2048 = List[Byte](capacity=2048)
    for _ in range(2048):
        pkt2048.append(UInt8(0x5A))
    for i in range(16):
        var ok = conn_a._buffer_zero_rtt_or_drop(Span(pkt2048))
        assert_true(
            ok,
            "exact-fit packet #" + String(i) + " must be buffered (16 × 2048 = 32768)",
        )
    assert_equal_int(
        len(conn_a.zrtt.buffer), 16,
        "all 16 exact-fit packets must be buffered",
    )
    assert_equal_int(
        conn_a.zrtt.buffer_bytes, 32768,
        "byte total must equal 16 × 2048 at the exact-fit boundary",
    )
    _ = conn_a.is_server

    # Sub-case B — 2049 B packets trip the byte cap before the packet cap.
    var conn_b = _make_server_conn(tls, UInt32(0xFFFFFFFF))
    var pkt2049 = List[Byte](capacity=2049)
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
        len(conn_b.zrtt.buffer), 15,
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
    var small: List[Byte] = [UInt8(0x00), UInt8(0x22), UInt8(0x33)]
    for _ in range(3):
        _ = conn._buffer_zero_rtt_or_drop(Span(small))
    assert_equal_int(
        len(conn.zrtt.buffer), 3,
        "pre-drain: 3 packets buffered",
    )
    assert_equal_int(
        conn.zrtt.buffer_bytes, 9,
        "pre-drain: 9 bytes buffered",
    )

    var now = UInt64(1_000_000)
    var ecn_mark = UInt8(0)
    conn._drain_zero_rtt_buffer(now, ecn_mark)

    assert_equal_int(
        len(conn.zrtt.buffer), 0,
        "post-drain: buffer must be empty",
    )
    assert_equal_int(
        conn.zrtt.buffer_bytes, 0,
        "post-drain: zrtt.buffer_bytes must be 0",
    )

    # Idempotent: second call is a no-op (early return on empty buffer).
    conn._drain_zero_rtt_buffer(now, ecn_mark)
    assert_equal_int(
        len(conn.zrtt.buffer), 0,
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

    var pkt: List[Byte] = [UInt8(0xDE), UInt8(0xAD), UInt8(0xBE), UInt8(0xEF)]
    var ok = conn._buffer_zero_rtt_or_drop(Span(pkt))
    assert_true(ok, "pre-discard packet must be buffered")
    assert_equal_int(
        len(conn.zrtt.buffer), 1,
        "pre-discard: 1 packet buffered",
    )

    conn._discard_zero_rtt_keys()

    assert_equal_int(
        len(conn.zrtt.buffer), 0,
        "post-discard: buffer must be empty",
    )
    assert_equal_int(
        conn.zrtt.buffer_bytes, 0,
        "post-discard: zrtt.buffer_bytes must be 0",
    )
    _ = conn.is_server
    print("  test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys: PASS")


def test_zero_rtt_buffer_cleared_at_connection_destroy() raises:
    """When a QuicConnection holding a populated reorder buffer goes out
    of scope, `__del__` must run without crash. Mojo's destructor chain
    frees the `List[List[Byte]]` allocations transitively — this test
    asserts only that the destructor runs (no probe counter for List
    free).
    """
    var tls = TlsBackend("lib/librustls_mojo.so")

    # Scope-bounded conn: __del__ fires at block exit.
    if True:
        var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))
        var pkt: List[Byte] = [UInt8(0xAB), UInt8(0xCD)]
        for _ in range(4):
            _ = conn._buffer_zero_rtt_or_drop(Span(pkt))
        assert_equal_int(
            len(conn.zrtt.buffer), 4,
            "pre-destroy: 4 packets buffered",
        )
        # Extend conn lifetime past the length read so ASAP-destruction
        # doesn't fire __del__ early.
        _ = conn.is_server
    # End of scope — conn.__del__ fires. zrtt.buffer's nested Lists
    # are freed transitively. No crash = pass.

    print("  test_zero_rtt_buffer_cleared_at_connection_destroy: PASS")


def test_drain_survives_mid_packet_raise() raises:
    """AC drain-survives-mid-packet-raise: the drain continues past a
    silently-dropped middle 0-RTT packet — packets one and three still
    replay, and `zrtt.draining` resets to False.

    What this test actually exercises (Fix-2 drain-mode containment):
    the middle 0-RTT packet is dropped at the Path B install-fold
    *inside* recv_from_buffer (drain-mode silent drop), NOT at the
    drain's own `except e:` branch.
    That branch executes zero times in this test. Its purpose is
    defense-in-depth against UNCLASSIFIED raises (internal errors,
    future bugs), not exercised by this integration test.

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
        conn.zrtt.draining,
        "zrtt.draining must be False after the drain",
    )
    assert_equal_int(
        len(conn.zrtt.buffer), 0,
        "buffer fully drained",
    )
    _ = conn.is_server
    print("  test_drain_survives_mid_packet_raise: PASS")


def test_install_raise_folds_into_failure_path() raises:
    """AC install-raise-folds-into-failure-path: with the pinned
    negative-handle fault, `recv_from_buffer` does NOT raise on a 0-RTT
    packet whose key install fails with rc=-1, and the packet lands in
    `zrtt.buffer` (pre-drain mode), exactly like the rc=1
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
    var buf_owned = Owned[UInt8](len(zero_rtt))
    var buf_ptr = buf_owned.ptr()
    for i in range(len(zero_rtt)):
        buf_ptr[i] = zero_rtt[i]
    try:
        conn.recv_from_buffer(
            buf_ptr, len(zero_rtt), UInt64(2_000_000), UInt8(0)
        )
    finally:
        conn.conn_handle = real_handle
    _ = buf_owned

    assert_equal_int(
        len(conn.zrtt.buffer), 1,
        "0-RTT packet lands in zrtt.buffer after the contained"
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
    var buf_owned = Owned[UInt8](total)
    var buf_ptr = buf_owned.ptr()
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
    _ = buf_owned

    assert_equal_int(
        conn.spaces[0].largest_recv_pn, 0,
        "survivor Initial processed — largest_recv_pn advanced to 0"
        " despite the preceding 0-RTT install raise",
    )
    assert_false(
        conn.zrtt.draining,
        "zrtt.draining must be False after the feed",
    )
    _ = conn.is_server
    print("  test_coalesced_survivors_still_processed: PASS")


def test_one_rtt_ack_dispatch_unaffected_by_guard() raises:
    """AC one-rtt-acks-unaffected: an ACK frame dispatched with
    `space_idx=2` (1-RTT / Application space) MUST NOT trip the
    ACK-in-0-RTT guard.

    Scope: the 0-RTT guard is checked BEFORE `_handle_ack`. On a fresh
    connection the ACK names a packet number never sent, so `_handle_ack`
    may legitimately close with PROTOCOL_VIOLATION (optimistic-ACK defence)
    or raise. Either is downstream of the guard, so the test only requires
    that any pending close does NOT carry the [QUIC-ACK-IN-0RTT] tag.
    """
    var tls = TlsBackend("lib/librustls_mojo.so")
    var conn = _make_server_conn(tls, UInt32(0xFFFFFFFF))

    var af = AckFrame()
    af.largest_ack = UInt64(0)
    var frame = Frame.ack(af)

    var now = UInt64(2_000_000)
    # space_idx=2 is the 1-RTT Application space; the 0-RTT guard must not fire.
    var w = ByteWriter()
    serialize_frame(frame, w)
    var buf = w.finish()
    var cursor = FrameCursor(Span(buf))
    var tid = cursor.next()
    assert_true(
        Bool(tid) and tid.value() == frame.type_id,
        "encoded ACK must parse back as ACK",
    )
    try:
        conn._dispatch_frame(cursor, 2, now)
    except:
        # A raise from _handle_ack is downstream of the guard. Check the
        # guard state below.
        pass

    var close_reason = String("")
    if conn.close.pending:
        var pc = conn.close.pending.value().copy()
        for i in range(len(pc.reason)):
            close_reason = close_reason + chr(Int(pc.reason[i]))
    assert_false(
        String(GUARD_TAG_ACK_IN_ZERO_RTT) in close_reason,
        "ACK in 1-RTT space MUST NOT trip the 0-RTT guard; closed with: "
        + close_reason,
    )
    _ = conn.is_server
    print("  test_one_rtt_ack_dispatch_unaffected_by_guard: PASS")


def main() raises:
    test_decrypt_zero_rtt_stream_routes_to_per_stream_buffer()
    test_decrypt_zero_rtt_crypto_trips_f30_guard()
    test_decrypt_zero_rtt_ack_trips_guard_not_oob()
    test_one_rtt_ack_dispatch_unaffected_by_guard()
    test_zero_rtt_buffer_respects_packet_cap()
    test_zero_rtt_buffer_respects_byte_cap_boundary()
    test_zero_rtt_buffer_drains_idempotently()
    test_zero_rtt_buffer_clears_on_discard_zero_rtt_keys()
    test_zero_rtt_buffer_cleared_at_connection_destroy()
    test_drain_survives_mid_packet_raise()
    test_install_raise_folds_into_failure_path()
    test_coalesced_survivors_still_processed()
