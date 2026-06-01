"""Pure-predicate guards for QUIC conformance (no I/O, no connection refs)."""

from navette.quic.guard_tags import (
    GUARD_TAG_RESET_SEND_ONLY,
    GUARD_TAG_STOP_LOCAL_NOT_CREATED,
    GUARD_TAG_NO_FRAMES,
    GUARD_TAG_UNKNOWN_FRAME,
    GUARD_TAG_RESERVED_BITS_HS,
    GUARD_TAG_RESERVED_BITS_SHORT,
)


struct GuardVerdict(Copyable, Movable):
    """Verdict returned by a conformance predicate when a guard trips."""

    var error_code: UInt64
    var tag: String

    def __init__(out self, *, error_code: UInt64, tag: String):
        self.error_code = error_code
        self.tag = tag

    def __init__(out self, *, other: Self):
        self.error_code = other.error_code
        self.tag = other.tag

    def __init__(out self, *, deinit take: Self):
        self.error_code = take.error_code
        self.tag = take.tag


struct QuicResetCtx(Copyable, Movable):
    """Inputs to the F15 RESET_STREAM guard predicate."""

    var stream_id: UInt64
    var local_uni_opened: UInt64
    var local_bidi_opened: UInt64

    def __init__(out self, *, stream_id: UInt64, local_uni_opened: UInt64, local_bidi_opened: UInt64):
        self.stream_id = stream_id
        self.local_uni_opened = local_uni_opened
        self.local_bidi_opened = local_bidi_opened

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.local_uni_opened = other.local_uni_opened
        self.local_bidi_opened = other.local_bidi_opened

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.local_uni_opened = take.local_uni_opened
        self.local_bidi_opened = take.local_bidi_opened


struct QuicStopSendingCtx(Copyable, Movable):
    """Inputs to the F16 STOP_SENDING guard predicate."""

    var stream_id: UInt64
    var local_uni_opened: UInt64
    var local_bidi_opened: UInt64

    def __init__(out self, *, stream_id: UInt64, local_uni_opened: UInt64, local_bidi_opened: UInt64):
        self.stream_id = stream_id
        self.local_uni_opened = local_uni_opened
        self.local_bidi_opened = local_bidi_opened

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.local_uni_opened = other.local_uni_opened
        self.local_bidi_opened = other.local_bidi_opened

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.local_uni_opened = take.local_uni_opened
        self.local_bidi_opened = take.local_bidi_opened


def predicate_f15_reset_on_server_uni(ctx: QuicResetCtx) -> Optional[GuardVerdict]:
    """Return Some(STREAM_STATE_ERROR + tag) when a RESET_STREAM targets
    a server-uni stream (RFC 9000 §19.4 + §3.2 — the peer cannot RESET a
    stream where this endpoint is the sender).

    RFC 9000 §2.1: server-uni stream IDs end in 0b11 (suffix 3 mod 4).
    """
    var sid = ctx.stream_id
    var is_server_uni = (sid & UInt64(3)) == UInt64(3)
    if not is_server_uni:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x05),  # STREAM_STATE_ERROR
            tag=String(GUARD_TAG_RESET_SEND_ONLY),
        )
    )


def check_long_reserved_bits(first_byte: UInt8) -> Optional[GuardVerdict]:
    """RFC 9000 §17.2 — long-header reserved bits (mask 0x0C) MUST be 0.

    Receivers MUST treat receipt of a long-header packet with any
    reserved bit set as a connection error of type PROTOCOL_VIOLATION.
    """
    if (first_byte & UInt8(0x0C)) == UInt8(0):
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x0A),  # PROTOCOL_VIOLATION
            tag=String(GUARD_TAG_RESERVED_BITS_HS),
        )
    )


def check_short_reserved_bits(first_byte: UInt8) -> Optional[GuardVerdict]:
    """RFC 9000 §17.3.1 — 1-RTT (short) header reserved bits (mask 0x18)
    MUST be 0. Key Phase (0x04) and PN length (0x03) are NOT reserved; only
    bits 3 and 4 are. Receivers MUST close with PROTOCOL_VIOLATION on a
    set bit.
    """
    if (first_byte & UInt8(0x18)) == UInt8(0):
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x0A),  # PROTOCOL_VIOLATION
            tag=String(GUARD_TAG_RESERVED_BITS_SHORT),
        )
    )


def is_unknown_frame_type(type_id: UInt64) -> Bool:
    """Return True iff `type_id` is outside RFC 9000 §19's closed set
    of frame type ids. STREAM frames live in 0x08..0x0F (the low three bits
    encode OFF/LEN/FIN flags); MAX_*/CONNECTION_CLOSE/HANDSHAKE_DONE etc.
    live in 0x10..0x1E. Everything else MUST be treated as unknown and
    closed with FRAME_ENCODING_ERROR (RFC 9000 §12.4).
    """
    if type_id <= UInt64(0x07):
        return False
    if type_id >= UInt64(0x08) and type_id <= UInt64(0x0F):
        return False
    if type_id >= UInt64(0x10) and type_id <= UInt64(0x1E):
        return False
    return True


def predicate_f11_no_frames(frame_count: Int) -> Optional[GuardVerdict]:
    """Return Some(PROTOCOL_VIOLATION + tag) when a QUIC packet carries no
    frames (RFC 9000 §12.4 — "An endpoint MUST treat receipt of a packet
    containing no frames as a connection error of type PROTOCOL_VIOLATION").
    """
    if frame_count != 0:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x0A),  # PROTOCOL_VIOLATION
            tag=String(GUARD_TAG_NO_FRAMES),
        )
    )


def predicate_f16_stop_sending_local_not_created(
    ctx: QuicStopSendingCtx,
) -> Optional[GuardVerdict]:
    """Return Some(STREAM_STATE_ERROR + tag) when STOP_SENDING targets a
    locally-initiated stream that has not yet been created
    (RFC 9000 §19.5).

    On the server: server-uni IDs end in 0b11 (suffix 3 mod 4) and
    server-bidi IDs end in 0b01 (suffix 1 mod 4). For each class the
    max ever-created local id = `(count-1)*4 + base`; anything strictly
    greater is uncreated and MUST trip STREAM_STATE_ERROR.
    """
    var sid = ctx.stream_id
    var suffix = sid & UInt64(3)
    var is_local_uni = suffix == UInt64(3)
    var is_local_bidi = suffix == UInt64(1)
    if not is_local_uni and not is_local_bidi:
        return Optional[GuardVerdict]()
    var created: Bool
    if is_local_uni:
        created = sid < (ctx.local_uni_opened * UInt64(4) + UInt64(3))
    else:
        created = sid < (ctx.local_bidi_opened * UInt64(4) + UInt64(1))
    if created:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x05),  # STREAM_STATE_ERROR
            tag=String(GUARD_TAG_STOP_LOCAL_NOT_CREATED),
        )
    )
