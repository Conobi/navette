"""Pure-predicate guards for QUIC conformance (no I/O, no connection refs)."""

from navette.quic.guard_tags import GUARD_TAG_RESET_SEND_ONLY, GUARD_TAG_STOP_LOCAL_NOT_CREATED


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
