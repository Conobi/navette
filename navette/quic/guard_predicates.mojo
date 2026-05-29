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
    """Stub for the F15 guard: tripped when the peer RESET_STREAMs a
    stream id the server itself opened. Returns None until the real
    check lands in a later commit."""
    return Optional[GuardVerdict]()


def predicate_f16_stop_sending_local_not_created(ctx: QuicStopSendingCtx) -> Optional[GuardVerdict]:
    """Stub for the F16 guard: tripped when the peer STOP_SENDINGs a
    stream id past the highest local-opened watermark. Returns None
    until the real check lands in a later commit."""
    return Optional[GuardVerdict]()
