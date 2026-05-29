"""Pure-predicate guards for HTTP/3 conformance (no I/O, no connection refs)."""

from navette.h3.guard_tags import (
    GUARD_TAG_DATA_BEFORE_HEADERS,
    GUARD_TAG_CTRL_NO_SETTINGS,
    GUARD_TAG_DATA_ON_CTRL,
    GUARD_TAG_HEADERS_ON_CTRL,
    GUARD_TAG_SECOND_SETTINGS,
    GUARD_TAG_CANCEL_PUSH_REQ,
)
from navette.quic.guard_predicates import GuardVerdict


struct H3StreamCtx(Copyable, Movable):
    """Per-stream context fed to H3 guard predicates.

    `kind` encodes the stream role: 0=request-bidi, 1=peer-control,
    2=peer-qpack-enc, 3=peer-qpack-dec. `headers_seen` flips true once
    the first HEADERS frame on a request stream has been dispatched.
    `settings_seen` flips true once a SETTINGS frame has been observed
    on a control stream. `first_frame_seen` flips true once ANY frame
    has arrived on a control stream — F32 keys on this so that
    second-frame-after-non-SETTINGS violations route to F33/F34 rather
    than re-firing F32. Request-stream predicates ignore the field.
    """

    var kind: UInt8
    var headers_seen: Bool
    var settings_seen: Bool
    var first_frame_seen: Bool

    def __init__(
        out self,
        *,
        kind: UInt8,
        headers_seen: Bool,
        settings_seen: Bool,
        first_frame_seen: Bool = False,
    ):
        self.kind = kind
        self.headers_seen = headers_seen
        self.settings_seen = settings_seen
        self.first_frame_seen = first_frame_seen

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.headers_seen = other.headers_seen
        self.settings_seen = other.settings_seen
        self.first_frame_seen = other.first_frame_seen

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.headers_seen = take.headers_seen
        self.settings_seen = take.settings_seen
        self.first_frame_seen = take.first_frame_seen


def predicate_f31_data_before_headers(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_FRAME_UNEXPECTED + tag) when a DATA frame arrives on a
    request-bidi stream before any HEADERS frame (RFC 9114 §4.1)."""
    if ctx.kind != UInt8(0):  # request-bidi only
        return Optional[GuardVerdict]()
    if frame_type != UInt64(0x00):  # 0x00 = DATA
        return Optional[GuardVerdict]()
    if ctx.headers_seen:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x0103),  # H3_FRAME_UNEXPECTED
        tag=String(GUARD_TAG_DATA_BEFORE_HEADERS),
    ))


def predicate_f32_first_control_not_settings(first_frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_MISSING_SETTINGS + tag) when the first frame on the
    peer control stream is not SETTINGS (RFC 9114 §6.2.1).

    Fires only when `ctx.first_frame_seen=False`. Once any frame has
    arrived, subsequent non-SETTINGS frames route to F33/F34 instead,
    so the predicate is purely a "first-frame" check and does not
    overlap the steady-state cohort."""
    if ctx.kind != UInt8(1):  # peer-control only
        return Optional[GuardVerdict]()
    if ctx.first_frame_seen:  # only the genuine first frame is eligible
        return Optional[GuardVerdict]()
    if ctx.settings_seen:
        return Optional[GuardVerdict]()
    if first_frame_type == UInt64(0x04):  # SETTINGS
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x010A),  # H3_MISSING_SETTINGS
        tag=String(GUARD_TAG_CTRL_NO_SETTINGS),
    ))


def predicate_f33_data_on_control(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_FRAME_UNEXPECTED + tag) when a DATA frame arrives
    on the peer control stream (RFC 9114 §7.2.1).

    Fires only when `ctx.first_frame_seen=True` — the first-frame DATA
    case routes to F32 (missing SETTINGS) instead. The check is what
    gives the cohort true predicate-layer exclusivity; at runtime the
    dispatch always sets `first_frame_seen=True` before reaching this
    branch, so the gate is a no-op for live traffic."""
    if ctx.kind != UInt8(1):  # peer-control only
        return Optional[GuardVerdict]()
    if not ctx.first_frame_seen:
        return Optional[GuardVerdict]()
    if frame_type != UInt64(0x00):  # 0x00 = DATA
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x0103),  # H3_FRAME_UNEXPECTED
        tag=String(GUARD_TAG_DATA_ON_CTRL),
    ))


def predicate_f34_headers_on_control(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_FRAME_UNEXPECTED + tag) when a HEADERS frame
    arrives on the peer control stream (RFC 9114 §7.2.2).

    Fires only when `ctx.first_frame_seen=True`; first-frame HEADERS
    routes to F32 instead. See F33's docstring for the dispatch-time
    reasoning."""
    if ctx.kind != UInt8(1):  # peer-control only
        return Optional[GuardVerdict]()
    if not ctx.first_frame_seen:
        return Optional[GuardVerdict]()
    if frame_type != UInt64(0x01):  # 0x01 = HEADERS
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x0103),  # H3_FRAME_UNEXPECTED
        tag=String(GUARD_TAG_HEADERS_ON_CTRL),
    ))


def predicate_f35_second_settings(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_FRAME_UNEXPECTED + tag) when a second SETTINGS
    frame arrives on the peer control stream (RFC 9114 §7.2.4)."""
    if ctx.kind != UInt8(1):  # peer-control only
        return Optional[GuardVerdict]()
    if frame_type != UInt64(0x04):  # 0x04 = SETTINGS
        return Optional[GuardVerdict]()
    if not ctx.settings_seen:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x0103),  # H3_FRAME_UNEXPECTED
        tag=String(GUARD_TAG_SECOND_SETTINGS),
    ))


def predicate_f36_cancel_push_on_request(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Return Some(H3_FRAME_UNEXPECTED + tag) when a CANCEL_PUSH frame
    arrives on a request-bidi stream (RFC 9114 §7.2.3)."""
    if ctx.kind != UInt8(0):  # request-bidi only
        return Optional[GuardVerdict]()
    if frame_type != UInt64(0x03):  # 0x03 = CANCEL_PUSH
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](GuardVerdict(
        error_code=UInt64(0x0103),  # H3_FRAME_UNEXPECTED
        tag=String(GUARD_TAG_CANCEL_PUSH_REQ),
    ))
