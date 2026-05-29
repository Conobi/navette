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
    on a control stream.
    """

    var kind: UInt8
    var headers_seen: Bool
    var settings_seen: Bool

    def __init__(out self, *, kind: UInt8, headers_seen: Bool, settings_seen: Bool):
        self.kind = kind
        self.headers_seen = headers_seen
        self.settings_seen = settings_seen

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.headers_seen = other.headers_seen
        self.settings_seen = other.settings_seen

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.headers_seen = take.headers_seen
        self.settings_seen = take.settings_seen


def predicate_f31_data_before_headers(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: DATA on a request bidi stream before HEADERS has been seen."""
    return Optional[GuardVerdict]()


def predicate_f32_first_control_not_settings(first_frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: first frame on the peer control stream is not SETTINGS."""
    return Optional[GuardVerdict]()


def predicate_f33_data_on_control(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: DATA frame received on a control stream."""
    return Optional[GuardVerdict]()


def predicate_f34_headers_on_control(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: HEADERS frame received on a control stream."""
    return Optional[GuardVerdict]()


def predicate_f35_second_settings(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: SETTINGS frame received after the first SETTINGS frame."""
    return Optional[GuardVerdict]()


def predicate_f36_cancel_push_on_request(frame_type: UInt64, ctx: H3StreamCtx) -> Optional[GuardVerdict]:
    """Stub: CANCEL_PUSH frame received on a request stream."""
    return Optional[GuardVerdict]()
