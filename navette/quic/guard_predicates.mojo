"""Pure-predicate guards for QUIC conformance (no I/O, no connection refs)."""

from navette.quic.guard_tags import (
    GUARD_TAG_RESET_SEND_ONLY,
    GUARD_TAG_STOP_LOCAL_NOT_CREATED,
    GUARD_TAG_NO_FRAMES,
    GUARD_TAG_UNKNOWN_FRAME,
    GUARD_TAG_RESERVED_BITS_HS,
    GUARD_TAG_RESERVED_BITS_SHORT,
    GUARD_TAG_PATH_CHALLENGE_HS,
    GUARD_TAG_DATAGRAM_HS,
    GUARD_TAG_MIGRATION_DISABLED,
    GUARD_TAG_NEW_TOKEN_SERVER,
    GUARD_TAG_HANDSHAKE_DONE_SERVER,
    GUARD_TAG_MAX_STREAM_DATA_NONEXIST,
    GUARD_TAG_MAX_STREAM_DATA_RECV_ONLY,
    GUARD_TAG_MAX_STREAMS_OVERFLOW,
    GUARD_TAG_STREAMS_BLOCKED_OVERFLOW,
    GUARD_TAG_CID_RETIRE_PRIOR_GT_SEQ,
    GUARD_TAG_CID_ZERO_LENGTH,
    GUARD_TAG_STREAM_LARGE_OFFSET,
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


struct MaxStreamDataCtx(Copyable, Movable):
    """Inputs to the F18 / F19 MAX_STREAM_DATA guard.

    `exists` reflects whether the local stream map knows about
    `stream_id`; `has_send_side` reflects whether this endpoint sends on
    the stream (RFC 9000 §3 — only the sender of a stream can be the
    recipient of MAX_STREAM_DATA). A False/False pair indicates a stream
    the peer never created; True/False is a recv-only stream where the
    peer is the sender.
    """

    var stream_id: UInt64
    var exists: Bool
    var has_send_side: Bool

    def __init__(out self, *, stream_id: UInt64, exists: Bool, has_send_side: Bool):
        self.stream_id = stream_id
        self.exists = exists
        self.has_send_side = has_send_side

    def __init__(out self, *, other: Self):
        self.stream_id = other.stream_id
        self.exists = other.exists
        self.has_send_side = other.has_send_side

    def __init__(out self, *, deinit take: Self):
        self.stream_id = take.stream_id
        self.exists = take.exists
        self.has_send_side = take.has_send_side


def predicate_f18_f19_max_stream_data(
    ctx: MaxStreamDataCtx,
) -> Optional[GuardVerdict]:
    """RFC 9000 §19.10: MAX_STREAM_DATA on a stream that does not exist
    (F18) or on a recv-only stream where the peer is the sender (F19)
    are both STREAM_STATE_ERROR.

    Per RFC 9000 §19.10 the error namespace is STREAM_STATE_ERROR (0x05)
    regardless of whether the offence is non-existence or wrong-side.
    """
    if not ctx.exists:
        return Optional[GuardVerdict](
            GuardVerdict(
                error_code=UInt64(0x05),  # STREAM_STATE_ERROR
                tag=String(GUARD_TAG_MAX_STREAM_DATA_NONEXIST),
            )
        )
    if not ctx.has_send_side:
        return Optional[GuardVerdict](
            GuardVerdict(
                error_code=UInt64(0x05),  # STREAM_STATE_ERROR
                tag=String(GUARD_TAG_MAX_STREAM_DATA_RECV_ONLY),
            )
        )
    return Optional[GuardVerdict]()


def check_max_streams_value(v: UInt64) -> Optional[GuardVerdict]:
    """RFC 9000 §19.11: MAX_STREAMS carries a stream-count limit that MUST
    NOT exceed 2^60 (the wire format cannot represent a valid stream id
    beyond that). A value > 2^60 is FRAME_ENCODING_ERROR. Used for F20.
    """
    if v <= (UInt64(1) << 60):
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x07),  # FRAME_ENCODING_ERROR
            tag=String(GUARD_TAG_MAX_STREAMS_OVERFLOW),
        )
    )


def check_streams_blocked_value(v: UInt64) -> Optional[GuardVerdict]:
    """RFC 9000 §19.14: STREAMS_BLOCKED carries the same stream-count
    field as MAX_STREAMS and is subject to the identical 2^60 cap. A
    limit > 2^60 cannot describe a valid stream id and MUST close the
    connection with FRAME_ENCODING_ERROR. Used for F21.
    """
    if v <= (UInt64(1) << 60):
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x07),  # FRAME_ENCODING_ERROR
            tag=String(GUARD_TAG_STREAMS_BLOCKED_OVERFLOW),
        )
    )


def check_new_connection_id_retire_prior(
    seq_num: UInt64, retire_prior_to: UInt64
) -> Optional[GuardVerdict]:
    """RFC 9000 §19.15: in a NEW_CONNECTION_ID frame, `Retire Prior To`
    MUST be less than or equal to `Sequence Number`. A frame with
    `retire_prior_to > seq_num` is malformed and MUST close the
    connection with FRAME_ENCODING_ERROR (0x07). Used for F22.
    """
    if retire_prior_to <= seq_num:
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x07),  # FRAME_ENCODING_ERROR
            tag=String(GUARD_TAG_CID_RETIRE_PRIOR_GT_SEQ),
        )
    )


def stream_offset_exceeds_fc(
    offset: UInt64, data_len: UInt64, fc_limit: UInt64
) -> Bool:
    """RFC 9000 §4.1: a STREAM frame whose `offset + data_len` exceeds
    the receiver's per-stream flow-control limit MUST close the
    connection with FLOW_CONTROL_ERROR. Returns True when the frame is
    out of bounds; also returns True on UInt64 overflow (`offset +
    data_len < offset`), which is impossible to express within a valid
    flow-control window. Used for F01.
    """
    var sum = offset + data_len
    if sum < offset:
        return True  # arithmetic overflow — far beyond any legal window
    return sum > fc_limit


def check_new_connection_id_length(cid_len: UInt64) -> Optional[GuardVerdict]:
    """RFC 9000 §19.15: the `Length` field of a NEW_CONNECTION_ID frame
    MUST be in the range 1..20 inclusive. A frame whose connection id
    length falls outside that range is a wire-encoding error and MUST
    close the connection with FRAME_ENCODING_ERROR (0x07). Used for F23.
    """
    if cid_len >= UInt64(1) and cid_len <= UInt64(20):
        return Optional[GuardVerdict]()
    return Optional[GuardVerdict](
        GuardVerdict(
            error_code=UInt64(0x07),  # FRAME_ENCODING_ERROR
            tag=String(GUARD_TAG_CID_ZERO_LENGTH),
        )
    )


def is_client_only_frame_on_server(type_id: UInt64, is_server: Bool) -> Bool:
    """RFC 9000 §19.7 (NEW_TOKEN, 0x07) and §19.20 (HANDSHAKE_DONE, 0x1E)
    are server-to-client only. If a server receives either, the peer is
    misbehaving and the connection MUST close with PROTOCOL_VIOLATION.
    """
    if not is_server:
        return False
    return type_id == UInt64(0x07) or type_id == UInt64(0x1E)


def is_path_challenge_in_handshake(type_id: UInt64, space_idx: Int) -> Bool:
    """RFC 9000 §17.2.4: PATH_CHALLENGE / PATH_RESPONSE (0x1A / 0x1B) are
    allowed only in 1-RTT packets (space_idx == 2). Receipt in Initial
    (0) or Handshake (1) is a PROTOCOL_VIOLATION.
    """
    var is_path = type_id == UInt64(0x1A) or type_id == UInt64(0x1B)
    return is_path and space_idx < 2


def is_datagram_in_handshake(type_id: UInt64, space_idx: Int) -> Bool:
    """RFC 9221 §5: DATAGRAM (0x30) and DATAGRAM_LEN (0x31) are 1-RTT only.

    Receipt in Initial (0) or Handshake (1) MUST be treated as a
    PROTOCOL_VIOLATION; the dispatch site closes with error 0x0A.
    Mirrors the shape of `is_path_challenge_in_handshake` so the gate
    composes the same way at the top of `_dispatch_frame`.
    """
    var is_dgram = type_id == UInt64(0x30) or type_id == UInt64(0x31)
    return is_dgram and space_idx < 2


def is_unknown_frame_type(type_id: UInt64) -> Bool:
    """Return True iff `type_id` is outside the recognized frame-type set.

    RFC 9000 §19 baseline: PADDING..NEW_TOKEN (0x00..0x07); STREAM
    (0x08..0x0F, low 3 bits encode OFF/LEN/FIN flags); MAX_DATA..HANDSHAKE_DONE
    (0x10..0x1E). RFC 9221 extension: DATAGRAM (0x30) and DATAGRAM_LEN (0x31).
    Everything else MUST be treated as unknown and closed with
    FRAME_ENCODING_ERROR (RFC 9000 §12.4). Note that this predicate is
    permission-blind — `frame_allowed_in_packet_type` is the authority for
    "is this frame legal in this packet epoch" (DATAGRAMs are 1-RTT-only).
    """
    if type_id <= UInt64(0x07):
        return False
    if type_id >= UInt64(0x08) and type_id <= UInt64(0x0F):
        return False
    if type_id >= UInt64(0x10) and type_id <= UInt64(0x1E):
        return False
    if type_id == UInt64(0x30) or type_id == UInt64(0x31):
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
