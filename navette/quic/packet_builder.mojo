# navette/quic/packet_builder.mojo
#
# Packet building primitives and send-path data types extracted from
# connection.mojo. All functions are free (no QuicConnection self).

from std.collections import Optional, Span

from navette.quic.codec import varint_len
from navette.quic.frame import (
    Frame,
    ConnectionCloseFrame,
    serialize_frame,
)
from navette.quic.packet import (
    PacketType,
    PacketHeader,
    serialize_long_header_into,
    serialize_short_header_into,
    pn_truncate,
)
from navette.quic.packet_protect import PacketProtect


# ── Constants ───────────────────────────────────────────────────────

comptime AEAD_TAG_LEN: Int = 16
comptime MAX_PN_LEN: Int = 4
comptime HP_SAMPLE_LEN: Int = 16
comptime ANTI_AMP_HEADER_FUDGE: UInt64 = 100
comptime MIN_PLAINTEXT_LEN: Int = 4
comptime MAX_DATAGRAM_SIZE: Int = 1200
comptime MAX_CLOSE_REASON_BYTES: Int = 256

# ── SentStreamFrame kind tags ───────────────────────────────────────

comptime SSF_STREAM: UInt8 = 0
comptime SSF_RESET_STREAM: UInt8 = 1
comptime SSF_STOP_SENDING: UInt8 = 2
comptime SSF_MAX_DATA: UInt8 = 3
comptime SSF_MAX_STREAM_DATA: UInt8 = 4
comptime SSF_MAX_STREAMS_BIDI: UInt8 = 5
comptime SSF_MAX_STREAMS_UNI: UInt8 = 6
comptime SSF_NEW_CID: UInt8 = 7
comptime SSF_RETIRE_CID: UInt8 = 8


# ── Data structs ────────────────────────────────────────────────────


struct SentStreamFrame(Copyable, Movable):
    """Record of a stream-layer frame sent in the Application space.

    Used to re-apply state on ACK (confirm transitions, release FC credit)
    and on loss (re-queue data, clear `advertised`/`needs_*` flags).
    """

    var kind: UInt8
    var stream_id: UInt64
    var offset: UInt64
    var length: UInt64
    var fin: Bool
    var cid_seq: UInt64

    def __init__(out self):
        self.kind = UInt8(0)
        self.stream_id = UInt64(0)
        self.offset = UInt64(0)
        self.length = UInt64(0)
        self.fin = False
        self.cid_seq = UInt64(0)


struct PacketPlan(Copyable, Movable):
    """One packet between frame assembly and encryption.

    `send()` plans every keyed space first so padding can land in the last
    packet; only then are PNs allocated and packets protected.
    """

    var space_idx: Int
    var frames: List[Frame]
    var sent_records: List[SentStreamFrame]
    var payload: List[UInt8]
    var ack_committed: Bool
    var has_stream_data: Bool

    def __init__(
        out self,
        space_idx: Int,
        var frames: List[Frame],
        var sent_records: List[SentStreamFrame],
        var payload: List[UInt8],
        ack_committed: Bool,
        has_stream_data: Bool = False,
    ):
        self.space_idx = space_idx
        self.frames = frames^
        self.sent_records = sent_records^
        self.payload = payload^
        self.ack_committed = ack_committed
        self.has_stream_data = has_stream_data


# ── Send-path utility functions ─────────────────────────────────────


def datagram_budget() -> Int:
    """Fixed datagram budget (PMTUD not implemented)."""
    return MAX_DATAGRAM_SIZE


def amp_allowance(bytes_received: UInt64, bytes_sent: UInt64) -> Int:
    """Bytes an unvalidated server may still send, saturating at 0."""
    var cap = 3 * bytes_received
    var spent = bytes_sent + ANTI_AMP_HEADER_FUDGE
    if spent >= cap:
        return 0
    return Int(cap - spent)


def header_len(space_idx: Int, local_cid_len: Int, peer_cid_len: Int) -> Int:
    """Budgeted header bytes for a packet in the given space."""
    if space_idx == 0:
        return 7 + peer_cid_len + local_cid_len + 1 + 2 + MAX_PN_LEN
    if space_idx == 1:
        return 7 + peer_cid_len + local_cid_len + 2 + MAX_PN_LEN
    return 1 + peer_cid_len + MAX_PN_LEN


# ── Packet building ─────────────────────────────────────────────────


def build_packet(
    mut pkt_buf: List[UInt8],
    mut protect: PacketProtect,
    peer_cid: Span[UInt8, _],
    local_cid: Span[UInt8, _],
    space_idx: Int,
    pn: UInt64,
    pn_len: Int,
    payload: List[UInt8],
    header_budget: Int,
    padding: Int = 0,
) raises:
    """Build a complete encrypted QUIC packet into pkt_buf."""
    pkt_buf.clear()

    var plaintext_len = len(payload) + padding
    if plaintext_len < MIN_PLAINTEXT_LEN:
        plaintext_len = MIN_PLAINTEXT_LEN
    var payload_ciphertext_len = plaintext_len + AEAD_TAG_LEN

    if space_idx == 0 or space_idx == 1:
        var header = PacketHeader()
        header.is_long_header = True
        header.version = UInt32(1)
        header.dcid = List[UInt8](capacity=len(peer_cid))
        for b in peer_cid:
            header.dcid.append(b)
        header.scid = List[UInt8](capacity=len(local_cid))
        for b in local_cid:
            header.scid.append(b)
        if space_idx == 0:
            header.packet_type = PacketType.initial()
            header.token = List[UInt8]()
        else:
            header.packet_type = PacketType.handshake()
        header.payload_length = UInt64(pn_len + payload_ciphertext_len)
        serialize_long_header_into(header, pkt_buf)
    else:
        serialize_short_header_into(peer_cid, pkt_buf)

    seal_packet(
        pkt_buf, protect, header_budget,
        space_idx, pn, pn_len, payload, plaintext_len,
    )


def seal_packet(
    mut pkt_buf: List[UInt8],
    mut protect: PacketProtect,
    header_budget: Int,
    space_idx: Int,
    pn: UInt64,
    pn_len: Int,
    payload: List[UInt8],
    plaintext_len: Int,
) raises:
    """Encode PN, append payload, encrypt and apply header protection."""
    pkt_buf[0] = (pkt_buf[0] & 0xFC) | UInt8(pn_len - 1)

    var pn_offset = len(pkt_buf)
    debug_assert(
        pn_offset + pn_len <= header_budget,
        "header exceeds its budgeted length",
    )

    var truncated = pn_truncate(pn, pn_len)
    for i in range(pn_len):
        var shift = UInt64((pn_len - 1 - i) * 8)
        pkt_buf.append(UInt8((truncated >> shift) & 0xFF))

    pkt_buf.extend(Span(payload))
    for _ in range(plaintext_len - len(payload) + AEAD_TAG_LEN):
        pkt_buf.append(UInt8(0))

    var total_len = len(pkt_buf)
    var pkt_ptr = pkt_buf.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()

    var hdr_len = pn_offset + pn_len
    _ = protect.encrypt_payload_in_place(
        space_idx, pn, pkt_ptr, hdr_len,
        plaintext_len, total_len,
    )

    protect.protect_header_ptr(
        space_idx, pkt_ptr, total_len, pn_offset, pn_len,
    )
