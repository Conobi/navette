# navette/quic/packet_builder.mojo
#
# Packet building primitives and send-path data types extracted from
# connection.mojo. All functions are free (no QuicConnection self).

from std.collections import Optional, Span

from navette.quic.codec import varint_len, write_u8_at
from navette.quic.cid_buf import CidBuf
from navette.quic.frame import (
    Frame,
    ConnectionCloseFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    ResetStreamFrame,
    StopSendingFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    serialize_frame,
    write_stream_frame_direct,
)
from navette.quic.stream import Stream, SendState
from navette.quic.stream_map import StreamMap
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
comptime ANTI_AMP_HEADER_FUDGE: UInt64 = 100
comptime MIN_PLAINTEXT_LEN: Int = 4
comptime MAX_DATAGRAM_SIZE: Int = 1200
comptime SCRATCH_PAYLOAD_CAP: Int = MAX_DATAGRAM_SIZE * 5
comptime SCRATCH_WRITER_CAP: Int = 256
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
    var payload: List[Byte]
    var ack_committed: Bool
    var has_stream_data: Bool

    def __init__(
        out self,
        space_idx: Int,
        var frames: List[Frame],
        var sent_records: List[SentStreamFrame],
        var payload: List[Byte],
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
    mut pkt_buf: List[Byte],
    mut protect: PacketProtect,
    peer_cid: Span[Byte, _],
    local_cid: Span[Byte, _],
    space_idx: Int,
    pn: UInt64,
    pn_len: Int,
    payload: List[Byte],
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
        header.dcid = CidBuf.from_span(peer_cid)
        header.scid = CidBuf.from_span(local_cid)
        if space_idx == 0:
            header.packet_type = PacketType.initial()
            # header.token/token_len already zero-initialized by PacketHeader().
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
    mut pkt_buf: List[Byte],
    mut protect: PacketProtect,
    header_budget: Int,
    space_idx: Int,
    pn: UInt64,
    pn_len: Int,
    payload: List[Byte],
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
    var pn_base = len(pkt_buf)
    pkt_buf.resize(pn_base + pn_len, Byte(0))
    for i in range(pn_len):
        var shift = UInt64((pn_len - 1 - i) * 8)
        pkt_buf[pn_base + i] = UInt8((truncated >> shift) & 0xFF)

    pkt_buf.extend(Span(payload))
    var pad_len = plaintext_len - len(payload) + AEAD_TAG_LEN
    pkt_buf.resize(len(pkt_buf) + pad_len, Byte(0))

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


# ── Standalone stream/FC frame emitters ────────────────────────────

def emit_one_stream_frame(
    sid: Int,
    p: UnsafePointer[Stream, MutUntrackedOrigin],
    ss: SendState,
    limit: Int,
    mut sent_records: List[SentStreamFrame],
    mut stream_payload: List[Byte],
    budget: Int,
    used: Int,
) raises -> Optional[Tuple[Int, UInt64]]:
    """Emit a single STREAM frame for one stream. Returns (new_used, conn_delta) or None."""
    var meta = p[].send_buf.value().prepare_frame(limit)
    if not meta:
        return None
    var frame_meta = meta.value()
    var frame_offset = frame_meta[0]
    var chunk_size = frame_meta[1]
    var frame_fin = frame_meta[2]
    var frame_len = UInt64(chunk_size)
    var data_view = p[].send_buf.value().data_span(frame_offset, chunk_size)
    var wl = write_stream_frame_direct(
        stream_payload, budget=budget - used,
        stream_id=p[].id, offset=frame_offset, data=data_view, fin=frame_fin,
    )
    debug_assert(wl > 0 and used + wl <= budget, "STREAM frame exceeds its charge")
    var new_used = used + wl
    var conn_delta = UInt64(0)
    var prev_end = frame_offset + frame_len
    if prev_end > p[].fc_send.value().received:
        conn_delta = prev_end - p[].fc_send.value().received
        p[].fc_send.value().add_received(conn_delta)
    if ss == SendState.READY:
        p[].send_state = Optional[SendState](SendState.SEND)
    if frame_fin and p[].send_buf.value().fin_offset:
        p[].send_state = Optional[SendState](SendState.DATA_SENT)
    var rec = SentStreamFrame()
    rec.kind = SSF_STREAM
    rec.stream_id = p[].id
    rec.offset = frame_offset
    rec.length = frame_len
    rec.fin = frame_fin
    sent_records.append(rec^)
    return Tuple[Int, UInt64](new_used, conn_delta)


def drain_max_stream_data_frames(
    mut stream_map: StreamMap,
    mut frames: List[Frame],
    mut sent_records: List[SentStreamFrame],
    budget: Int,
    mut used: Int,
) raises:
    """Drain MAX_STREAM_DATA control list with write-cursor compaction."""
    var write = 0
    var full = False
    for i in range(len(stream_map.control_max_stream_data)):
        var sid = stream_map.control_max_stream_data[i]
        if full:
            if write != i:
                stream_map.control_max_stream_data[write] = sid
            write += 1
            continue
        if not stream_map.has_stream(sid):
            continue
        var p = stream_map.stream_ptr(sid)
        if not p[].needs_max_stream_data or not p[].fc_recv:
            continue
        var next_limit = p[].fc_recv.value().next_limit()
        var wl = 1 + varint_len(p[].id) + varint_len(next_limit)
        if used + wl > budget:
            if write != i:
                stream_map.control_max_stream_data[write] = sid
            write += 1
            full = True
            continue
        var new_limit = p[].fc_recv.value().update_limit()
        p[].needs_max_stream_data = False
        var f = Frame.max_stream_data(MaxStreamDataFrame(p[].id, new_limit))
        used += f.wire_len()
        frames.append(f^)
        var rec = SentStreamFrame()
        rec.kind = SSF_MAX_STREAM_DATA
        rec.stream_id = p[].id
        sent_records.append(rec^)
    while len(stream_map.control_max_stream_data) > write:
        _ = stream_map.control_max_stream_data.pop()


def drain_reset_stream_frames(
    mut stream_map: StreamMap,
    mut frames: List[Frame],
    mut sent_records: List[SentStreamFrame],
    budget: Int,
    mut used: Int,
) raises:
    """Drain RESET_STREAM control list with write-cursor compaction."""
    var write = 0
    var full = False
    for i in range(len(stream_map.control_reset)):
        var sid = stream_map.control_reset[i]
        if full:
            if write != i:
                stream_map.control_reset[write] = sid
            write += 1
            continue
        if not stream_map.has_stream(sid):
            continue
        var p = stream_map.stream_ptr(sid)
        if not p[].needs_reset_stream:
            continue
        var rs_f = ResetStreamFrame(
            p[].id,
            p[].reset_stream_error,
            p[].reset_stream_final_size,
        )
        var f = Frame.reset_stream(rs_f)
        var wl = f.wire_len()
        if used + wl > budget:
            if write != i:
                stream_map.control_reset[write] = sid
            write += 1
            full = True
            continue
        frames.append(f^)
        used += wl
        p[].needs_reset_stream = False
        var rec = SentStreamFrame()
        rec.kind = SSF_RESET_STREAM
        rec.stream_id = p[].id
        sent_records.append(rec^)
    while len(stream_map.control_reset) > write:
        _ = stream_map.control_reset.pop()


def drain_stop_sending_frames(
    mut stream_map: StreamMap,
    mut frames: List[Frame],
    mut sent_records: List[SentStreamFrame],
    budget: Int,
    mut used: Int,
) raises:
    """Drain STOP_SENDING control list with write-cursor compaction."""
    var write = 0
    var full = False
    for i in range(len(stream_map.control_stop_sending)):
        var sid = stream_map.control_stop_sending[i]
        if full:
            if write != i:
                stream_map.control_stop_sending[write] = sid
            write += 1
            continue
        if not stream_map.has_stream(sid):
            continue
        var p = stream_map.stream_ptr(sid)
        if not p[].needs_stop_sending:
            continue
        var ss_f = StopSendingFrame(p[].id, p[].stop_sending_error)
        var f = Frame.stop_sending(ss_f)
        var wl = f.wire_len()
        if used + wl > budget:
            if write != i:
                stream_map.control_stop_sending[write] = sid
            write += 1
            full = True
            continue
        frames.append(f^)
        used += wl
        p[].needs_stop_sending = False
        var rec = SentStreamFrame()
        rec.kind = SSF_STOP_SENDING
        rec.stream_id = p[].id
        sent_records.append(rec^)
    while len(stream_map.control_stop_sending) > write:
        _ = stream_map.control_stop_sending.pop()


@always_inline
def emit_stream_frames(
    mut stream_map: StreamMap,
    mut sent_records: List[SentStreamFrame],
    mut stream_payload: List[Byte],
    budget: Int,
    mut used: Int,
) raises:
    """Emit STREAM frames from the sendable queue with round-robin fairness."""
    var max_bytes_per_frame = MAX_DATAGRAM_SIZE
    var initial_len = len(stream_map.sendable_queue)
    var popped = 0
    while popped < initial_len:
        var sid = stream_map.sendable_queue.popleft()
        popped += 1
        if sid not in stream_map.sendable_set:
            continue
        if sid not in stream_map.streams:
            stream_map.remove_sendable(sid)
            continue
        var conn_avail = stream_map.conn_fc_send.available()
        if conn_avail == 0:
            stream_map.sendable_queue.appendleft(sid)
            break
        var p = stream_map.stream_ptr(sid)
        if not p[].send_state or not p[].send_buf or not p[].fc_send:
            stream_map.remove_sendable(sid)
            continue
        var ss = p[].send_state.value()
        # DATA_SENT stays sendable: once the FIN is framed, lost bytes
        # re-queued by on_loss are only ever resent from here.
        if (ss != SendState.READY and ss != SendState.SEND
                and ss != SendState.DATA_SENT):
            stream_map.remove_sendable(sid)
            continue
        var stream_avail = p[].fc_send.value().available()
        var fin_pending = (
            p[].send_buf.value().fin and not p[].send_buf.value().fin_offset
        )
        if stream_avail == 0 and not fin_pending:
            stream_map.sendable_queue.append(sid)
            continue
        var hdr_charge = (
            1 + varint_len(p[].id)
            + varint_len(p[].send_buf.value().unsent_offset) + 2
        )
        var room = budget - used - hdr_charge
        if room < 0:
            stream_map.sendable_queue.appendleft(sid)
            break
        var limit = Int(conn_avail)
        if Int(stream_avail) < limit:
            limit = Int(stream_avail)
        if max_bytes_per_frame < limit:
            limit = max_bytes_per_frame
        if room < limit:
            limit = room
        var emitted = emit_one_stream_frame(
            sid, p, ss, limit, sent_records, stream_payload, budget, used,
        )
        if not emitted:
            stream_map.remove_sendable(sid)
            continue
        used = emitted.value()[0]
        var conn_delta = emitted.value()[1]
        if conn_delta > 0:
            stream_map.conn_fc_send.add_received(conn_delta)
        if not p[].send_buf.value().has_pending():
            stream_map.remove_sendable(sid)
        else:
            stream_map.sendable_queue.append(sid)


@always_inline
def emit_blocked_frames(
    mut stream_map: StreamMap,
    mut frames: List[Frame],
    budget: Int,
    mut used: Int,
) raises:
    """Emit DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED frames."""
    var conn_limit = stream_map.conn_fc_send.limit
    if (stream_map.conn_fc_send.received >= conn_limit
            and stream_map.conn_fc_send.blocked_at != conn_limit):
        var wl = 1 + varint_len(conn_limit)
        if used + wl <= budget:
            frames.append(Frame.data_blocked(conn_limit))
            used += wl
            stream_map.conn_fc_send.blocked_at = conn_limit
    var blocked_ids = List[Int]()
    for key in stream_map.sendable_set.keys():
        blocked_ids.append(key)
    for ref sid in blocked_ids:
        if not stream_map.has_stream(sid):
            continue
        var p = stream_map.stream_ptr(sid)
        if not p[].fc_send:
            continue
        var stream_limit = p[].fc_send.value().limit
        if (p[].fc_send.value().available() == UInt64(0)
                and p[].fc_send.value().blocked_at != stream_limit
                and stream_limit > UInt64(0)):
            var wl = 1 + varint_len(p[].id) + varint_len(stream_limit)
            if used + wl > budget:
                continue
            frames.append(Frame.stream_data_blocked(StreamDataBlockedFrame(p[].id, stream_limit)))
            used += wl
            p[].fc_send.value().blocked_at = stream_limit
    if stream_map.needs_streams_blocked_bidi:
        var bidi_limit = stream_map.peer_max_streams_bidi
        var wl = 1 + varint_len(bidi_limit)
        if stream_map.streams_blocked_at_bidi != bidi_limit and used + wl <= budget:
            frames.append(
                Frame.streams_blocked(StreamsBlockedFrame(bidi_limit, True))
            )
            used += wl
            stream_map.streams_blocked_at_bidi = bidi_limit
    if stream_map.needs_streams_blocked_uni:
        var uni_limit = stream_map.peer_max_streams_uni
        var wl = 1 + varint_len(uni_limit)
        if stream_map.streams_blocked_at_uni != uni_limit and used + wl <= budget:
            frames.append(
                Frame.streams_blocked(StreamsBlockedFrame(uni_limit, False))
            )
            used += wl
            stream_map.streams_blocked_at_uni = uni_limit

