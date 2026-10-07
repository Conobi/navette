# src/quic/cid.mojo
#
# Connection ID management for QUIC — RFC 9000 §5.
#
# Handles issuance of local CIDs (with HMAC-SHA256 reset tokens),
# tracking remote CIDs received via NEW_CONNECTION_ID frames and
# retirement via RETIRE_CONNECTION_ID, with every per-peer list bounded.

from std.memory import Pointer
from std.collections import Span

from navette.tls.lib import SharedLibrary
from navette.quic.cid_buf import CidBuf
from navette.util.byte_vec import ByteVec
from navette.util.secure_random import fill_random
from navette.util.siphash import SipKey, siphash13
from navette.quic.error import CONNECTION_ID_LIMIT_ERROR, PROTOCOL_VIOLATION
from navette.quic.guard_predicates import GuardVerdict


# ── CID state constants ────────────────────────────────────────────────────────

comptime CID_ACTIVE: UInt8 = 0
comptime CID_PENDING_RETIRE: UInt8 = 1
comptime CID_RETIRED: UInt8 = 2

# Most local CIDs we keep active at once, whatever the peer's
# active_connection_id_limit (a varint up to 2^62-1). RFC 9000 Section 5.1.1
# allows issuing fewer than the peer's limit; quic-go and msquic keep 4,
# ngtcp2 8, quiche min(peer, 2). Without it one handshake drives an
# unbounded issuance loop (getrandom + HMAC + allocation per CID).
comptime MAX_ISSUED_CIDS = 4

# Outstanding (unacknowledged) retirements of the peer's CIDs allowed per
# CID we let the peer keep active; quiche's RETIRED_CONN_ID_LIMIT_MULTIPLIER.
comptime RETIRE_QUEUE_MULTIPLIER = 3
# Hard ceiling on outstanding retirements, whatever our own limit is.
comptime MAX_RETIRE_QUEUE = 64


def clamp_local_active_limit(limit: UInt64) -> UInt64:
    """Our active_connection_id_limit held to [2, MAX_RETIRE_QUEUE].

    2 is the RFC 9000 Section 18.2 minimum. The ceiling keeps the stored
    peer CIDs and the retire backlog small. The transport parameter we
    advertise must go through this too, or a peer staying within the
    advertised limit would be closed for exceeding the enforced one.
    """
    return min(max(limit, UInt64(2)), UInt64(MAX_RETIRE_QUEUE))


# Key of the stateless reset tokens: one per server, so every connection of
# the server derives the same token for a CID (RFC 9000 Section 10.3).
comptime ResetKey = InlineArray[UInt8, 32]

# Close reasons for CID frame violations.
comptime CID_REASON_LIMIT = "NEW_CONNECTION_ID exceeds active_connection_id_limit"
comptime CID_REASON_RETIRE_BACKLOG = "too many unacknowledged RETIRE_CONNECTION_ID"
comptime CID_REASON_CONFLICT = "NEW_CONNECTION_ID conflicts with a known sequence or CID"
comptime CID_REASON_RETIRE_UNISSUED = "RETIRE_CONNECTION_ID for a sequence never issued"
comptime CID_REASON_RETIRE_OWN_DCID = "RETIRE_CONNECTION_ID retires the packet's own DCID"


# ── CidEntry ──────────────────────────────────────────────────────────────────


@fieldwise_init
struct CidEntry(Copyable, Movable):
    """A connection ID with its stateless reset token; inline bytes, so a copy never allocates."""

    var cid: CidBuf
    var sequence: UInt64
    var reset_token: ByteVec[16]
    var state: UInt8              # CID_ACTIVE / CID_PENDING_RETIRE / CID_RETIRED
    var advertised: Bool          # True once a NEW_CONNECTION_ID frame has been sent


# ── CidManager ────────────────────────────────────────────────────────────────


struct CidManager(Movable):
    """Manages local and remote connection IDs for a QUIC connection.

    Local CIDs: issued by us, used by the peer as their DCID.
    Remote CIDs: provided by the peer, used by us as our DCID.

    Both lists hold only live entries: a retired CID is removed at once
    (remote: once its RETIRE_CONNECTION_ID is queued; local: when the
    peer retires it), so memory is bounded by `local_active_limit`
    remote and `MAX_ISSUED_CIDS` local entries whatever the peer sends.
    Frame handlers return a `GuardVerdict` instead of raising; the
    connection closes with it.
    """

    var local_cids: List[CidEntry]         # CIDs we issued, all Active
    var local_next_seq: UInt64             # next sequence number for local CIDs
    var local_retire_prior_to: UInt64      # our retire_prior_to for outgoing NEW_CID
    var remote_cids: List[CidEntry]        # peer's CIDs, all Active
    var remote_active_cid_seq: UInt64      # seq of CID we're currently using
    var local_active_limit: UInt64         # our active_connection_id_limit
    var _peer_active_limit: UInt64         # peer's limit, unclamped; set via set_peer_active_limit
    var retire_queue: List[UInt64]         # seqs whose RETIRE_CONNECTION_ID is still unsent
    var _retire_unacked: List[UInt64]      # seqs retired but not yet acknowledged (superset of retire_queue)
    var retire_queue_cap: Int              # max len(_retire_unacked), from local_active_limit
    var highest_retire_prior_to: UInt64    # highest retire_prior_to from peer
    var _lib: SharedLibrary                # ref-counted RustlsLibrary for HMAC-SHA256
    var _reset_key: ResetKey               # HMAC-SHA256 key of the reset tokens; never re-drawn
    var cid_epoch: UInt64                  # bumped whenever `local_cids` gains or loses an entry

    def __init__(
        out self,
        lib: SharedLibrary,
        initial_local_cid: Span[Byte, _],
        initial_remote_cid: Span[Byte, _],
        local_active_limit: UInt64,
        peer_active_limit: UInt64,
        reset_key: Optional[ResetKey] = None,
    ) raises:
        """Initialise a CidManager.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            initial_local_cid:  The CID we present as SCID in Initial packets.
            initial_remote_cid: The peer's initial CID (their SCID / our DCID).
            local_active_limit: The active_connection_id_limit we advertise,
                clamped by `clamp_local_active_limit`; bounds the peer CIDs
                we store and the retire backlog.
            peer_active_limit:  Peer's active_connection_id_limit transport
                parameter; issuance is clamped to MAX_ISSUED_CIDS.
            reset_key: The server-wide reset-token key; None draws one for
                this connection alone, as a client does.

        Raises:
            If the kernel CSPRNG fails while drawing the key.
        """
        self._lib = SharedLibrary(copy=lib)
        self._reset_key = ResetKey(fill=UInt8(0))
        if reset_key:
            self._reset_key = reset_key.value().copy()
        else:
            fill_random(Span(self._reset_key))

        # The initial CID travels in the handshake, not in a
        # NEW_CONNECTION_ID frame, so it starts out advertised.
        var local_cid = CidBuf.from_span(initial_local_cid)
        var token = _hmac_sha256_truncate16(self._lib, Span(self._reset_key), initial_local_cid)
        self.local_cids = [CidEntry(local_cid^, UInt64(0), token^, CID_ACTIVE, True)]
        self.local_next_seq = UInt64(1)
        self.local_retire_prior_to = UInt64(0)

        # The peer's initial CID: its token, if any, is not tracked.
        var zero_token = ByteVec[16](_storage=InlineArray[Byte, 16](fill=Byte(0)), _len=16)
        self.remote_cids = [
            CidEntry(CidBuf.from_span(initial_remote_cid), UInt64(0), zero_token^, CID_ACTIVE, False)
        ]
        self.remote_active_cid_seq = UInt64(0)

        self.local_active_limit = clamp_local_active_limit(local_active_limit)
        self._peer_active_limit = UInt64(0)
        self.retire_queue = List[UInt64]()
        self._retire_unacked = List[UInt64]()
        var scaled = self.local_active_limit * UInt64(
            RETIRE_QUEUE_MULTIPLIER
        )
        self.retire_queue_cap = Int(min(scaled, UInt64(MAX_RETIRE_QUEUE)))
        self.highest_retire_prior_to = UInt64(0)
        self.cid_epoch = UInt64(0)
        self.set_peer_active_limit(peer_active_limit)

    def set_peer_active_limit(mut self, limit: UInt64):
        """Record the peer's limit; the only writer of `_peer_active_limit`.

        `limit` is untrusted (up to 2^62-1): every derived quantity goes
        through `issue_limit()` so no arithmetic sees the raw value.
        """
        self._peer_active_limit = limit

    def peer_active_limit(self) -> UInt64:
        """The peer's advertised limit, unclamped."""
        return self._peer_active_limit

    def issue_limit(self) -> Int:
        """Active local CIDs we keep: min(peer limit, MAX_ISSUED_CIDS)."""
        if self._peer_active_limit < UInt64(MAX_ISSUED_CIDS):
            return Int(self._peer_active_limit)
        return MAX_ISSUED_CIDS

    # ── Reset tokens ──────────────────────────────────────────────────────────

    def generate_reset_token(self, cid: Span[Byte, _]) raises -> ByteVec[16]:
        """HMAC-SHA256(reset key, cid)[:16]: the same CID always maps to the same token."""
        return _hmac_sha256_truncate16(self._lib, Span(self._reset_key), cid)

    # ── Local CID issuance ────────────────────────────────────────────────────

    def issue_new_cid(mut self) raises -> Optional[CidEntry]:
        """Issue a new local CID if below `issue_limit()`.

        Returns the new CidEntry so the caller can build a NEW_CONNECTION_ID frame,
        or None once `issue_limit()` active CIDs exist.
        """
        if self.active_local_count() >= self.issue_limit():
            return None

        var new_cid = random_cid()
        var token = self.generate_reset_token(new_cid.as_span())
        var entry = CidEntry(new_cid^, self.local_next_seq, token^, CID_ACTIVE, False)
        self.local_next_seq += UInt64(1)
        self.local_cids.append(entry.copy())
        self.cid_epoch += UInt64(1)
        return entry^

    # ── Remote CID reception ──────────────────────────────────────────────────

    def on_new_connection_id(
        mut self,
        seq: UInt64,
        retire_prior_to: UInt64,
        cid: Span[mut=False, Byte, _],
        reset_token: Span[mut=False, Byte, _],
    ) -> Optional[GuardVerdict]:
        """Process a NEW_CONNECTION_ID frame (RFC 9000 Sections 5.1.1, 19.15).

        The caller has already checked `retire_prior_to <= seq`, the CID
        length (at most 20) and the token length (16). Outcomes:
        - exact repeat of a stored (seq, CID, token): ignored;
        - seq or CID matching a stored entry otherwise: PROTOCOL_VIOLATION,
          checked first, as quiche does, so a stale seq cannot smuggle in
          a CID we already hold;
        - seq below the highest retire_prior_to seen: not stored, one
          RETIRE_CONNECTION_ID queued (none while one is outstanding);
        - a retire_prior_to increase drops every older entry and queues its
          retirement, moving `remote_active_cid_seq` off a retired CID;
        - storing it would exceed `local_active_limit`, or the retirements
          would exceed `retire_queue_cap` unacknowledged:
          CONNECTION_ID_LIMIT_ERROR (quiche's IdLimit, same cap rule).

        Returns the verdict to close with, or None.
        """
        for ref e in self.remote_cids:
            var same_seq = e.sequence == seq
            var same_cid = e.cid.as_span() == cid
            if same_seq or same_cid:
                if same_seq and same_cid and e.reset_token.as_span() == reset_token:
                    return None
                return _verdict(PROTOCOL_VIOLATION, CID_REASON_CONFLICT)

        if seq < self.highest_retire_prior_to:
            if not self._queue_retirement(seq):
                return _verdict(CONNECTION_ID_LIMIT_ERROR, CID_REASON_RETIRE_BACKLOG)
            return None

        var backlog_full = False
        if retire_prior_to > self.highest_retire_prior_to:
            self.highest_retire_prior_to = retire_prior_to
            var i = 0
            while i < len(self.remote_cids):
                if self.remote_cids[i].sequence < retire_prior_to:
                    if not self._queue_retirement(self.remote_cids[i].sequence):
                        backlog_full = True
                    _ = self.remote_cids.pop(i)
                else:
                    i += 1

        if UInt64(len(self.remote_cids)) >= self.local_active_limit:
            return _verdict(CONNECTION_ID_LIMIT_ERROR, CID_REASON_LIMIT)

        var token = ByteVec[16]()
        _ = token.extend_truncated(reset_token)
        self.remote_cids.append(CidEntry(CidBuf.from_span(cid), seq, token^, CID_ACTIVE, False))
        if self.remote_active_cid_seq < self.highest_retire_prior_to:
            var lowest = seq
            for ref e in self.remote_cids:
                lowest = min(lowest, e.sequence)
            self.remote_active_cid_seq = lowest

        if backlog_full:
            return _verdict(CONNECTION_ID_LIMIT_ERROR, CID_REASON_RETIRE_BACKLOG)
        return None

    def retire_remote(mut self, seq: UInt64) -> Bool:
        """Retire one of the peer's CIDs on our own initiative (e.g. migration).

        Drops the entry and queues its RETIRE_CONNECTION_ID. Returns False,
        changing nothing, when the retire backlog is full.
        """
        if not self._queue_retirement(seq):
            return False
        for i in range(len(self.remote_cids)):
            if self.remote_cids[i].sequence == seq:
                _ = self.remote_cids.pop(i)
                break
        return True

    def _queue_retirement(mut self, seq: UInt64) -> Bool:
        """Owe the peer a RETIRE_CONNECTION_ID for `seq`.

        A seq already outstanding is not queued twice (RFC 9000 Section
        19.15: "unless it has already done so"). Returns False when
        `retire_queue_cap` retirements are already unacknowledged: a peer
        that keeps retiring CIDs without acknowledging ours would otherwise
        grow this backlog at line rate.
        """
        for ref s in self._retire_unacked:
            if s == seq:
                return True
        if len(self._retire_unacked) >= self.retire_queue_cap:
            return False
        self._retire_unacked.append(seq)
        self.retire_queue.append(seq)
        return True

    # ── Loss-recovery re-queue ────────────────────────────────────────────────

    def requeue_retire(mut self, sequence: UInt64):
        """Re-queue an unsent or lost RETIRE_CONNECTION_ID.

        Skips a seq already queued or already acknowledged, so the queue
        stays a subset of the outstanding retirements and within
        `retire_queue_cap`.
        """
        if len(self.retire_queue) >= self.retire_queue_cap:
            return
        for ref s in self.retire_queue:
            if s == sequence:
                return
        for ref s in self._retire_unacked:
            if s == sequence:
                self.retire_queue.append(sequence)
                return

    def on_retire_acked(mut self, sequence: UInt64):
        """The RETIRE_CONNECTION_ID for `sequence` was acknowledged; free its slot."""
        for i in range(len(self._retire_unacked)):
            if self._retire_unacked[i] == sequence:
                _ = self._retire_unacked.pop(i)
                return

    # ── Local CID retirement (peer sends RETIRE_CONNECTION_ID) ────────────────

    def on_retire_connection_id(
        mut self, sequence: UInt64, packet_dcid: Span[Byte, _]
    ) raises -> Optional[GuardVerdict]:
        """Handle a RETIRE_CONNECTION_ID frame (RFC 9000 Section 19.16).

        `packet_dcid` is the DCID of the packet carrying the frame (empty
        when unknown). A sequence never issued, or one naming
        `packet_dcid`, is a PROTOCOL_VIOLATION; a sequence already retired
        is ignored. The retired entry is dropped from `local_cids` (bumping
        `cid_epoch`, so the server unregisters its demux key) and a
        replacement is issued if the active count fell below `issue_limit()`.
        """
        if sequence >= self.local_next_seq:
            return _verdict(PROTOCOL_VIOLATION, CID_REASON_RETIRE_UNISSUED)
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                if len(packet_dcid) > 0 and self.local_cids[i].cid.as_span() == packet_dcid:
                    return _verdict(PROTOCOL_VIOLATION, CID_REASON_RETIRE_OWN_DCID)
                _ = self.local_cids.pop(i)
                self.cid_epoch += UInt64(1)
                if self.active_local_count() < self.issue_limit():
                    _ = self.issue_new_cid()
                return None
        return None

    def on_retire_connection_id(
        mut self, sequence: UInt64
    ) raises -> Optional[GuardVerdict]:
        """`on_retire_connection_id` without the carrying packet's DCID check."""
        return self.on_retire_connection_id(
            sequence, Span[Byte, ImmStaticOrigin]()
        )

    # ── Drain retirement queue ────────────────────────────────────────────────

    def pending_retire_frames(mut self) -> List[UInt64]:
        """Drain the unsent retirements; they stay outstanding until acked.

        The caller builds the frames and reports each one's fate through
        `on_retire_acked` or `requeue_retire`.
        """
        var result = self.retire_queue^
        self.retire_queue = List[UInt64]()
        return result^

    # ── Predicates ────────────────────────────────────────────────────────────

    def active_local_count(self) -> Int:
        """Count Active local CIDs."""
        var count = 0
        for ref entry in self.local_cids:
            if entry.state == CID_ACTIVE:
                count += 1
        return count

    def active_remote_count(self) -> Int:
        """Count Active remote CIDs."""
        var count = 0
        for ref entry in self.remote_cids:
            if entry.state == CID_ACTIVE:
                count += 1
        return count

    def needs_new_cid(self) -> Bool:
        """True if a new local CID should be issued (count below `issue_limit()`)."""
        return self.active_local_count() < self.issue_limit()

    def has_unadvertised(self) -> Bool:
        """Non-allocating: an Active local CID still owes a NEW_CONNECTION_ID."""
        for ref entry in self.local_cids:
            if entry.state == CID_ACTIVE and not entry.advertised:
                return True
        return False

    def has_pending_retire(self) -> Bool:
        """Non-allocating: a RETIRE_CONNECTION_ID is queued."""
        return len(self.retire_queue) > 0

    def pending_new_cid_entries(self) -> List[CidEntry]:
        """Copies of the Active local CIDs still owing a NEW_CONNECTION_ID frame."""
        var result = List[CidEntry]()
        for ref entry in self.local_cids:
            if entry.state == CID_ACTIVE and not entry.advertised:
                result.append(entry.copy())
        return result^

    def mark_advertised(mut self, sequence: UInt64):
        """Mark a local CID as advertised after its NEW_CONNECTION_ID frame is sent."""
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                self.local_cids[i].advertised = True
                return

    def clear_advertised(mut self, sequence: UInt64):
        """Clear the advertised flag so a lost NEW_CONNECTION_ID is resent; no-op once retired."""
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                self.local_cids[i].advertised = False
                return


def _verdict(code: UInt64, reason: StaticString) -> Optional[GuardVerdict]:
    """Close verdict for a CID frame violation; `code` is a transport error."""
    return Optional[GuardVerdict](GuardVerdict(error_code=code, tag=String(reason)))


def random_cid() raises -> CidBuf:
    """A fresh 8-byte CID from the kernel CSPRNG; the server demux packs 8-byte DCIDs raw (`dcid_to_u64`)."""
    var cid = CidBuf(data=InlineArray[UInt8, 20](fill=UInt8(0)), len=UInt8(8))
    fill_random(Span(cid.data)[:8])
    return cid^


# ── Private helpers ───────────────────────────────────────────────────────────


def _hmac_sha256_truncate16(
    lib: SharedLibrary, key: Span[Byte, _], msg: Span[Byte, _]
) raises -> ByteVec[16]:
    """HMAC-SHA256(key, msg)[:16] via aws-lc-rs; `key` and `msg` (a CID) at most 32 bytes each.

    Both are staged on the stack: the binding takes mutable pointers.
    """
    if len(key) > 32 or len(msg) > 32:
        raise "HMAC-SHA256: key or message too long"
    var k = InlineArray[UInt8, 32](fill=UInt8(0))
    var m = InlineArray[UInt8, 32](fill=UInt8(0))
    var mac = InlineArray[UInt8, 32](fill=UInt8(0))
    for i in range(len(key)):
        k[i] = key[i]
    for i in range(len(msg)):
        m[i] = msg[i]
    var rlib = lib.inner_ptr()
    var rc = rlib[].hmac_sha256(
        Pointer(to=k[0]), Int32(len(key)), Pointer(to=m[0]), Int32(len(msg)), Pointer(to=mac[0])
    )
    if rc != 0:
        raise "HMAC-SHA256 failed: " + rlib[].last_error()
    var token = ByteVec[16]()
    token.extend(Span(mac)[:16])
    return token^


# ── 8-byte DCID → UInt64 packing (server demux helper) ────────────────────────


def dcid_to_u64(bytes: Span[Byte, _]) -> UInt64:
    """Pack 8 bytes (big-endian) into a UInt64 for use as a Dict[UInt64, Int]
    key. Server demux fast path — replaces String/hex-keyed lookup.

    Precondition: `len(bytes) == 8`. Server SCIDs are pinned at 8 bytes
    (RFC 9000 §7.2 minimum 8 for the client's Initial DCID; servers
    choose their own length and we pin it). `debug_assert` is compiled
    out in release builds where ASSERT mode is `none`, leaving a pure
    8-iter shift loop.
    """
    debug_assert(len(bytes) == 8, "DCID must be 8 bytes")
    var result: UInt64 = 0
    for i in range(8):
        result = (result << 8) | UInt64(bytes[i])
    return result


def demux_key(dcid: Span[Byte, _], key: SipKey) -> UInt64:
    """Server demux key of a DCID; the function is fixed by the DCID length, so a lookup is one probe.

    8 bytes (every server SCID, and 8-byte client Initial DCIDs) pack raw
    via `dcid_to_u64`, so `caps.conn_id` stays the SCID as a u64. Any
    other length is SipHash-1-3 of the whole DCID under the server's
    secret `key`: two long DCIDs sharing a prefix no longer collide, and
    a client cannot aim one at another connection's raw key without
    knowing `key`. Lengths 0-7 hash too, but only as lookups that miss:
    the server drops an Initial whose DCID is under 8 bytes (RFC 9000
    Section 7.2) before it can create a connection, so no slot is ever
    keyed by one.
    """
    if len(dcid) == 8:
        return dcid_to_u64(dcid)
    return siphash13(key, dcid)
