# src/quic/cid.mojo
#
# Connection ID management for QUIC — RFC 9000 §5.
#
# Handles issuance of local CIDs (with HMAC-SHA256 reset tokens),
# tracking remote CIDs received via NEW_CONNECTION_ID frames and
# retirement via RETIRE_CONNECTION_ID, with every per-peer list bounded.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _cid_alloc

from navette.tls.lib import SharedLibrary
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


# Close reasons for CID frame violations.
comptime CID_REASON_LIMIT = "NEW_CONNECTION_ID exceeds active_connection_id_limit"
comptime CID_REASON_RETIRE_BACKLOG = "too many unacknowledged RETIRE_CONNECTION_ID"
comptime CID_REASON_CONFLICT = "NEW_CONNECTION_ID conflicts with a known sequence or CID"
comptime CID_REASON_RETIRE_UNISSUED = "RETIRE_CONNECTION_ID for a sequence never issued"
comptime CID_REASON_RETIRE_OWN_DCID = "RETIRE_CONNECTION_ID retires the packet's own DCID"


# ── CidEntry ──────────────────────────────────────────────────────────────────


struct CidEntry(Copyable, Movable):
    """A single connection ID entry with associated metadata."""

    var cid: List[Byte]          # connection ID bytes (8 bytes)
    var sequence: UInt64          # sequence number
    var reset_token: List[Byte]  # 16-byte stateless reset token
    var state: UInt8              # CID_ACTIVE / CID_PENDING_RETIRE / CID_RETIRED
    var advertised: Bool          # True once a NEW_CONNECTION_ID frame has been sent

    def __init__(
        out self,
        cid: List[Byte],
        sequence: UInt64,
        reset_token: List[Byte],
        state: UInt8,
        advertised: Bool = False,
    ):
        self.cid = List[Byte](copy=cid)
        self.sequence = sequence
        self.reset_token = List[Byte](copy=reset_token)
        self.state = state
        self.advertised = advertised

    def __init__(out self, *, copy: Self):
        self.cid = List[Byte](copy=copy.cid)
        self.sequence = copy.sequence
        self.reset_token = List[Byte](copy=copy.reset_token)
        self.state = copy.state
        self.advertised = copy.advertised


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
    var server_secret: List[Byte]         # 32-byte key for HMAC-SHA256 reset tokens
    var cid_epoch: UInt64                  # bumped whenever `local_cids` gains or loses an entry

    def __init__(
        out self,
        lib: SharedLibrary,
        initial_local_cid: List[Byte],
        initial_remote_cid: List[Byte],
        local_active_limit: UInt64,
        peer_active_limit: UInt64,
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
        """
        self._lib = SharedLibrary(copy=lib)

        # Generate 32-byte server_secret via getrandom(2).
        var rbuf = _cid_alloc[UInt8](32)
        _ = external_call["getrandom", Int](rbuf, UInt64(32), UInt32(0))
        self.server_secret = List[Byte](capacity=32)
        self.server_secret.extend(Span(unsafe_ptr=rbuf, length=32))
        rbuf.unsafe_free()

        # Build initial local CID entry (seq=0, Active) with a reset token.
        # Mark as advertised=True: the initial CID is conveyed in the handshake,
        # not via a NEW_CONNECTION_ID frame, so no advertisement is pending.
        var local_token = _hmac_sha256_truncate16(
            self._lib, Span(self.server_secret), Span(initial_local_cid)
        )
        var local_entry = CidEntry(
            initial_local_cid, UInt64(0), local_token, CID_ACTIVE, True
        )

        self.local_cids = List[CidEntry]()
        self.local_cids.append(local_entry^)
        self.local_next_seq = UInt64(1)
        self.local_retire_prior_to = UInt64(0)

        # Build initial remote CID entry (seq=0, Active, empty token).
        var empty_token = List[Byte](capacity=16)
        empty_token.resize(16, Byte(0))
        var remote_entry = CidEntry(
            initial_remote_cid, UInt64(0), empty_token, CID_ACTIVE
        )

        self.remote_cids = List[CidEntry]()
        self.remote_cids.append(remote_entry^)
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

    # ── CID generation ────────────────────────────────────────────────────────

    def generate_cid(mut self) raises -> List[Byte]:
        """Generate an 8-byte random connection ID via getrandom(2)."""
        var buf = _cid_alloc[UInt8](8)
        _ = external_call["getrandom", Int](buf, UInt64(8), UInt32(0))
        var cid = List[Byte](capacity=8)
        cid.extend(Span(unsafe_ptr=buf, length=8))
        buf.unsafe_free()
        return cid^

    def generate_reset_token(self, cid: Span[Byte, _]) raises -> List[Byte]:
        """Compute HMAC-SHA256(server_secret, cid)[:16] as the reset token."""
        return _hmac_sha256_truncate16(self._lib, Span(self.server_secret), cid)

    # ── Local CID issuance ────────────────────────────────────────────────────

    def issue_new_cid(mut self) raises -> Optional[CidEntry]:
        """Issue a new local CID if below `issue_limit()`.

        Returns the new CidEntry so the caller can build a NEW_CONNECTION_ID frame,
        or None once `issue_limit()` active CIDs exist.
        """
        if self.active_local_count() >= self.issue_limit():
            return None

        var new_cid = self.generate_cid()
        var token = _hmac_sha256_truncate16(self._lib, Span(self.server_secret), Span(new_cid))
        var entry = CidEntry(new_cid, self.local_next_seq, token, CID_ACTIVE)
        self.local_next_seq += UInt64(1)
        var entry_copy = CidEntry(copy=entry)
        self.local_cids.append(entry_copy^)
        self.cid_epoch += UInt64(1)
        return entry^

    # ── Remote CID reception ──────────────────────────────────────────────────

    def on_new_connection_id(
        mut self,
        seq: UInt64,
        retire_prior_to: UInt64,
        cid: List[Byte],
        reset_token: List[Byte],
    ) -> Optional[GuardVerdict]:
        """Process a NEW_CONNECTION_ID frame (RFC 9000 Sections 5.1.1, 19.15).

        The caller has already checked `retire_prior_to <= seq` and the CID
        length. Outcomes:
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
            var same_cid = _bytes_eq(Span(e.cid), Span(cid))
            if same_seq or same_cid:
                if same_seq and same_cid and _bytes_eq(
                    Span(e.reset_token), Span(reset_token)
                ):
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

        self.remote_cids.append(
            CidEntry(List[Byte](copy=cid), seq, List[Byte](copy=reset_token), CID_ACTIVE)
        )
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
                if len(packet_dcid) > 0 and _bytes_eq(
                    Span(self.local_cids[i].cid), packet_dcid
                ):
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
        """Return Active local CIDs that have not yet been advertised.

        The connection send path calls this to discover which CIDs need a
        NEW_CONNECTION_ID frame, then calls mark_advertised() after sending.
        """
        var result = List[CidEntry]()
        for ref entry in self.local_cids:
            if entry.state == CID_ACTIVE and not entry.advertised:
                result.append(CidEntry(copy=entry))
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


def _bytes_eq(a: Span[Byte, _], b: Span[Byte, _]) -> Bool:
    """Byte equality, lengths included; not constant-time, so not for secrets."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


# ── Private helpers ───────────────────────────────────────────────────────────


def _hmac_sha256_truncate16(
    lib: SharedLibrary, key: Span[Byte, _], msg: Span[Byte, _]
) raises -> List[Byte]:
    """Derive a 16-byte reset token via HMAC-SHA256(key, msg)[:16].

    Uses the Rust FFI bridge (aws-lc-rs) for a proper cryptographic MAC.
    """
    var rlib = lib.inner_ptr()

    var key_ptr = _cid_alloc[UInt8](len(key))
    for i in range(len(key)):
        key_ptr[unsafe_offset=i] = key[i]

    var msg_ptr = _cid_alloc[UInt8](max(len(msg), 1))
    for i in range(len(msg)):
        msg_ptr[unsafe_offset=i] = msg[i]

    var out_ptr = _cid_alloc[UInt8](32)

    var rc = rlib[].hmac_sha256(
        key_ptr, Int32(len(key)),
        msg_ptr, Int32(len(msg)),
        out_ptr,
    )

    if rc != 0:
        var err = rlib[].last_error()
        key_ptr.unsafe_free()
        msg_ptr.unsafe_free()
        out_ptr.unsafe_free()
        raise "HMAC-SHA256 failed: " + err

    # Truncate to first 16 bytes for the reset token.
    var token = List[Byte](capacity=16)
    token.extend(Span(unsafe_ptr=out_ptr, length=16))

    key_ptr.unsafe_free()
    msg_ptr.unsafe_free()
    out_ptr.unsafe_free()
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
