# src/quic/cid.mojo
#
# Connection ID management for QUIC — RFC 9000 §5.
#
# Handles issuance of local CIDs (with HMAC-SHA256 reset tokens),
# tracking remote CIDs received via NEW_CONNECTION_ID frames,
# retirement via RETIRE_CONNECTION_ID, and stuffing-defense via
# a bounded retire_queue.

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _cid_alloc

from navette.tls.lib import SharedLibrary


# ── CID state constants ────────────────────────────────────────────────────────

comptime CID_ACTIVE: UInt8 = 0
comptime CID_PENDING_RETIRE: UInt8 = 1
comptime CID_RETIRED: UInt8 = 2


# ── CidEntry ──────────────────────────────────────────────────────────────────


struct CidEntry(Copyable, Movable):
    """A single connection ID entry with associated metadata."""

    var cid: List[UInt8]          # connection ID bytes (8 bytes)
    var sequence: UInt64          # sequence number
    var reset_token: List[UInt8]  # 16-byte stateless reset token
    var state: UInt8              # CID_ACTIVE / CID_PENDING_RETIRE / CID_RETIRED
    var advertised: Bool          # True once a NEW_CONNECTION_ID frame has been sent

    def __init__(
        out self,
        cid: List[UInt8],
        sequence: UInt64,
        reset_token: List[UInt8],
        state: UInt8,
        advertised: Bool = False,
    ):
        self.cid = List[UInt8](copy=cid)
        self.sequence = sequence
        self.reset_token = List[UInt8](copy=reset_token)
        self.state = state
        self.advertised = advertised

    def __init__(out self, *, other: Self):
        self.cid = List[UInt8](copy=other.cid)
        self.sequence = other.sequence
        self.reset_token = List[UInt8](copy=other.reset_token)
        self.state = other.state
        self.advertised = other.advertised

    def __init__(out self, *, deinit take: Self):
        self.cid = take.cid^
        self.sequence = take.sequence
        self.reset_token = take.reset_token^
        self.state = take.state
        self.advertised = take.advertised


# ── CidManager ────────────────────────────────────────────────────────────────


struct CidManager(Movable):
    """Manages local and remote connection IDs for a QUIC connection.

    Local CIDs: issued by us, used by the peer as their DCID.
    Remote CIDs: provided by the peer, used by us as our DCID.
    """

    var local_cids: List[CidEntry]         # CIDs we issued
    var local_next_seq: UInt64             # next sequence number for local CIDs
    var local_retire_prior_to: UInt64      # our retire_prior_to for outgoing NEW_CID
    var remote_cids: List[CidEntry]        # peer's CIDs
    var remote_active_cid_seq: UInt64      # seq of CID we're currently using
    var local_active_limit: UInt64         # our active_connection_id_limit
    var peer_active_limit: UInt64          # peer's active_connection_id_limit
    var retire_queue: List[UInt64]         # seq numbers to RETIRE_CONNECTION_ID for
    var retire_queue_cap: Int              # max queue depth (peer_active_limit * 8)
    var highest_retire_prior_to: UInt64    # highest retire_prior_to from peer
    var _lib: SharedLibrary                # ref-counted RustlsLibrary for HMAC-SHA256
    var server_secret: List[UInt8]         # 32-byte key for HMAC-SHA256 reset tokens

    def __init__(
        out self,
        lib: SharedLibrary,
        initial_local_cid: List[UInt8],
        initial_remote_cid: List[UInt8],
        local_active_limit: UInt64,
        peer_active_limit: UInt64,
    ) raises:
        """Initialise a CidManager.

        Args:
            lib: SharedLibrary handle (refcount is incremented).
            initial_local_cid:  The CID we present as SCID in Initial packets.
            initial_remote_cid: The peer's initial CID (their SCID / our DCID).
            local_active_limit: Our active_connection_id_limit transport parameter.
            peer_active_limit:  Peer's active_connection_id_limit transport parameter.
        """
        self._lib = SharedLibrary(other=lib)

        # Generate 32-byte server_secret via getrandom(2).
        var rbuf = _cid_alloc[UInt8](32).as_unsafe_any_origin()
        _ = external_call["getrandom", Int](rbuf, UInt64(32), UInt32(0))
        self.server_secret = List[UInt8](capacity=32)
        for i in range(32):
            self.server_secret.append(rbuf[i])
        rbuf.free()

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
        var empty_token = List[UInt8](capacity=16)
        for _ in range(16):
            empty_token.append(UInt8(0))
        var remote_entry = CidEntry(
            initial_remote_cid, UInt64(0), empty_token, CID_ACTIVE
        )

        self.remote_cids = List[CidEntry]()
        self.remote_cids.append(remote_entry^)
        self.remote_active_cid_seq = UInt64(0)

        self.local_active_limit = local_active_limit
        self.peer_active_limit = peer_active_limit
        self.retire_queue = List[UInt64]()
        self.retire_queue_cap = Int(peer_active_limit * UInt64(8))
        self.highest_retire_prior_to = UInt64(0)

    def __init__(out self, *, deinit take: Self):
        self.local_cids = take.local_cids^
        self.local_next_seq = take.local_next_seq
        self.local_retire_prior_to = take.local_retire_prior_to
        self.remote_cids = take.remote_cids^
        self.remote_active_cid_seq = take.remote_active_cid_seq
        self.local_active_limit = take.local_active_limit
        self.peer_active_limit = take.peer_active_limit
        self.retire_queue = take.retire_queue^
        self.retire_queue_cap = take.retire_queue_cap
        self.highest_retire_prior_to = take.highest_retire_prior_to
        self._lib = take._lib^
        self.server_secret = take.server_secret^

    # ── CID generation ────────────────────────────────────────────────────────

    def generate_cid(mut self) raises -> List[UInt8]:
        """Generate an 8-byte random connection ID via getrandom(2)."""
        var buf = _cid_alloc[UInt8](8).as_unsafe_any_origin()
        _ = external_call["getrandom", Int](buf, UInt64(8), UInt32(0))
        var cid = List[UInt8](capacity=8)
        for i in range(8):
            cid.append(buf[i])
        buf.free()
        return cid^

    def generate_reset_token(self, cid: Span[UInt8, _]) raises -> List[UInt8]:
        """Compute HMAC-SHA256(server_secret, cid)[:16] as the reset token."""
        return _hmac_sha256_truncate16(self._lib, Span(self.server_secret), cid)

    # ── Local CID issuance ────────────────────────────────────────────────────

    def issue_new_cid(mut self) raises -> Optional[CidEntry]:
        """Issue a new local CID if below peer_active_limit.

        Returns the new CidEntry so the caller can build a NEW_CONNECTION_ID frame,
        or None if the peer's limit has been reached.
        """
        if UInt64(self.active_local_count()) >= self.peer_active_limit:
            return None

        var new_cid = self.generate_cid()
        var token = _hmac_sha256_truncate16(self._lib, Span(self.server_secret), Span(new_cid))
        var entry = CidEntry(new_cid, self.local_next_seq, token, CID_ACTIVE)
        self.local_next_seq += UInt64(1)
        var entry_copy = CidEntry(other=entry)
        self.local_cids.append(entry_copy^)
        return entry^

    # ── Remote CID reception ──────────────────────────────────────────────────

    def on_new_connection_id(
        mut self,
        seq: UInt64,
        retire_prior_to: UInt64,
        cid: List[UInt8],
        reset_token: List[UInt8],
    ) raises:
        """Process an incoming NEW_CONNECTION_ID frame from the peer.

        Queues retirements for any remote CIDs with sequence < retire_prior_to,
        then stores the new CID (Active or PendingRetire depending on whether
        it arrives after a higher retire_prior_to has been seen).

        Raises PROTOCOL_VIOLATION if the retirement queue would overflow.
        """
        # Step 1: update highest_retire_prior_to and queue retirements.
        if retire_prior_to > self.highest_retire_prior_to:
            self.highest_retire_prior_to = retire_prior_to
            # Queue retirement for all remote CIDs with seq < retire_prior_to.
            for i in range(len(self.remote_cids)):
                if self.remote_cids[i].sequence < retire_prior_to:
                    if self.remote_cids[i].state == CID_ACTIVE:
                        # Check cap before adding.
                        if len(self.retire_queue) >= self.retire_queue_cap:
                            raise "PROTOCOL_VIOLATION: retirement queue overflow"
                        self.remote_cids[i].state = CID_PENDING_RETIRE
                        self.retire_queue.append(self.remote_cids[i].sequence)

        # Step 2: check cap (accounting for any additions above).
        if len(self.retire_queue) > self.retire_queue_cap:
            raise "PROTOCOL_VIOLATION: retirement queue overflow"

        # Step 3: decide whether this new CID is already obsolete.
        var state: UInt8
        if seq < self.highest_retire_prior_to:
            # Late arrival: should be immediately retired.
            state = CID_PENDING_RETIRE
            if len(self.retire_queue) >= self.retire_queue_cap:
                raise "PROTOCOL_VIOLATION: retirement queue overflow"
            self.retire_queue.append(seq)
        else:
            state = CID_ACTIVE

        # Step 4: store the new CID.
        var entry = CidEntry(
            List[UInt8](copy=cid), seq, List[UInt8](copy=reset_token), state
        )
        self.remote_cids.append(entry^)

    # ── Loss-recovery re-queue ────────────────────────────────────────────────

    def requeue_retire(mut self, sequence: UInt64) raises:
        """Re-queue a lost RETIRE_CONNECTION_ID. Respects retire_queue_cap."""
        if len(self.retire_queue) >= self.retire_queue_cap:
            raise "PROTOCOL_VIOLATION: retire_queue cap exceeded on re-queue"
        self.retire_queue.append(sequence)

    # ── Local CID retirement (peer sends RETIRE_CONNECTION_ID) ────────────────

    def on_retire_connection_id(mut self, sequence: UInt64) raises:
        """Handle a RETIRE_CONNECTION_ID frame from the peer.

        Marks the identified local CID as Retired.  Per RFC 9000 §5.1.1, if
        the number of active local CIDs then drops below peer_active_limit, a
        replacement CID is issued automatically so the connection layer can
        advertise it in a NEW_CONNECTION_ID frame.

        Raises if the sequence number is not found.
        """
        var found = False
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                self.local_cids[i].state = CID_RETIRED
                found = True
                break
        if not found:
            raise "RETIRE_CONNECTION_ID: unknown sequence " + String(Int(sequence))

        # Replace the retired CID if the active count dropped below the limit.
        if self.active_local_count() < Int(self.peer_active_limit):
            _ = self.issue_new_cid()

    # ── Drain retirement queue ────────────────────────────────────────────────

    def pending_retire_frames(mut self) -> List[UInt64]:
        """Drain and return all sequence numbers that need RETIRE_CONNECTION_ID frames.

        The caller is responsible for building the actual frames.
        """
        var result = self.retire_queue^
        self.retire_queue = List[UInt64]()
        return result^

    # ── Predicates ────────────────────────────────────────────────────────────

    def active_local_count(self) -> Int:
        """Count Active local CIDs."""
        var count = 0
        for i in range(len(self.local_cids)):
            if self.local_cids[i].state == CID_ACTIVE:
                count += 1
        return count

    def active_remote_count(self) -> Int:
        """Count Active remote CIDs."""
        var count = 0
        for i in range(len(self.remote_cids)):
            if self.remote_cids[i].state == CID_ACTIVE:
                count += 1
        return count

    def needs_new_cid(self) -> Bool:
        """True if a new local CID should be issued (count below peer_active_limit)."""
        return UInt64(self.active_local_count()) < self.peer_active_limit

    def pending_new_cid_entries(self) -> List[CidEntry]:
        """Return Active local CIDs that have not yet been advertised.

        The connection send path calls this to discover which CIDs need a
        NEW_CONNECTION_ID frame, then calls mark_advertised() after sending.
        """
        var result = List[CidEntry]()
        for i in range(len(self.local_cids)):
            if self.local_cids[i].state == CID_ACTIVE and not self.local_cids[i].advertised:
                result.append(CidEntry(other=self.local_cids[i]))
        return result^

    def mark_advertised(mut self, sequence: UInt64):
        """Mark a local CID as advertised after its NEW_CONNECTION_ID frame is sent."""
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                self.local_cids[i].advertised = True
                return

    def clear_advertised(mut self, sequence: UInt64):
        """Clear the advertised flag for a local CID, allowing retransmission on loss."""
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                # Only clear if still Active (not retired)
                if self.local_cids[i].state == CID_ACTIVE:
                    self.local_cids[i].advertised = False
                return


# ── Private helpers ───────────────────────────────────────────────────────────


def _hmac_sha256_truncate16(
    lib: SharedLibrary, key: Span[UInt8, _], msg: Span[UInt8, _]
) raises -> List[UInt8]:
    """Derive a 16-byte reset token via HMAC-SHA256(key, msg)[:16].

    Uses the Rust FFI bridge (aws-lc-rs) for a proper cryptographic MAC.
    """
    var rlib = lib.inner_ptr()

    var key_ptr = _cid_alloc[UInt8](len(key)).as_unsafe_any_origin()
    for i in range(len(key)):
        key_ptr[i] = key[i]

    var msg_ptr = _cid_alloc[UInt8](max(len(msg), 1)).as_unsafe_any_origin()
    for i in range(len(msg)):
        msg_ptr[i] = msg[i]

    var out_ptr = _cid_alloc[UInt8](32).as_unsafe_any_origin()

    var rc = rlib[].hmac_sha256(
        key_ptr, Int32(len(key)),
        msg_ptr, Int32(len(msg)),
        out_ptr,
    )

    if rc != 0:
        var err = rlib[].last_error()
        key_ptr.free()
        msg_ptr.free()
        out_ptr.free()
        raise "HMAC-SHA256 failed: " + err

    # Truncate to first 16 bytes for the reset token.
    var token = List[UInt8](capacity=16)
    for i in range(16):
        token.append(out_ptr[i])

    key_ptr.free()
    msg_ptr.free()
    out_ptr.free()
    return token^


# ── 8-byte DCID → UInt64 packing (server demux helper) ────────────────────────


def dcid_to_u64(bytes: Span[UInt8, _]) -> UInt64:
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
