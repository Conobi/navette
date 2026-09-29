# src/quic/cid.mojo
#
# Connection ID management for QUIC — RFC 9000 §5.
#
# Handles issuance of local CIDs (with HMAC-SHA256 reset tokens),
# tracking remote CIDs received via NEW_CONNECTION_ID frames,
# retirement via RETIRE_CONNECTION_ID, and stuffing-defense via
# a bounded retire_queue.

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span
from std.memory.alloc import unsafe_alloc as _cid_alloc

from navette.tls.lib import SharedLibrary
from navette.util.siphash import SipKey, siphash13


# ── CID state constants ────────────────────────────────────────────────────────

comptime CID_ACTIVE: UInt8 = 0
comptime CID_PENDING_RETIRE: UInt8 = 1
comptime CID_RETIRED: UInt8 = 2


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
    var server_secret: List[Byte]         # 32-byte key for HMAC-SHA256 reset tokens

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
            local_active_limit: Our active_connection_id_limit transport parameter.
            peer_active_limit:  Peer's active_connection_id_limit transport parameter.
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

        self.local_active_limit = local_active_limit
        self.peer_active_limit = peer_active_limit
        self.retire_queue = List[UInt64]()
        self.retire_queue_cap = Int(peer_active_limit * UInt64(8))
        self.highest_retire_prior_to = UInt64(0)

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
        var entry_copy = CidEntry(copy=entry)
        self.local_cids.append(entry_copy^)
        return entry^

    # ── Remote CID reception ──────────────────────────────────────────────────

    def on_new_connection_id(
        mut self,
        seq: UInt64,
        retire_prior_to: UInt64,
        cid: List[Byte],
        reset_token: List[Byte],
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
            List[Byte](copy=cid), seq, List[Byte](copy=reset_token), state
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
        """True if a new local CID should be issued (count below peer_active_limit)."""
        return UInt64(self.active_local_count()) < self.peer_active_limit

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
        """Clear the advertised flag for a local CID, allowing retransmission on loss."""
        for i in range(len(self.local_cids)):
            if self.local_cids[i].sequence == sequence:
                # Only clear if still Active (not retired)
                if self.local_cids[i].state == CID_ACTIVE:
                    self.local_cids[i].advertised = False
                return


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
