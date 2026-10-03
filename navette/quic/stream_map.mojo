# src/quic/stream_map.mojo
# QUIC stream collection with connection-level flow control and
# stream concurrency limits — RFC 9000 §4.
#
# StreamMap owns all active streams, enforces MAX_STREAMS limits,
# drives implicit stream creation, and manages the round-robin send schedule.

from std.collections import Dict, Optional
from std.collections.deque import Deque
from std.memory import Pointer, UnsafePointer
from std.memory.alloc import unsafe_alloc as _heap_alloc
from navette.quic.flow_control import FlowControl, CONN_FC_MAX_WINDOW
from navette.protect.governor import conn_limit
from navette.quic.stream import (
    Stream,
    SendState,
    RecvState,
    stream_is_bidi,
    stream_is_local,
)


struct StreamMap(Movable):
    """Collection of QUIC streams with connection-level flow control.

    Tracks all active streams, enforces stream concurrency limits, handles
    implicit peer stream creation, drives MAX_STREAMS updates, and manages
    a round-robin send schedule.
    """

    # ── Collection ────────────────────────────────────────────────────────────
    # Streams are heap-allocated and stored by pointer so that in-place
    # mutation (`stream_ref`/`stream_ptr`) never has to copy the ~5KB+
    # Stream (SendBuf/RecvBuf included) out of and back into the Dict.
    var streams: Dict[Int, UnsafePointer[Stream, MutUntrackedOrigin]]
    var is_server: Bool

    # ── Connection-level flow control ─────────────────────────────────────────
    var conn_fc_recv: FlowControl
    var conn_fc_send: FlowControl

    # ── Stream concurrency limits ─────────────────────────────────────────────
    var local_max_streams_bidi: UInt64   # limit we advertise to peer
    var local_max_streams_uni: UInt64
    var peer_max_streams_bidi: UInt64    # peer's limit on us
    var peer_max_streams_uni: UInt64
    var local_opened_bidi: UInt64        # count of locally-initiated bidi
    var local_opened_uni: UInt64
    var peer_opened_bidi: UInt64         # count of peer-initiated (including implicit)
    var peer_opened_uni: UInt64
    var peer_completed_bidi: UInt64      # count of fully-closed peer streams
    var peer_completed_uni: UInt64

    # ── Initial concurrency targets (for MAX_STREAMS formula) ─────────────────
    var initial_max_streams_bidi: UInt64
    var initial_max_streams_uni: UInt64
    var regrant_window: UInt64           # bidi re-grant M = D + window; in [1, initial]; narrowed by `apply_budget`

    # ── Stream creation defaults (from local transport params) ────────────────
    var local_stream_fc_window_bidi_local: UInt64
    var local_stream_fc_window_bidi_remote: UInt64
    var local_stream_fc_window_uni: UInt64

    # ── Peer's initial stream FC limits (from peer transport params) ──────────
    var peer_stream_fc_limit_bidi_local: UInt64
    var peer_stream_fc_limit_bidi_remote: UInt64
    var peer_stream_fc_limit_uni: UInt64

    # ── Scheduling ────────────────────────────────────────────────────────────
    var sendable_queue: Deque[Int]
    var sendable_set: Dict[Int, Bool]

    # ── Per-stream control frame queues ──────────────────────────────────────
    var control_max_stream_data: List[Int]
    var control_reset: List[Int]
    var control_stop_sending: List[Int]

    # ── Pending flags ─────────────────────────────────────────────────────────
    var needs_max_data: Bool
    var needs_max_streams_bidi: Bool
    var needs_max_streams_uni: Bool
    var needs_streams_blocked_bidi: Bool   # set when open_stream() hits peer bidi limit
    var needs_streams_blocked_uni: Bool    # set when open_stream() hits peer uni limit
    var streams_blocked_at_bidi: UInt64    # dedup: last peer_max_streams_bidi we notified
    var streams_blocked_at_uni: UInt64     # dedup: last peer_max_streams_uni we notified

    # ── Constructors ─────────────────────────────────────────────────────────

    def __init__(
        out self,
        is_server: Bool,
        conn_recv_limit: UInt64,
        conn_recv_window: UInt64,
        conn_send_limit: UInt64,
        local_max_streams_bidi: UInt64,
        local_max_streams_uni: UInt64,
        local_window_bidi_local: UInt64,
        local_window_bidi_remote: UInt64,
        local_window_uni: UInt64,
    ):
        self.streams = Dict[Int, UnsafePointer[Stream, MutUntrackedOrigin]](capacity=256)
        self.is_server = is_server

        self.conn_fc_recv = FlowControl(conn_recv_limit, conn_recv_window, CONN_FC_MAX_WINDOW)
        self.conn_fc_send = FlowControl(conn_send_limit, conn_send_limit)

        self.local_max_streams_bidi = local_max_streams_bidi
        self.local_max_streams_uni = local_max_streams_uni
        self.peer_max_streams_bidi = UInt64(0)
        self.peer_max_streams_uni = UInt64(0)

        self.local_opened_bidi = UInt64(0)
        self.local_opened_uni = UInt64(0)
        self.peer_opened_bidi = UInt64(0)
        self.peer_opened_uni = UInt64(0)
        self.peer_completed_bidi = UInt64(0)
        self.peer_completed_uni = UInt64(0)

        self.initial_max_streams_bidi = local_max_streams_bidi
        self.initial_max_streams_uni = local_max_streams_uni
        self.regrant_window = local_max_streams_bidi

        self.local_stream_fc_window_bidi_local = local_window_bidi_local
        self.local_stream_fc_window_bidi_remote = local_window_bidi_remote
        self.local_stream_fc_window_uni = local_window_uni

        # Peer FC limits: zero until set_peer_limits() is called after handshake
        self.peer_stream_fc_limit_bidi_local = UInt64(0)
        self.peer_stream_fc_limit_bidi_remote = UInt64(0)
        self.peer_stream_fc_limit_uni = UInt64(0)

        self.sendable_queue = Deque[Int]()
        self.sendable_set = Dict[Int, Bool](capacity=256)
        self.control_max_stream_data = List[Int]()
        self.control_reset = List[Int]()
        self.control_stop_sending = List[Int]()

        self.needs_max_data = False
        self.needs_max_streams_bidi = False
        self.needs_max_streams_uni = False
        self.needs_streams_blocked_bidi = False
        self.needs_streams_blocked_uni = False
        self.streams_blocked_at_bidi = UInt64(0)
        self.streams_blocked_at_uni = UInt64(0)

    def __deinit__(deinit self):
        """Free every stream still owned by this map.

        Streams removed via `maybe_cleanup` already free their pointer on
        the way out; this only catches whatever is still open when the
        connection (and therefore this StreamMap) is torn down.
        """
        for entry in self.streams.items():
            try:
                entry.value.unsafe_deinit_pointee()
                entry.value.unsafe_free()
            except:
                pass

    # ── Handshake completion ─────────────────────────────────────────────────

    def set_peer_limits(
        mut self,
        max_streams_bidi: UInt64,
        max_streams_uni: UInt64,
        stream_fc_bidi_local: UInt64,
        stream_fc_bidi_remote: UInt64,
        stream_fc_uni: UInt64,
        conn_fc_send_limit: UInt64,
    ) raises:
        """Populate peer-negotiated limits after the handshake completes.

        Any peer-initiated streams created BEFORE the handshake completed
        (i.e., during 0-RTT processing on the server side) were initialised
        with `peer_stream_fc_limit_*` defaults of 0. Once the peer's real
        transport parameters arrive, we retroactively raise each existing
        stream's `fc_send` limit to the matching peer limit so that response
        data can flow on those streams. `FlowControl.ensure_limit` is
        monotonic — never lowers an existing limit — so streams that
        already have a higher limit (e.g. locally-initiated streams created
        post-handshake) are unaffected.
        """
        self.peer_max_streams_bidi = max_streams_bidi
        self.peer_max_streams_uni = max_streams_uni
        self.peer_stream_fc_limit_bidi_local = stream_fc_bidi_local
        self.peer_stream_fc_limit_bidi_remote = stream_fc_bidi_remote
        self.peer_stream_fc_limit_uni = stream_fc_uni
        self.conn_fc_send.ensure_limit(conn_fc_send_limit)

        # Retroactively bump fc_send for any peer-initiated streams that
        # were created with the default 0 limits (only happens on the
        # server when peer opened streams via 0-RTT before its TPs were
        # parsed). Iterate by snapshotted key list — mutation below goes
        # through the existing pointer (no insert/remove on `self.streams`),
        # but snapshotting keeps this loop robust to future changes here.
        var stream_ids = List[Int](capacity=len(self.streams))
        for key in self.streams.keys():
            stream_ids.append(key)
        for ref sid in stream_ids:
            if sid not in self.streams:
                continue
            var p = self.streams[sid]
            if not p[].fc_send:
                continue
            # Pick the matching peer limit for this stream's direction.
            # Bidi streams use the limit appropriate to "who initiated":
            # peer-initiated bidi -> peer's bidi_local (peer is sender of
            # initial OPEN, so they constrain WE on this peer-bidi stream
            # via their bidi_local); local-initiated bidi -> peer's
            # bidi_remote.
            var target_limit: UInt64
            var sid64 = UInt64(sid)
            if stream_is_bidi(sid64):
                if stream_is_local(sid64, self.is_server):
                    target_limit = stream_fc_bidi_remote
                else:
                    target_limit = stream_fc_bidi_local
            else:
                if stream_is_local(sid64, self.is_server):
                    target_limit = stream_fc_uni
                else:
                    # Peer-initiated uni stream — local endpoint never
                    # sends, so fc_send is unused; skip.
                    continue
            var fc = p[].fc_send.value().copy()
            fc.ensure_limit(target_limit)
            p[].fc_send = fc^

    # ── Internal: pointer-backed storage ─────────────────────────────────────

    def _insert_stream(mut self, stream_id: Int, var stream: Stream):
        """Heap-allocate a slot for a brand-new stream and insert it.

        Caller guarantees `stream_id` is not already present — an existing
        entry would leak its pointer. Use `set_stream` to replace one.
        """
        var p = _heap_alloc[Stream](1)
        p.unsafe_write(stream^)
        self.streams[stream_id] = p

    # ── Local stream creation (§4.2) ─────────────────────────────────────────

    def open_stream(mut self, bidi: Bool) raises -> UInt64:
        """Open a locally-initiated stream. Returns the new stream ID.

        Raises if the peer's concurrency limit would be exceeded.
        """
        if bidi:
            if self.local_opened_bidi >= self.peer_max_streams_bidi:
                self.needs_streams_blocked_bidi = True
                raise "stream limit reached: peer_max_streams_bidi=" + String(
                    Int(self.peer_max_streams_bidi)
                )
            # RFC 9000 §2.1: client bidi IDs = 0,4,8,... ; server bidi = 1,5,9,...
            var server_bit = UInt64(1) if self.is_server else UInt64(0)
            var id = self.local_opened_bidi * UInt64(4) + server_bit
            var stream = Stream.new_local_bidi(
                id,
                fc_send_limit=self.peer_stream_fc_limit_bidi_remote,
                fc_recv_limit=self.local_stream_fc_window_bidi_local,
                fc_recv_window=self.local_stream_fc_window_bidi_local,
            )
            self._insert_stream(Int(id), stream^)
            self.local_opened_bidi += UInt64(1)
            return id
        else:
            if self.local_opened_uni >= self.peer_max_streams_uni:
                self.needs_streams_blocked_uni = True
                raise "stream limit reached: peer_max_streams_uni=" + String(
                    Int(self.peer_max_streams_uni)
                )
            # RFC 9000 §2.1: client uni IDs = 2,6,10,... ; server uni = 3,7,11,...
            var server_bit = UInt64(1) if self.is_server else UInt64(0)
            var id = self.local_opened_uni * UInt64(4) + UInt64(2) + server_bit
            var stream = Stream.new_local_uni(
                id,
                fc_send_limit=self.peer_stream_fc_limit_uni,
            )
            self._insert_stream(Int(id), stream^)
            self.local_opened_uni += UInt64(1)
            return id

    # ── Peer stream creation (§4.2) ──────────────────────────────────────────

    def get_or_create_peer_stream(
        mut self, stream_id: UInt64
    ) raises -> List[UInt64]:
        """Process a frame referencing a peer-initiated stream.

        Returns list of newly-created stream IDs (including implicit ones).
        Raises on protocol violations or limit errors.
        """
        # If stream exists, nothing to do
        if Int(stream_id) in self.streams:
            return List[UInt64]()

        # Locally-initiated stream that doesn't exist: protocol violation
        if stream_is_local(stream_id, self.is_server):
            raise "PROTOCOL_VIOLATION: received frame for locally-initiated stream id=" + String(
                Int(stream_id)
            )

        var bidi = stream_is_bidi(stream_id)
        var ordinal = stream_id // UInt64(4)

        # Validate against our limit
        if bidi:
            if ordinal + UInt64(1) > self.local_max_streams_bidi:
                raise "STREAM_LIMIT_ERROR: peer stream ordinal=" + String(
                    Int(ordinal)
                ) + " exceeds local_max_streams_bidi=" + String(
                    Int(self.local_max_streams_bidi)
                )
        else:
            if ordinal + UInt64(1) > self.local_max_streams_uni:
                raise "STREAM_LIMIT_ERROR: peer stream ordinal=" + String(
                    Int(ordinal)
                ) + " exceeds local_max_streams_uni=" + String(
                    Int(self.local_max_streams_uni)
                )

        # Determine lowest ordinal not yet opened
        var start_ordinal: UInt64
        if bidi:
            start_ordinal = self.peer_opened_bidi
        else:
            start_ordinal = self.peer_opened_uni

        var new_ids = List[UInt64]()

        # Implicitly create all streams from start_ordinal up to and including ordinal
        var i = start_ordinal
        while i <= ordinal:
            # Compute the peer stream ID for this ordinal
            # Peer-initiated: bit0 = 0 (client) or 1 (server) — opposite of is_server
            var peer_bit = UInt64(0) if self.is_server else UInt64(1)
            var uni_bit = UInt64(0) if bidi else UInt64(2)
            var peer_id = i * UInt64(4) + uni_bit + peer_bit

            if Int(peer_id) not in self.streams:
                if bidi:
                    var stream = Stream.new_remote_bidi(
                        peer_id,
                        fc_send_limit=self.peer_stream_fc_limit_bidi_local,
                        fc_recv_limit=self.local_stream_fc_window_bidi_remote,
                        fc_recv_window=self.local_stream_fc_window_bidi_remote,
                    )
                    self._insert_stream(Int(peer_id), stream^)
                else:
                    var stream = Stream.new_remote_uni(
                        peer_id,
                        fc_recv_limit=self.local_stream_fc_window_uni,
                        fc_recv_window=self.local_stream_fc_window_uni,
                    )
                    self._insert_stream(Int(peer_id), stream^)
                new_ids.append(peer_id)

            i += UInt64(1)

        # Update peer_opened counter
        if bidi:
            if ordinal + UInt64(1) > self.peer_opened_bidi:
                self.peer_opened_bidi = ordinal + UInt64(1)
        else:
            if ordinal + UInt64(1) > self.peer_opened_uni:
                self.peer_opened_uni = ordinal + UInt64(1)

        return new_ids^

    # ── Stream access ────────────────────────────────────────────────────────

    def get_stream(self, stream_id: Int) raises -> Stream:
        """Get a copy of the stream. Raises if not found."""
        if stream_id not in self.streams:
            raise "stream not found: id=" + String(stream_id)
        return Stream(copy=self.streams[stream_id][])

    def set_stream(mut self, stream_id: Int, var stream: Stream) raises:
        """Replace a stream in place through its existing pointer.

        `stream_id` must already be present — typically the same id just
        returned by `get_stream`/`stream_ref`. No new allocation: the old
        pointee is dropped and the new value written into the same slot.
        """
        var p = self.streams[stream_id]
        p.unsafe_deinit_pointee()
        p.unsafe_write(stream^)

    def was_opened(self, stream_id: UInt64) -> Bool:
        """True when its initiator has already opened `stream_id`, whether or
        not it is still in the map; an absent id for which this holds was
        closed and freed."""
        var ordinal = stream_id // UInt64(4)
        var bidi = stream_is_bidi(stream_id)
        if stream_is_local(stream_id, self.is_server):
            if bidi:
                return ordinal < self.local_opened_bidi
            return ordinal < self.local_opened_uni
        if bidi:
            return ordinal < self.peer_opened_bidi
        return ordinal < self.peer_opened_uni

    def has_stream(self, stream_id: Int) -> Bool:
        """Cheaper `stream_id in self.streams` for callers about to take a ref."""
        return stream_id in self.streams

    def stream_ptr(self, stream_id: Int) raises -> UnsafePointer[Stream, MutUntrackedOrigin]:
        """Direct pointer to the stream for in-place mutation — no copy.

        The pointer stays valid until `maybe_cleanup` removes this
        `stream_id` or this map is destroyed; the caller must not hold it
        past either.
        """
        if stream_id not in self.streams:
            raise "stream not found: id=" + String(stream_id)
        return self.streams[stream_id]

    def try_stream_ptr(
        self, stream_id: Int,
    ) -> Optional[UnsafePointer[Stream, MutUntrackedOrigin]]:
        """Look up a stream pointer without raising. Returns None if absent (1 probe)."""
        return self.streams.find(stream_id)

    def stream_ref(ref self, stream_id: Int) raises -> ref [MutAnyOrigin] Stream:
        """Borrow the stream in place; raises like `get_stream` when absent.

        While the returned ref is live the caller must not remove this
        stream (`maybe_cleanup`) or destroy this map (`__deinit__`) — the
        pointee would be freed out from under the ref. Unlike the old
        `Dict[Int, Stream]` storage, inserting into `streams` (rehashing
        the Dict) is safe: the pointee's heap address never moves.
        """
        if stream_id not in self.streams:
            raise "stream not found: id=" + String(stream_id)
        return self.streams[stream_id][]

    # ── Stream cleanup (§4.3) ────────────────────────────────────────────────

    def maybe_cleanup(mut self, stream_id: Int) raises -> Bool:
        """Remove a fully-closed stream. Returns True if removed."""
        var result = self.streams.find(stream_id)
        if not result:
            return False

        if not result.value()[].is_fully_closed():
            return False

        # Track peer-initiated completions for MAX_STREAMS update
        var is_peer = not stream_is_local(UInt64(stream_id), self.is_server)
        if is_peer:
            if stream_is_bidi(UInt64(stream_id)):
                self.peer_completed_bidi += UInt64(1)
            else:
                self.peer_completed_uni += UInt64(1)

        var p = self.streams.pop(stream_id)
        p.unsafe_deinit_pointee()
        p.unsafe_free()
        self.remove_sendable(stream_id)
        self.check_max_streams_update()
        return True

    # ── MAX_STREAMS update (§4.4) ────────────────────────────────────────────

    def check_max_streams_update(mut self):
        """Linear-growth MAX_STREAMS: raise limit by completed count; bidi credit tops up to `regrant_window`."""
        var new_bidi_limit = self.peer_completed_bidi + self.regrant_window
        if new_bidi_limit > self.local_max_streams_bidi:
            self.needs_max_streams_bidi = True
            self.local_max_streams_bidi = new_bidi_limit

        var new_uni_limit = self.peer_completed_uni + self.initial_max_streams_uni
        if new_uni_limit > self.local_max_streams_uni:
            self.needs_max_streams_uni = True
            self.local_max_streams_uni = new_uni_limit

    def apply_budget(mut self, budget: UInt64, work: UInt64, n: UInt64) -> Bool:
        """Re-derive the bidi window from the governor's server-wide `budget` (`n` connections, `work` open streams).

        `conn_limit` keeps it in `[min(32, initial), initial]` and cuts it at most once until the last cut has taken
        effect; credit already granted is never taken back. True when the limit grew: a MAX_STREAMS must be sent now,
        since a client blocked on stream credit sends nothing that would trigger one.
        """
        var before = self.local_max_streams_bidi
        var open_c = self.peer_opened_bidi - min(self.peer_opened_bidi, self.peer_completed_bidi)
        var cap = self.initial_max_streams_bidi
        self.regrant_window = max(UInt64(1), conn_limit(self.regrant_window, open_c, budget, work, n, cap))
        self.check_max_streams_update()
        return self.local_max_streams_bidi > before

    # ── Send scheduling ──────────────────────────────────────────────────────

    def add_sendable(mut self, stream_id: Int):
        """Enqueue a stream for STREAM frame emission if not already present."""
        if stream_id not in self.sendable_set:
            self.sendable_set[stream_id] = True
            self.sendable_queue.append(stream_id)

    def remove_sendable(mut self, stream_id: Int) raises:
        """Mark a stream as no longer sendable (lazy Deque eviction)."""
        if stream_id in self.sendable_set:
            _ = self.sendable_set.pop(stream_id)

    # ── Control frame queuing ────────────────────────────────────────────────

    def mark_max_stream_data(mut self, stream_id: Int):
        """Queue a MAX_STREAM_DATA frame for the next send pass."""
        self.control_max_stream_data.append(stream_id)

    def mark_reset(mut self, stream_id: Int):
        """Queue a RESET_STREAM frame for the next send pass."""
        self.control_reset.append(stream_id)

    def mark_stop_sending(mut self, stream_id: Int):
        """Queue a STOP_SENDING frame for the next send pass."""
        self.control_stop_sending.append(stream_id)
