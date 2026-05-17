# src/quic/stream_map.mojo
# QUIC stream collection with connection-level flow control and
# stream concurrency limits — RFC 9000 §4.
#
# StreamMap owns all active streams, enforces MAX_STREAMS limits,
# drives implicit stream creation, and manages the round-robin send schedule.

from std.collections import Dict, Optional
from navette.quic.flow_control import FlowControl, CONN_FC_MAX_WINDOW
from navette.quic.stream import (
    Stream,
    SEND_READY,
    RECV_RECV,
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
    var streams: Dict[Int, Stream]
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

    # ── Stream creation defaults (from local transport params) ────────────────
    var local_stream_fc_window_bidi_local: UInt64
    var local_stream_fc_window_bidi_remote: UInt64
    var local_stream_fc_window_uni: UInt64

    # ── Peer's initial stream FC limits (from peer transport params) ──────────
    var peer_stream_fc_limit_bidi_local: UInt64
    var peer_stream_fc_limit_bidi_remote: UInt64
    var peer_stream_fc_limit_uni: UInt64

    # ── Scheduling ────────────────────────────────────────────────────────────
    var sendable_ids: List[Int]
    var send_index: Int

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
        self.streams = Dict[Int, Stream]()
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

        self.local_stream_fc_window_bidi_local = local_window_bidi_local
        self.local_stream_fc_window_bidi_remote = local_window_bidi_remote
        self.local_stream_fc_window_uni = local_window_uni

        # Peer FC limits: zero until set_peer_limits() is called after handshake
        self.peer_stream_fc_limit_bidi_local = UInt64(0)
        self.peer_stream_fc_limit_bidi_remote = UInt64(0)
        self.peer_stream_fc_limit_uni = UInt64(0)

        self.sendable_ids = List[Int]()
        self.send_index = 0

        self.needs_max_data = False
        self.needs_max_streams_bidi = False
        self.needs_max_streams_uni = False
        self.needs_streams_blocked_bidi = False
        self.needs_streams_blocked_uni = False
        self.streams_blocked_at_bidi = UInt64(0)
        self.streams_blocked_at_uni = UInt64(0)

    def __init__(out self, *, deinit take: Self):
        self.streams = take.streams^
        self.is_server = take.is_server
        self.conn_fc_recv = take.conn_fc_recv^
        self.conn_fc_send = take.conn_fc_send^
        self.local_max_streams_bidi = take.local_max_streams_bidi
        self.local_max_streams_uni = take.local_max_streams_uni
        self.peer_max_streams_bidi = take.peer_max_streams_bidi
        self.peer_max_streams_uni = take.peer_max_streams_uni
        self.local_opened_bidi = take.local_opened_bidi
        self.local_opened_uni = take.local_opened_uni
        self.peer_opened_bidi = take.peer_opened_bidi
        self.peer_opened_uni = take.peer_opened_uni
        self.peer_completed_bidi = take.peer_completed_bidi
        self.peer_completed_uni = take.peer_completed_uni
        self.initial_max_streams_bidi = take.initial_max_streams_bidi
        self.initial_max_streams_uni = take.initial_max_streams_uni
        self.local_stream_fc_window_bidi_local = take.local_stream_fc_window_bidi_local
        self.local_stream_fc_window_bidi_remote = take.local_stream_fc_window_bidi_remote
        self.local_stream_fc_window_uni = take.local_stream_fc_window_uni
        self.peer_stream_fc_limit_bidi_local = take.peer_stream_fc_limit_bidi_local
        self.peer_stream_fc_limit_bidi_remote = take.peer_stream_fc_limit_bidi_remote
        self.peer_stream_fc_limit_uni = take.peer_stream_fc_limit_uni
        self.sendable_ids = take.sendable_ids^
        self.send_index = take.send_index
        self.needs_max_data = take.needs_max_data
        self.needs_max_streams_bidi = take.needs_max_streams_bidi
        self.needs_max_streams_uni = take.needs_max_streams_uni
        self.needs_streams_blocked_bidi = take.needs_streams_blocked_bidi
        self.needs_streams_blocked_uni = take.needs_streams_blocked_uni
        self.streams_blocked_at_bidi = take.streams_blocked_at_bidi
        self.streams_blocked_at_uni = take.streams_blocked_at_uni

    # ── Handshake completion ─────────────────────────────────────────────────

    def set_peer_limits(
        mut self,
        max_streams_bidi: UInt64,
        max_streams_uni: UInt64,
        stream_fc_bidi_local: UInt64,
        stream_fc_bidi_remote: UInt64,
        stream_fc_uni: UInt64,
        conn_fc_send_limit: UInt64,
    ):
        """Populate peer-negotiated limits after the handshake completes."""
        self.peer_max_streams_bidi = max_streams_bidi
        self.peer_max_streams_uni = max_streams_uni
        self.peer_stream_fc_limit_bidi_local = stream_fc_bidi_local
        self.peer_stream_fc_limit_bidi_remote = stream_fc_bidi_remote
        self.peer_stream_fc_limit_uni = stream_fc_uni
        self.conn_fc_send.ensure_limit(conn_fc_send_limit)

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
            self.streams[Int(id)] = stream^
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
            self.streams[Int(id)] = stream^
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
                    self.streams[Int(peer_id)] = stream^
                else:
                    var stream = Stream.new_remote_uni(
                        peer_id,
                        fc_recv_limit=self.local_stream_fc_window_uni,
                        fc_recv_window=self.local_stream_fc_window_uni,
                    )
                    self.streams[Int(peer_id)] = stream^
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
        return Stream(other=self.streams[stream_id])

    def set_stream(mut self, stream_id: Int, var stream: Stream):
        """Update (replace) a stream in the Dict."""
        self.streams[stream_id] = stream^

    # ── Stream cleanup (§4.3) ────────────────────────────────────────────────

    def maybe_cleanup(mut self, stream_id: Int) raises -> Bool:
        """Remove a fully-closed stream. Returns True if removed."""
        if stream_id not in self.streams:
            return False

        var s = Stream(other=self.streams[stream_id])
        if not s.is_fully_closed():
            return False

        # Track peer-initiated completions for MAX_STREAMS update
        var is_peer = not stream_is_local(UInt64(stream_id), self.is_server)
        if is_peer:
            if stream_is_bidi(UInt64(stream_id)):
                self.peer_completed_bidi += UInt64(1)
            else:
                self.peer_completed_uni += UInt64(1)

        _ = self.streams.pop(stream_id)
        self.remove_sendable(stream_id)
        self.check_max_streams_update()
        return True

    # ── MAX_STREAMS update (§4.4) ────────────────────────────────────────────

    def check_max_streams_update(mut self):
        """Linear-growth MAX_STREAMS: raise limit by completed count."""
        var new_bidi_limit = self.peer_completed_bidi + self.initial_max_streams_bidi
        if new_bidi_limit > self.local_max_streams_bidi:
            self.needs_max_streams_bidi = True
            self.local_max_streams_bidi = new_bidi_limit

        var new_uni_limit = self.peer_completed_uni + self.initial_max_streams_uni
        if new_uni_limit > self.local_max_streams_uni:
            self.needs_max_streams_uni = True
            self.local_max_streams_uni = new_uni_limit

    # ── Send scheduling ──────────────────────────────────────────────────────

    def add_sendable(mut self, stream_id: Int):
        """Add stream_id to the sendable list if not already present."""
        for i in range(len(self.sendable_ids)):
            if self.sendable_ids[i] == stream_id:
                return
        self.sendable_ids.append(stream_id)

    def remove_sendable(mut self, stream_id: Int):
        """Remove stream_id from the sendable list."""
        var new_list = List[Int]()
        for i in range(len(self.sendable_ids)):
            if self.sendable_ids[i] != stream_id:
                new_list.append(self.sendable_ids[i])
        self.sendable_ids = new_list^
        # Clamp send_index to valid range
        if len(self.sendable_ids) == 0:
            self.send_index = 0
        elif self.send_index >= len(self.sendable_ids):
            self.send_index = 0

    def get_next_sendable(mut self) -> Optional[Int]:
        """Round-robin: return next stream ID with pending send data."""
        var n = len(self.sendable_ids)
        if n == 0:
            return None
        if self.send_index >= n:
            self.send_index = 0
        var id = self.sendable_ids[self.send_index]
        self.send_index = (self.send_index + 1) % n
        return id
