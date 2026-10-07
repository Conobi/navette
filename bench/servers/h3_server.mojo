# bench/servers/h3_server.mojo
#
# HTTP/3 QUIC benchmark server for HttpArena on port 8443 (UDP).
#
# Uses bouclette's WatchLoop with multishot recvmsg via DatagramStream
# backed by a BufferPool, fire-and-forget sendmsg via WatchLoop.send_msg,
# and one TimerFuture armed to the earliest connection deadline (1 ms
# floor, 1000 ms ceiling). The event loop is:
#   step(TIMER_CEILING_MS) -> flush() -> repeat
# where flush() drains the DatagramStream, routes packets through QUIC/H3,
# services expired deadlines, re-arms the timer and submits egress.
#
# This is the benchmark variant of the library's H3UdpServer[BenchHandler],
# carrying error-count diagnostics. Every operation is driven by
# WatchLoop — no raw io_uring calls.

from std.memory import Pointer
from std.collections import Span, Optional, Dict
from std.memory.alloc import unsafe_alloc as _heap_alloc

from navette.tls.lib import TlsBackend, SharedLibrary
from navette.tls.config import QuicServerConfig
from navette.quic.connection import QuicConnection
from navette.quic.trans_param import TransportParams, default_transport_params
from navette.quic.packet import is_long_header_initial, extract_dcid
from navette.quic.cid_buf import CidBuf
from navette.quic.cid import dcid_to_u64
from navette.runtime.socket_helpers import udp_listener
from navette.h3.h3_handler_server import H3HandlerServer
from bench.lib.handler import (
    BenchHandler,
    BenchState,
    StaticEntry,
    _load_static_files,
    _load_dataset,
)
from interop.file_io import read_file, getenv_opt
from interop.udp import monotonic_us
from navette.util.null_ptr import null_ptr

from bouclette import (
    WatchLoop,
    TimerFuture,
    BufferPool,
    DatagramStream,
    Datagram,
    DeliveryHeader,
    Message,
    Socket,
    SocketAddrV4,
    SocketAddrV6,
)


# ── constants ──────────────────────────────────────────────────────────

comptime _SQ_ENTRIES: Int = 4096
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600

# Peer address capacity used by the delivery header decoder. Must
# match bouclette's _NAME_CAPACITY (sizeof(sockaddr_in6) = 28 on x86_64).
comptime _RECV_NAME_CAPACITY: Int = 28

# Control capacity — zero for bench (no ECN/GRO needed).
comptime _RECV_CONTROL_CAPACITY: Int = 0

# Loop-timer bounds (ms) and the idle timeout substituted when the
# transport params carry 0. Mirrors the library server.
comptime TIMER_FLOOR_MS: UInt64 = 1
comptime TIMER_CEILING_MS: UInt64 = 1000
comptime SERVER_DEFAULT_IDLE_TIMEOUT_MS: UInt64 = 30_000


def _timer_arm_ms(deadline: Optional[UInt64], now: UInt64) -> UInt64:
    """Milliseconds to arm the loop timer for a deadline at absolute µs.

    `ceil((deadline - now) / 1000)` clamped to `[TIMER_FLOOR_MS,
    TIMER_CEILING_MS]`; the ceiling when there is no deadline, the floor
    when it has already passed.
    """
    if deadline is None:
        return TIMER_CEILING_MS
    var d = deadline.value()
    if d <= now:
        return TIMER_FLOOR_MS
    var ms = (d - now + UInt64(999)) // UInt64(1000)
    if ms < TIMER_FLOOR_MS:
        return TIMER_FLOOR_MS
    if ms > TIMER_CEILING_MS:
        return TIMER_CEILING_MS
    return ms


def _sockaddr_matches(
    addr: List[Byte],
    name_ptr: Pointer[UInt8, MutUntrackedOrigin],
    name_len: Int,
) -> Bool:
    """Length-and-bytes comparison of a stored sockaddr blob with a delivery's."""
    if len(addr) != name_len:
        return False
    for j in range(name_len):
        if addr[j] != name_ptr[unsafe_offset=j]:
            return False
    return True


# ── helpers (kept from original) ───────────────────────────────────────


comptime _HEX_DIGITS = "0123456789abcdef"


# unused at hot-path post-2026-04-28-quic-bench-dcid-u64-demux; retained
# for ad-hoc debug rendering and for `tests/test_quic_connection.mojo`'s
# `test_dcid_demux_disambiguates_two_conns`. Do not delete without
# re-grepping across the repo.
def _bytes_to_hex(bytes: Span[Byte, _]) -> String:
    """Hex-encode bytes for use as a Dict[String, Int] key.

    Pinned to 8-byte DCIDs (server SCID length is pinned at 8 bytes;
    client Initial DCIDs are RFC 9000 minimum 8). Span parameter
    so call sites pass `quic.initial_dcid.as_span()` or `pd.dcid.as_span()`
    without consuming the source buffer.
    """
    var key = String()
    var hex_bytes = _HEX_DIGITS.as_bytes()
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        key += chr(Int(hex_bytes[b >> 4]))
        key += chr(Int(hex_bytes[b & 0x0F]))
    return key^


def _set_msg_peer_raw(mut msg: Message, addr: List[Byte]):
    """Set a Message's peer from raw sockaddr bytes (Linux layout).

    Parses sa_family (LE on x86_64) to choose between AF_INET and
    AF_INET6, builds the typed address, and calls `msg.set_peer`.
    Does nothing when the addr is too short or has an unknown family.
    """
    if len(addr) < 4:
        return

    # sa_family is little-endian on Linux x86_64.
    var family = Int(addr[0]) | (Int(addr[1]) << 8)
    # Port is network-order (big-endian).
    var port = (UInt16(addr[2]) << 8) | UInt16(addr[3])

    if family == 2:  # AF_INET
        if len(addr) < 8:
            return
        msg.set_peer(SocketAddrV4(
            addr[4], addr[5], addr[6], addr[7], port=port,
        ))
    elif family == 10:  # AF_INET6
        if len(addr) < 24:
            return
        # 8 segments of 2 bytes each, big-endian, at offset [8..24).
        # SocketAddrV6 expects host-order segments.
        var s0 = (UInt16(addr[8]) << 8) | UInt16(addr[9])
        var s1 = (UInt16(addr[10]) << 8) | UInt16(addr[11])
        var s2 = (UInt16(addr[12]) << 8) | UInt16(addr[13])
        var s3 = (UInt16(addr[14]) << 8) | UInt16(addr[15])
        var s4 = (UInt16(addr[16]) << 8) | UInt16(addr[17])
        var s5 = (UInt16(addr[18]) << 8) | UInt16(addr[19])
        var s6 = (UInt16(addr[20]) << 8) | UInt16(addr[21])
        var s7 = (UInt16(addr[22]) << 8) | UInt16(addr[23])
        var scope_id = UInt32(0)
        if len(addr) >= 28:
            scope_id = (
                UInt32(addr[24])
                | (UInt32(addr[25]) << 8)
                | (UInt32(addr[26]) << 16)
                | (UInt32(addr[27]) << 24)
            )
        msg.set_peer(SocketAddrV6(
            s0, s1, s2, s3, s4, s5, s6, s7,
            port=port, scope_id=scope_id,
        ))


# ── PendingDatagram ──────────────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    """A single inbound UDP segment parked between stream drain and flush.

    `payload_ptr` and `name_ptr` are raw pointers into the
    `DatagramStream`'s leased buffer. The lease stays alive in
    `_live_datagrams` until `_flush_impl` completes. `dgram_idx`
    indexes into `_live_datagrams` / `_dgram_refcounts` so the
    refcount can be decremented when this segment is consumed.
    """
    var payload_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_len: Int
    var name_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var name_len: Int
    var dcid: CidBuf
    var dgram_idx: Int

    def __init__(
        out self,
        payload_ptr: Pointer[UInt8, MutUntrackedOrigin],
        payload_len: Int,
        name_ptr: Pointer[UInt8, MutUntrackedOrigin],
        name_len: Int,
        var dcid: CidBuf,
        dgram_idx: Int,
    ):
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.name_ptr = name_ptr
        self.name_len = name_len
        self.dcid = dcid^
        self.dgram_idx = dgram_idx

    def __init__(out self, *, copy: Self):
        self.payload_ptr = copy.payload_ptr
        self.payload_len = copy.payload_len
        self.name_ptr = copy.name_ptr
        self.name_len = copy.name_len
        self.dcid = CidBuf(copy=copy.dcid)
        self.dgram_idx = copy.dgram_idx

    def __init__(out self, *, deinit move: Self):
        self.payload_ptr = move.payload_ptr
        self.payload_len = move.payload_len
        self.name_ptr = move.name_ptr
        self.name_len = move.name_len
        self.dcid = move.dcid^
        self.dgram_idx = move.dgram_idx


# ── EgressPacket ─────────────────────────────────────────────────────


struct EgressPacket(Movable):
    """A queued egress datagram — payload + destination address.

    Buffered during _flush_impl's per-packet drain and timeout drain.
    Submitted via WatchLoop.send_msg in flush()'s _submit_egress phase.
    """

    var data: List[Byte]
    var addr: List[Byte]

    def __init__(out self, var data: List[Byte], var addr: List[Byte]):
        self.data = data^
        self.addr = addr^

    def __init__(out self, *, deinit move: Self):
        self.data = move.data^
        self.addr = move.addr^


# ── H3UdpHandler ─────────────────────────────────────────────────────


struct H3UdpHandler(Movable):
    """UDP-based H3 benchmark server driven by WatchLoop.

    Ingress is via a DatagramStream (multishot recvmsg backed by a
    BufferPool); egress is via WatchLoop.send_msg (fire-and-forget,
    loop owns the message slab). One TimerFuture, armed to the earliest
    connection deadline, wakes the loop for retransmits and expiry; the
    decision to service deadlines is made against the clock in flush().

    Must be heap-allocated before use: profiling pointers and the
    loop reference store this struct's address, so it may not move
    afterwards.
    """

    var udp_socket: Socket
    var conn_dcid_map: Dict[UInt64, Int]
    var conn_h3s: List[Pointer[H3HandlerServer[BenchHandler], MutUntrackedOrigin]]
    var conn_addrs: List[List[Byte]]
    # Per-conn list of DCID-u64 keys we inserted into conn_dcid_map.
    # Used by _free_conn to remove ALL of a conn's entries on swap-and-pop
    # (B-permissive dual-DCID strategy: each conn has 2 entries — initial_dcid
    # AND local_cid).
    var conn_dcids: List[List[UInt64]]
    var pending_rx: List[PendingDatagram]
    var state_ptr: Pointer[BenchState, MutUntrackedOrigin]
    var tls_lib: SharedLibrary
    var server_config: QuicServerConfig

    # WatchLoop recv infrastructure.
    var _recv_pool: Optional[BufferPool]
    var _recv_stream: Optional[DatagramStream]

    # Live datagrams from the DatagramStream. Each Datagram holds a
    # LeasedBuffer whose raw pointers are stored in pending_rx. The
    # list keeps the leases alive until _flush_impl completes.
    var _live_datagrams: List[Optional[Datagram]]
    var _dgram_refcounts: List[UInt16]

    # Egress backlog — packets queued for the next _submit_egress.
    var _egress_backlog: List[EgressPacket]

    # WatchLoop-based timer for QUIC loss detection / idle close.
    var _timer: Optional[TimerFuture]
    var _loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin]
    # Absolute µs deadline the live kernel timer targets (None = no
    # live timer), plus test-readable arm bookkeeping.
    var _armed_deadline_us: Optional[UInt64]
    var _last_armed_ms: UInt64
    var _reset_count: Int
    var _timeout_count: Int
    # Test-only clock override consulted by `_now()`; None in production.
    var _clock_override_us: Optional[UInt64]

    # Plan C diagnostic — count kernel-level recvmsg drops + multishot terminations.
    var enobufs_count: UInt64
    var multishot_term_count: UInt64
    # Plan C diagnostic — count silent error swallows in _flush_impl.
    var quic_server_err_count: UInt64
    var h3_handler_err_count: UInt64
    var feed_datagram_err_count: UInt64
    var quic_server_err_first: Bool   # print first error message only

    def __init__(
        out self,
        var udp_socket: Socket,
        state_ptr: Pointer[BenchState, MutUntrackedOrigin],
        var tls_lib: SharedLibrary,
        var server_config: QuicServerConfig,
    ):
        """Build the server.

        Args:
            udp_socket: Bound dual-stack UDP socket wrapped in a Socket.
            state_ptr: Shared benchmark state (static cache + dataset).
            tls_lib: The rustls shared library handle.
            server_config: QUIC server config (certs + transport params).
        """
        self.udp_socket = udp_socket^
        self.conn_dcid_map = Dict[UInt64, Int]()
        self.conn_h3s = List[Pointer[H3HandlerServer[BenchHandler], MutUntrackedOrigin]]()
        self.conn_addrs = List[List[Byte]]()
        self.conn_dcids = List[List[UInt64]]()
        self.pending_rx = List[PendingDatagram]()
        self.state_ptr = state_ptr
        self.tls_lib = tls_lib^
        self.server_config = server_config^

        self._recv_pool = Optional[BufferPool](None)
        self._recv_stream = Optional[DatagramStream](None)
        self._live_datagrams = List[Optional[Datagram]]()
        self._dgram_refcounts = List[UInt16]()
        self._egress_backlog = List[EgressPacket]()
        self._timer = Optional[TimerFuture](None)
        self._loop_ptr = null_ptr[WatchLoop, MutUntrackedOrigin]()
        self._armed_deadline_us = Optional[UInt64](None)
        self._last_armed_ms = UInt64(0)
        self._reset_count = 0
        self._timeout_count = 0
        self._clock_override_us = Optional[UInt64](None)

        self.enobufs_count = UInt64(0)
        self.multishot_term_count = UInt64(0)
        self.quic_server_err_count = UInt64(0)
        self.h3_handler_err_count = UInt64(0)
        self.feed_datagram_err_count = UInt64(0)
        self.quic_server_err_first = False

    def __init__(out self, *, deinit move: Self):
        self.udp_socket = move.udp_socket^
        self.conn_dcid_map = move.conn_dcid_map^
        self.conn_h3s = move.conn_h3s^
        self.conn_addrs = move.conn_addrs^
        self.conn_dcids = move.conn_dcids^
        self.pending_rx = move.pending_rx^
        self.state_ptr = move.state_ptr
        self.tls_lib = move.tls_lib^
        self.server_config = move.server_config^
        self._recv_pool = move._recv_pool^
        self._recv_stream = move._recv_stream^
        self._live_datagrams = move._live_datagrams^
        self._dgram_refcounts = move._dgram_refcounts^
        self._egress_backlog = move._egress_backlog^
        self._timer = move._timer^
        self._loop_ptr = move._loop_ptr
        self._armed_deadline_us = move._armed_deadline_us^
        self._last_armed_ms = move._last_armed_ms
        self._reset_count = move._reset_count
        self._timeout_count = move._timeout_count
        self._clock_override_us = move._clock_override_us^
        self.enobufs_count = move.enobufs_count
        self.multishot_term_count = move.multishot_term_count
        self.quic_server_err_count = move.quic_server_err_count
        self.h3_handler_err_count = move.h3_handler_err_count
        self.feed_datagram_err_count = move.feed_datagram_err_count
        self.quic_server_err_first = move.quic_server_err_first

    # --- Conn lookup ---

    def _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        """Map a DCID to a connection index.

        Returns:
            The connection index, or -1 when the DCID is unknown.
        """
        if dcid_u64 in self.conn_dcid_map:
            try:
                return self.conn_dcid_map[dcid_u64]
            except:
                return -1
        return -1

    # --- Lifecycle ---

    def wire_context(mut self):
        """No-op kept for lifecycle compatibility."""
        pass

    def start(mut self, mut loop: WatchLoop) raises:
        """Create recv/send infrastructure and arm the periodic timer.

        Must be called after heap-allocation and before the first step.

        Args:
            loop: The WatchLoop that owns recv, send, and timers.
        """
        self._loop_ptr = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )

        # Create the buffer pool and arm multishot recvmsg.
        self._recv_pool = Optional(
            loop.buffer_pool(PBUF_COUNT, PBUF_SIZE)
        )
        self._recv_stream = Optional(
            loop.recv_msg_multishot(
                self.udp_socket,
                self._recv_pool.value(),
                control_capacity=_RECV_CONTROL_CAPACITY,
            )
        )

        # Arm the timer to the (empty) minimum deadline: the ceiling.
        self._rearm_timer()

    # --- clock ---

    def _now(self) -> UInt64:
        """Protocol time in µs: the test override when set, else monotonic."""
        if self._clock_override_us is not None:
            return self._clock_override_us.value()
        return monotonic_us()

    def _set_clock_for_tests(mut self, now_us: UInt64):
        """Pin `_now()` so tests can cross deadlines without sleeping."""
        self._clock_override_us = Optional[UInt64](now_us)

    # --- DatagramStream drain ---

    def _drain_recv_stream(mut self):
        """Take all available datagrams from the DatagramStream and
        buffer them into pending_rx for _flush_impl.

        Each Datagram's LeasedBuffer is kept alive in _live_datagrams
        so the raw pointers stored in PendingDatagram remain valid until
        _flush_impl completes and buffer leases are released.
        """
        if self._recv_stream is None:
            return

        while True:
            var dgram_opt = self._recv_stream.value().next()
            if dgram_opt is None:
                break

            # Skip truncated datagrams.
            if dgram_opt.value().truncated():
                continue

            # Decode the delivery header for payload and peer address.
            var hdr = DeliveryHeader(
                dgram_opt.value().buffer.bytes(),
                _RECV_NAME_CAPACITY,
                _RECV_CONTROL_CAPACITY,
            )
            var payload = hdr.payload()
            if len(payload) == 0:
                continue

            # Get peer address region.
            var name = hdr.name()

            # Extract DCID from the payload.
            var dcid: CidBuf
            try:
                dcid = extract_dcid(payload)
            except:
                # Bad packet — skip.
                continue

            var dgram_idx = len(self._live_datagrams)
            self._dgram_refcounts.append(UInt16(1))

            self.pending_rx.append(
                PendingDatagram(
                    payload_ptr=payload.unsafe_ptr(),
                    payload_len=len(payload),
                    name_ptr=name.unsafe_ptr(),
                    name_len=len(name),
                    dcid=dcid^,
                    dgram_idx=dgram_idx,
                )
            )

            # Keep the lease alive until _flush_impl completes.
            self._live_datagrams.append(dgram_opt^)

    # --- flush: step-driven batch processing ---

    def flush(mut self):
        """Drain the recv stream, process ingress, service deadlines, submit egress.

        Called by the external run loop after each step(). The timer pass
        runs before egress submission so timer-owed datagrams leave in
        this flush, and the timer is re-armed before `_submit_egress` so
        its SQE is reserved before egress can exhaust the queue.
        """
        # 1. Drain datagrams from the DatagramStream into pending_rx.
        self._drain_recv_stream()

        # 2. Process buffered ingress (DCID routing, QUIC feed, egress
        #    drain, reap of connections closed by ingress).
        try:
            self._flush_impl()
        except e:
            print("h3-bench: flush error:", e)

        # 3. Timer pass — by clock: when no timer is live or the earliest
        #    deadline has passed. Drains only expired slots, then reaps.
        var now = self._now()
        if self._timer_pass_due(now):
            try:
                self._timer_pass(now)
            except:
                pass

        # 4. Re-arm the timer to the new minimum deadline.
        self._rearm_timer()

        # 5. Submit egress from backlog via WatchLoop.send_msg.
        try:
            self._submit_egress()
        except:
            pass

        # 6. Release buffer leases whose refcount reached 0.
        for i in range(len(self._live_datagrams)):
            if self._dgram_refcounts[i] == UInt16(0):
                self._live_datagrams[i] = Optional[Datagram](None)
        self._live_datagrams.clear()
        self._dgram_refcounts.clear()

        # 7. Rearm the stream if it disarmed (typically ENOBUFS).
        if self._recv_stream is not None:
            if not self._recv_stream.value().armed():
                self.multishot_term_count += UInt64(1)
                try:
                    self._recv_stream.value().rearm()
                except:
                    pass  # Will retry next flush.

    # --- timer ---

    def _next_deadline_us(self, now: UInt64) -> Optional[UInt64]:
        """Earliest deadline over all conns; `now` for one with capped egress."""
        var earliest = Optional[UInt64](None)
        for i in range(len(self.conn_h3s)):
            var candidate: Optional[UInt64]
            if self.conn_h3s[i][].has_pending_egress():
                candidate = Optional[UInt64](now)
            else:
                candidate = self.conn_h3s[i][].timeout(now)
            if candidate is None:
                continue
            if earliest is None or candidate.value() < earliest.value():
                earliest = candidate
        return earliest

    def _timer_live(self) -> Bool:
        """True while a kernel timer whose completion has not arrived exists."""
        return self._timer is not None and not self._timer.value().done()

    def _timer_pass_due(self, now: UInt64) -> Bool:
        """Pass gate: no live timer, or the minimum deadline has passed."""
        if not self._timer_live():
            return True
        var d = self._next_deadline_us(now)
        return d is not None and d.value() <= now

    def _rearm_timer(mut self):
        """Keep exactly one live kernel timer aimed at the minimum deadline.

        Absent/done future: always a fresh `timeout()`. Live future:
        `reset` only when the target moved earlier by more than 1 ms; a
        refused reset means the loop is gone, so the deadline is
        forgotten and the loop is not touched. A raise from `timeout()`
        leaves no timer; the next flush retries through the pass gate.
        """
        if Int(self._loop_ptr) == 0:
            return
        var now = self._now()
        var ms = _timer_arm_ms(self._next_deadline_us(now), now)
        var want = now + ms * UInt64(1000)

        if self._timer_live():
            var earlier = True
            if self._armed_deadline_us is not None:
                earlier = want + UInt64(1000) < self._armed_deadline_us.value()
            if not earlier:
                return
            if self._timer.value().reset(ms):
                self._reset_count += 1
                self._armed_deadline_us = Optional[UInt64](want)
                self._last_armed_ms = ms
            else:
                self._armed_deadline_us = Optional[UInt64](None)
            return

        try:
            var fresh = self._loop_ptr[].timeout(ms)
            self._timer = Optional[TimerFuture](fresh^)
            self._armed_deadline_us = Optional[UInt64](want)
            self._last_armed_ms = ms
            self._timeout_count += 1
        except:
            self._timer = Optional[TimerFuture](None)
            self._armed_deadline_us = Optional[UInt64](None)

    def _timer_pass(mut self, now: UInt64) raises:
        """Drain only conns whose deadline passed or whose egress was capped, then reap."""
        for i in range(len(self.conn_h3s)):
            var due = self.conn_h3s[i][].has_pending_egress()
            if not due:
                var t = self.conn_h3s[i][].timeout(now)
                due = t is not None and t.value() <= now
            if not due:
                continue
            try:
                self._drain_and_send(i, now)
            except:
                pass
        self._reap_closed()

    def _flush_impl(mut self) raises:
        """Route every buffered datagram to its connection and drain egress."""
        var now = self._now()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()
            # DCID-keyed lookup. pd.dcid was extracted at _drain_recv_stream
            # (long+short header).
            var dcid_u64 = dcid_to_u64(pd.dcid.as_span())
            var conn_idx = self._find_conn_by_dcid(dcid_u64)

            # Strict new-conn gate per RFC 9000 section 12.4: only long-header Initial
            # packets create new conns. All other DCID-misses are dropped
            # silently (matches TQUIC, quiche, quic-go, aioquic).
            if conn_idx < 0:
                var first_byte_span = Span[Byte, MutUntrackedOrigin](
                    unsafe_ptr=pd.payload_ptr, length=pd.payload_len)
                if not is_long_header_initial(first_byte_span):
                    self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)
                    continue
                # Fall through to QuicConnection.server(...) construction below.


            if conn_idx < 0:
                # Create new QUIC connection. DCID was already extracted in
                # _drain_recv_stream and travels in PendingDatagram. Idle
                # disabled would leak abandoned handshakes; substitute the
                # server default.
                var tp = default_transport_params()
                if tp.max_idle_timeout == UInt64(0):
                    tp.max_idle_timeout = SERVER_DEFAULT_IDLE_TIMEOUT_MS
                var dcid_copy = List[Byte](capacity=Int(pd.dcid.len))
                var _dcid_span = pd.dcid.as_span()
                for _i in range(len(_dcid_span)):
                    dcid_copy.append(_dcid_span[_i])
                var quic: QuicConnection
                try:
                    quic = QuicConnection.server(
                        SharedLibrary(copy=self.tls_lib),
                        self.server_config,
                        tp,
                        pd.dcid.as_span(),
                        Span(dcid_copy),
                        now,
                    )
                except e:
                    self.quic_server_err_count += UInt64(1)
                    if not self.quic_server_err_first:
                        self.quic_server_err_first = True
                        print("h3-bench DIAG: first QuicConnection.server error:", e)
                    self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)
                    continue

                # B-permissive dual-DCID extract (BEFORE quic^ is moved into
                # H3HandlerServer): both initial_dcid (client's random ICID)
                # and local_cid (server's chosen SCID) map to the same
                # conn_idx. Both stay until conn teardown.
                debug_assert(len(quic.initial_dcid) == 8, "initial_dcid != 8 bytes")
                debug_assert(len(quic.local_cid) == 8, "local_cid != 8 bytes")

                var icid_u64 = dcid_to_u64(quic.initial_dcid.as_span())
                var lcid_u64 = dcid_to_u64(quic.local_cid.as_span())

                var handler = BenchHandler(self.state_ptr)
                var h3: H3HandlerServer[BenchHandler]
                try:
                    h3 = H3HandlerServer[BenchHandler](
                        quic=quic^,
                        handler=handler^,
                    )
                except e:
                    self.h3_handler_err_count += UInt64(1)
                    if self.h3_handler_err_count == UInt64(1):
                        print("h3-bench DIAG: first H3HandlerServer error:", e)
                    self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)
                    continue

                var h3_ptr = _heap_alloc[H3HandlerServer[BenchHandler]](1)
                h3_ptr.unsafe_write(h3^)

                # Build address from the delivery header name region.
                var addr = List[Byte](capacity=pd.name_len)
                for j in range(pd.name_len):
                    addr.append(pd.name_ptr[unsafe_offset=j])

                conn_idx = len(self.conn_h3s)
                self.conn_dcid_map[icid_u64] = conn_idx
                self.conn_dcid_map[lcid_u64] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)

                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)
                self.conn_dcids.append(dcids^)

            # Feed datagram to the connection.
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(pd.payload_ptr, pd.payload_len, now)
            except e:
                self.feed_datagram_err_count += UInt64(1)
                if self.feed_datagram_err_count == UInt64(1):
                    print("h3-bench DIAG: first feed_datagram_from_buffer error:", e)

            # Update peer address from the delivery header name region —
            # only when it changed, and never once the connection is
            # closing (checked after the feed so the datagram that
            # triggers the close cannot redirect the reflected CLOSE).
            if not self.conn_h3s[conn_idx][].is_closing_or_draining():
                if not _sockaddr_matches(
                    self.conn_addrs[conn_idx], pd.name_ptr, pd.name_len
                ):
                    var addr_update = List[Byte](capacity=pd.name_len)
                    for j in range(pd.name_len):
                        addr_update.append(pd.name_ptr[unsafe_offset=j])
                    self.conn_addrs[conn_idx] = addr_update^

            # Drain and queue outgoing datagrams.
            try:
                self._drain_and_send(conn_idx, now)
            except:
                pass

            # Release this segment's share of the buffer refcount.
            self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)

        self.pending_rx.clear()

        # Reap connections the ingress drove to CLOSED, now that no
        # pending_rx entry can resolve to a moved index.
        self._reap_closed()

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain outgoing datagrams from a connection and queue for sendmsg.

        Packets are queued as EgressPacket entries in _egress_backlog;
        _submit_egress sends them all via WatchLoop.send_msg after
        _flush_impl completes.
        """
        var datagrams = List[List[Byte]]()
        self.conn_h3s[conn_idx][].drain_datagrams(now, datagrams)
        for i in range(len(datagrams)):
            # Move the payload out of the drained list (swap with an
            # empty husk) rather than copying 1200 bytes per datagram.
            var pkt = List[Byte]()
            swap(pkt, datagrams[i])
            if len(pkt) == 0:
                continue

            var addr_copy = List[Byte](copy=self.conn_addrs[conn_idx])
            self._egress_backlog.append(EgressPacket(pkt^, addr_copy^))

    def _submit_egress(mut self) raises:
        """Submit queued egress packets via WatchLoop.send_msg.

        Fire-and-forget: the future is dropped immediately. WatchLoop
        owns the slab internally; QUIC handles retransmission on loss.
        Payloads move into their `Message` (no per-datagram copy).
        """
        var n = len(self._egress_backlog)
        if n == 0:
            return

        for i in range(n):
            var data = List[Byte]()
            swap(data, self._egress_backlog[i].data)
            var msg = Message(data^)
            _set_msg_peer_raw(msg, self._egress_backlog[i].addr)
            try:
                _ = self._loop_ptr[].send_msg(self.udp_socket, msg^)
            except:
                pass  # QUIC handles loss; drop silently.

        self._egress_backlog.clear()

    # --- reap path ---

    def _reap_closed(mut self) raises:
        """Free every conn reporting `should_close()`, walking downward.

        Swap-and-pop moves the last conn into the freed index; walking
        from the end guarantees the survivor was already examined.
        """
        var i = len(self.conn_h3s) - 1
        while i >= 0:
            if self.conn_h3s[i][].should_close():
                self._free_conn(i)
            i -= 1

    def _free_conn(mut self, i: Int) raises:
        """Destroy conn `i`, drop its DCIDs and swap-and-pop the parallel lists."""
        var ptr = self.conn_h3s[i]
        ptr.unsafe_deinit_pointee()
        ptr.unsafe_free()

        # B-permissive teardown: pop ALL of dying conn's DCID entries
        # (typically 2: initial_dcid + local_cid).
        for dcid_u64 in self.conn_dcids[i]:
            _ = self.conn_dcid_map.pop(dcid_u64)

        var last = len(self.conn_h3s) - 1
        if i != last:
            # Swap the last element into position i in all parallel
            # lists (conn_h3s, conn_addrs, conn_dcids).
            self.conn_h3s[i] = self.conn_h3s[last]
            self.conn_addrs[i] = List[Byte](copy=self.conn_addrs[last])
            self.conn_dcids[i] = List[UInt64](copy=self.conn_dcids[last])

            # Remap ALL of the swapped-in conn's DCID entries from
            # `last` to `i`. CRITICAL: do NOT break after first match
            # (the survivor has 2 entries; both must be remapped).
            for dcid_u64 in self.conn_dcids[i]:
                self.conn_dcid_map[dcid_u64] = i

        _ = self.conn_h3s.pop()
        _ = self.conn_addrs.pop()
        _ = self.conn_dcids.pop()

# ── main ─────────────────────────────────────────────────────────────


def main() raises:
    """Run the HTTP/3-over-QUIC benchmark server until killed."""
    # Load static files from STATIC_DIR env var (default /data/static).
    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if static_dir_opt.__bool__():
        static_dir = static_dir_opt.value()
    else:
        static_dir = String("/data/static")
    var cache = _load_static_files(static_dir)

    # Load dataset for the /json profile from DATA_DIR (default /data).
    var data_dir_opt = getenv_opt("DATA_DIR")
    var data_dir: String
    if data_dir_opt.__bool__():
        data_dir = data_dir_opt.value()
    else:
        data_dir = String("/data")
    var dataset = _load_dataset(data_dir + "/dataset.json")

    # Heap-allocate combined bench state.
    var bstate = BenchState(static_cache=cache^, dataset=dataset^)
    var state_ptr = _heap_alloc[BenchState](1)
    state_ptr.unsafe_write(bstate^)

    # Load TLS library and create server config.
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if certs_dir_opt.__bool__():
        certs_dir = certs_dir_opt.value()
    else:
        certs_dir = String("certs")

    var tls = TlsBackend()
    var cert = read_file(certs_dir + "/server.crt")
    var key = read_file(certs_dir + "/server.key")
    var server_config = QuicServerConfig(tls.shared(), Span(cert), Span(key))

    # Create UDP socket via the library factory, wrapped in a Socket for
    # WatchLoop compatibility.
    var port = 8443
    var sock = udp_listener(port)
    var udp_socket = Socket(sock^)

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h3-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""

    # BENCH_WAIT_NR was an io_uring-specific knob (submit_and_wait floor).
    # WatchLoop hides that detail; report and move on.
    var wait_nr_opt = getenv_opt("BENCH_WAIT_NR")
    if wait_nr_opt.__bool__():
        var requested: Int
        try:
            requested = Int(wait_nr_opt.value())
        except:
            print(prefix + "h3-bench: BENCH_WAIT_NR parse failed, ignoring")
            requested = 1
        if requested != 1:
            print(
                prefix
                + "h3-bench: BENCH_WAIT_NR="
                + String(requested)
                + " unsupported (WatchLoop manages wait internally); ignoring"
            )

    # Build the WatchLoop and the heap-stable server.
    var loop_ptr = _heap_alloc[WatchLoop](1)
    loop_ptr.unsafe_write(WatchLoop(capacity=_SQ_ENTRIES))

    var handler = H3UdpHandler(
        udp_socket=udp_socket^,
        state_ptr=state_ptr,
        tls_lib=tls.shared(),
        server_config=server_config^,
    )
    var srv_ptr = _heap_alloc[H3UdpHandler](1)
    srv_ptr.unsafe_write(handler^)
    srv_ptr[].wire_context()
    srv_ptr[].start(loop_ptr[])

    print(prefix + "h3-bench: listening on https://[::]:" + String(port) + " (UDP/QUIC/H3)")

    # Event loop.
    while True:
        # Bounded by the timer ceiling: if arming the timer ever fails,
        # only ingress would otherwise wake the loop.
        _ = loop_ptr[].step(Int(TIMER_CEILING_MS))

        # Process the datagrams this step buffered. flush() runs the full
        # ingress -> egress -> timer pipeline.
        srv_ptr[].flush()

        _ = loop_ptr
