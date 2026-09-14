"""H3UdpServer — generic UDP + QUIC + H3 server (proactor model).

Drives multiple H3 connections off a single UDP socket using
WatchLoop for both ingress (multishot recvmsg via DatagramStream)
and egress (send_msg with ECN cmsgs).

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H3UdpServer[H: StreamHandler]            WatchLoop (io_uring/epoll)
    │                                        │
    │  DatagramStream (multishot recvmsg) ──┘  (BufferPool leases)
    │  ├─ drained in flush() into pending_rx
    │  WatchLoop.send_msg ─────────────────┘   (per-datagram sendmsg)
    │  ├─ fire-and-forget; WatchLoop owns slab
    │
    │  WatchLoop (owns one TimerFuture armed to the earliest
    │  │          connection deadline, 1 ms floor, 1000 ms ceiling)
    │  ├─ a wake-up source only: flush() services deadlines by clock
    │
    │  flush() ──── (after each step)
    │  └─ _drain_recv_stream: take datagrams from DatagramStream
    │  └─ _flush_ingress: demux pending_rx by DCID, route to
    │                     H3HandlerServer[H] per conn, drain egress,
    │                     reap connections that closed
    │  └─ timer pass (when the timer fired or a deadline passed):
    │                     drain only the expired slots, reap closed ones
    │  └─ _rearm_timer: re-arm to the new minimum deadline
    │  └─ _submit_egress: build Message + ECN cmsg, send_msg
    │  └─ release buffer leases (_live_datagrams.clear)
    │
    └─ conn_slots[i]: ConnSlot[H] (h3 ptr + addr + dcids + generation)
         └─ owns a QuicConnection + an H instance
```

# Timer contract

The server keeps exactly one live kernel timer, armed to the minimum of
every slot's cached deadline (clamped to `[TIMER_FLOOR_MS,
TIMER_CEILING_MS]`). Each `ConnSlot` caches `timeout(now)` — or `now`
while its egress is capped — seeded at creation and, after that, rewritten
only by `_refresh_deadline` at the end of every `_drain_and_send` and
`inject_response`; the pass gate and the re-arm scan the cached integers
without touching a connection, and the pass drains only the slots whose
cached deadline has passed.
If arming raises (loop gone, submission queue exhausted) no timer is live
until the next `flush()` retries; only ingress wakes the loop in that
state, so run loops must call `loop.step(TIMER_CEILING_MS)` rather than
an unbounded `step()`.

# Per-conn handler factory

`H` is the per-request handler trait (`StreamHandler`). Each new
QUIC connection allocates a fresh `H3HandlerServer[H]` on the heap,
which owns its own `H`. The library makes a new `H` for each conn
via `H()` (default constructor) — implement `H.__init__(out self)`
with whatever setup your handler needs. Per-conn state lives on the
handler instance; shared state lives behind a pointer the handler
holds.

# Lifetime / ownership

The UDP socket is wrapped in a `Socket` and moved into the server;
RAII keeps it alive for the entire loop's lifetime. The `TlsBackend`
and `QuicServerConfig` are moved into the server and destroyed
after all connections.

# Integration

After construction, the caller must:
  1. Heap-allocate the server (pointer stability).
  2. Call `wire_context()` (no-op kept for lifecycle compatibility).
  3. Call `start(loop)` to probe transport capabilities, create
     the BufferPool and DatagramStream, and arm the timer.
  4. In the run loop: `loop.step(TIMER_CEILING_MS)`, then `server.flush()`.
"""

from std.collections import Optional
from std.collections.dict import Dict
from std.memory import Pointer
from std.memory.alloc import unsafe_alloc as _heap_alloc

from boucle import (
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
from boucle.handle import OwnedHandle

from navette.runtime.udp_socket_state import UdpSocketState
from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import EarlyDataPredicateFn, IdempotentOnlyFilter
from navette.http.handler import StreamHandler
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.h3.h3_handler_server import H3HandlerServer
from navette.quic.cid import dcid_to_u64
from navette.quic.connection import QuicConnection
from navette.quic.packet import is_long_header_initial, extract_dcid, DcidBuf
from navette.quic.path_validator import PathKey
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us
from navette.quic.trans_param import TransportParams
from navette.util.null_ptr import null_ptr


# ── Wire constants ────────────────────────────────────────────────────────────


# BufferPool sizing for multishot recvmsg (via WatchLoop).
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600

# Control capacity passed to recv_msg_multishot. 48 bytes fits both
# an IP_TOS/IPV6_TCLASS record (24 B) and a UDP_GRO record (24 B).
comptime _RECV_CONTROL_CAPACITY: Int = 48

# Peer address capacity used by the delivery header decoder. Must
# match boucle's _NAME_CAPACITY (sizeof(sockaddr_in6) = 28 on x86_64).
comptime _RECV_NAME_CAPACITY: Int = 28

# Control capacity for egress Messages. 24 bytes holds one IP_TOS (1 B)
# or IPV6_TCLASS (4 B) ECN cmsg record (both 24 after CMSG_ALIGN).
comptime _SEND_CONTROL_CAPACITY: Int = 24

# Control capacity for GSO-batched egress Messages. 48 bytes holds one
# ECN cmsg (24 B) plus one SOL_UDP/UDP_SEGMENT record (24 B).
comptime _SEND_CONTROL_CAPACITY_GSO: Int = 48


# ── Timer policy ─────────────────────────────────────────────────────────────


# Bounds on the loop timer, in milliseconds. The floor matches the 1 ms
# granularity of the reference stacks; the ceiling bounds how long the
# loop sleeps when no connection has a deadline (and is the backstop run
# loops pass to `step()` when no timer is live).
comptime TIMER_FLOOR_MS: UInt64 = 1
comptime TIMER_CEILING_MS: UInt64 = 1000

# Idle timeout substituted when the configured transport parameters
# carry 0 (idle disabled): a public server must not keep the state of an
# abandoned handshake forever. `default_transport_params()` keeps 0 so
# client and test defaults are unchanged.
comptime SERVER_DEFAULT_IDLE_TIMEOUT_MS: UInt64 = 30_000

# "No deadline" sentinel for `ConnSlot.next_deadline_us`. `UInt64.MAX` so the
# scan is a plain min over integers; produced only by the `ConnSlot`
# constructor and by `_refresh_deadline` when `timeout()` returns None.
comptime NO_DEADLINE_US: UInt64 = UInt64.MAX


def _earliest_cached_deadline[H: StreamHandler](
    slots: List[ConnSlot[H]],
) -> Optional[UInt64]:
    """Min of every slot's cached deadline; None when no slot has one. Never dereferences `h3`."""
    var best = NO_DEADLINE_US
    for i in range(len(slots)):
        var d = slots[i].next_deadline_us
        if d < best:
            best = d
    if best == NO_DEADLINE_US:
        return Optional[UInt64](None)
    return Optional[UInt64](best)


def _timer_arm_ms(deadline: Optional[UInt64], now: UInt64) -> UInt64:
    """Milliseconds to arm the loop timer for a deadline at absolute µs.

    `ceil((deadline - now) / 1000)` clamped to `[TIMER_FLOOR_MS,
    TIMER_CEILING_MS]`; the ceiling when there is no deadline, the floor
    when it has already passed. Pure so tests can pin it directly.
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
    addr: List[UInt8],
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


def _sockaddr_to_path_key(
    buf_ptr: Pointer[mut=True, T=UInt8, origin=_],
    addr_offset: Int,
    addr_len: Int,
) -> PathKey:
    """Decode a Linux sockaddr_in / sockaddr_in6 blob into a `PathKey`.

    Layouts (host = little-endian for x86_64; family stored LE):

      sockaddr_in (16 B):
        [0..2)  sa_family (LE)         = AF_INET (2)
        [2..4)  sin_port  (BE)
        [4..8)  sin_addr  (network-order = BE)
        [8..16) zero pad

      sockaddr_in6 (28 B):
        [0..2)  sa_family (LE)         = AF_INET6 (10)
        [2..4)  sin6_port (BE)
        [4..8)  sin6_flowinfo          (ignored)
        [8..24) sin6_addr (16 B, BE)
        [24..28) sin6_scope_id         (ignored)

    The returned `PathKey.addr` is always 16 bytes. IPv4 zero-pads the
    high 12 bytes (matches `PathKey.from_v4`). Unknown family / short
    blobs yield `PathKey.zero()` — equality against any real peer is
    False, so the address-change branch will start a fresh challenge
    rather than spuriously trusting an empty addr.
    """
    if addr_len < 4:
        return PathKey.zero()

    # sa_family is little-endian on Linux x86_64.
    var family = Int32(
        Int(buf_ptr[unsafe_offset=addr_offset]) | (Int(buf_ptr[unsafe_offset=addr_offset + 1]) << 8)
    )
    # Port is network-order (big-endian).
    var port_hi = UInt16(buf_ptr[unsafe_offset=addr_offset + 2])
    var port_lo = UInt16(buf_ptr[unsafe_offset=addr_offset + 3])
    var port = (port_hi << 8) | port_lo

    if family == Int32(2):
        # AF_INET — 4-octet address at offset+4.
        if addr_len < 8:
            return PathKey.zero()
        return PathKey.from_v4(
            buf_ptr[unsafe_offset=addr_offset + 4],
            buf_ptr[unsafe_offset=addr_offset + 5],
            buf_ptr[unsafe_offset=addr_offset + 6],
            buf_ptr[unsafe_offset=addr_offset + 7],
            port,
        )
    elif family == Int32(10):
        # AF_INET6 — 16-octet address at offset+8.
        if addr_len < 24:
            return PathKey.zero()
        var addr = InlineArray[UInt8, 16](fill=UInt8(0))
        for i in range(16):
            addr[i] = buf_ptr[unsafe_offset=addr_offset + 8 + i]
        return PathKey(Int32(10), addr^, port)
    else:
        return PathKey.zero()


def _set_msg_peer_raw(mut msg: Message, addr: List[UInt8]):
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


def _egress_addrs_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Byte-compare two raw sockaddr blobs for GSO grouping."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


# ── Pending datagram (ingress queue) ──────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    """A single inbound UDP segment parked between stream drain and flush.

    `payload_ptr` and `name_ptr` are raw pointers into the
    `DatagramStream`'s leased buffer. The lease stays alive in
    `_live_datagrams` until `_flush_ingress` completes. `dgram_idx`
    indexes into `_live_datagrams` / `_dgram_refcounts` so the
    refcount can be decremented when this segment is consumed.
    """
    var payload_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var payload_len: Int
    var name_ptr: Pointer[UInt8, MutUntrackedOrigin]
    var name_len: Int
    var dcid: DcidBuf
    var ecn_mark: UInt8
    var dgram_idx: Int

    def __init__(
        out self,
        payload_ptr: Pointer[UInt8, MutUntrackedOrigin],
        payload_len: Int,
        name_ptr: Pointer[UInt8, MutUntrackedOrigin],
        name_len: Int,
        var dcid: DcidBuf,
        ecn_mark: UInt8,
        dgram_idx: Int,
    ):
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.name_ptr = name_ptr
        self.name_len = name_len
        self.dcid = dcid^
        self.ecn_mark = ecn_mark
        self.dgram_idx = dgram_idx

    def __init__(out self, *, copy: Self):
        self.payload_ptr = copy.payload_ptr
        self.payload_len = copy.payload_len
        self.name_ptr = copy.name_ptr
        self.name_len = copy.name_len
        self.dcid = DcidBuf(copy=copy.dcid)
        self.ecn_mark = copy.ecn_mark
        self.dgram_idx = copy.dgram_idx

    def __init__(out self, *, deinit move: Self):
        self.payload_ptr = move.payload_ptr
        self.payload_len = move.payload_len
        self.name_ptr = move.name_ptr
        self.name_len = move.name_len
        self.dcid = move.dcid^
        self.ecn_mark = move.ecn_mark
        self.dgram_idx = move.dgram_idx


# ── Egress packet (queued for flush submission) ─────────────────────────────


struct EgressPacket(Movable):
    """A queued egress datagram — payload + destination address + ECN mark.

    Buffered during CQE callbacks (timeout drains) and injected
    cross-transport responses. Submitted via WatchLoop.send_msg in
    flush()'s _submit_egress phase.
    """

    var data: List[UInt8]
    var addr: List[UInt8]
    var conn_idx: Int
    var ecn_mark: UInt8

    def __init__(
        out self,
        var data: List[UInt8],
        var addr: List[UInt8],
        conn_idx: Int,
        ecn_mark: UInt8,
    ):
        """Construct an egress packet.

        Args:
            data: Packet payload bytes (moved in).
            addr: Peer sockaddr bytes for sendmsg routing (moved in).
            conn_idx: Index into conn_slots for bookkeeping.
            ecn_mark: ECN codepoint from the QUIC connection's ecn_mark().
        """
        self.data = data^
        self.addr = addr^
        self.conn_idx = conn_idx
        self.ecn_mark = ecn_mark

    def __init__(out self, *, deinit move: Self):
        self.data = move.data^
        self.addr = move.addr^
        self.conn_idx = move.conn_idx
        self.ecn_mark = move.ecn_mark


# ── Connection slot + DCID demux entry ──────────────────────────────────────


struct _DcidEntry(Copyable, Movable):
    """`(idx, generation)` value of the DCID → connection-slot demux map.

    The generation guard lets a stale entry — left behind when a closed
    slot's index was reused by swap-and-pop — be detected at lookup time
    by comparing against the current `conn_slots[idx].generation`.
    """
    var idx: Int
    var generation: UInt64

    def __init__(out self, idx: Int, generation: UInt64):
        self.idx = idx
        self.generation = generation

    def __init__(out self, *, copy: Self):
        self.idx = copy.idx
        self.generation = copy.generation

    def __init__(out self, *, deinit move: Self):
        self.idx = move.idx
        self.generation = move.generation


struct ConnSlot[H: StreamHandler](Copyable, Movable):
    """One QUIC/H3 connection's per-slot record, indexed by `conn_slots` position.

    `dcids` holds every DCID the connection responds to (typically
    `[initial_dcid, local_cid]`). `generation` increments every time the
    slot is overwritten by a swap-and-pop survivor, so stale demux entries
    can be detected at lookup time.

    `next_deadline_us` caches the connection's earliest deadline as of
    `deadline_refreshed_at_us` (`now` while egress is capped, `timeout()`
    otherwise, `NO_DEADLINE_US` for none); after construction only the
    creation-time write and `_refresh_deadline` may change it, and the
    timer scan reads it without touching `h3`.

    `Copyable` is required by `List[ConnSlot[H]]` storage; aliasing
    `h3` across copies matches the prior `List[UnsafePointer[...]]`
    semantics (the underlying pointer was already trivially copied
    when the list grew).
    """
    var h3: Pointer[H3HandlerServer[Self.H], MutUntrackedOrigin]
    var addr: List[UInt8]
    var dcids: List[UInt64]
    var generation: UInt64
    var next_deadline_us: UInt64
    var deadline_refreshed_at_us: UInt64

    def __init__(
        out self,
        h3: Pointer[H3HandlerServer[Self.H], MutUntrackedOrigin],
        var addr: List[UInt8],
        var dcids: List[UInt64],
        generation: UInt64,
    ):
        self.h3 = h3
        self.addr = addr^
        self.dcids = dcids^
        self.generation = generation
        self.next_deadline_us = NO_DEADLINE_US
        self.deadline_refreshed_at_us = UInt64(0)

    def __init__(out self, *, copy: Self):
        self.h3 = copy.h3
        self.addr = List[UInt8](copy=copy.addr)
        self.dcids = List[UInt64](copy=copy.dcids)
        self.generation = copy.generation
        self.next_deadline_us = copy.next_deadline_us
        self.deadline_refreshed_at_us = copy.deadline_refreshed_at_us

    def __init__(out self, *, deinit move: Self):
        self.h3 = move.h3
        self.addr = move.addr^
        self.dcids = move.dcids^
        self.generation = move.generation
        self.next_deadline_us = move.next_deadline_us
        self.deadline_refreshed_at_us = move.deadline_refreshed_at_us


# ── H3UdpServer ──────────────────────────────────────────────────────────────


struct H3UdpServer[H: StreamHandler](Movable):
    """Generic UDP + QUIC + H3 server (proactor model).

    Parameterised on `H: StreamHandler`. Each accepted connection
    allocates a heap-owned `H3HandlerServer[H]` which owns its own
    `H` instance plus the underlying `QuicConnection` + `H3Connection`.

    Both ingress and egress use WatchLoop: ingress via a
    `DatagramStream` (multishot recvmsg backed by a `BufferPool`),
    egress via `WatchLoop.send_msg` with ECN marks written as cmsgs.
    An explicit `flush()` method drains the stream, processes buffered
    packets through QUIC, submits egress via send_msg, and releases
    buffer leases.

    `make_handler` is a user-provided factory function called once per
    new QUIC connection. The factory owns construction policy — share
    state via captured pointers (Mojo doesn't have closures yet, so
    factories typically read from a module-level singleton or take
    state via the surrounding context the user threads through).
    """

    # Listening UDP socket. Wraps the OwnedHandle in a Socket so
    # WatchLoop.recv_msg_multishot can reference it and set_recv_tos
    # can enable ECN cmsgs. RAII keeps the fd alive for the entire
    # loop's lifetime.
    var udp_socket: Socket

    # Transport params reused for every new QuicConnection.server() call.
    var transport_params: TransportParams

    # Per-conn handler factory.
    var make_handler: def () thin raises -> Self.H

    # Per-conn book-keeping. `conn_slots[i]` collapses what used to be
    # three parallel lists (h3 pointer / addr / dcids) plus a generation
    # counter. `conn_dcid_map` keys every DCID this conn responds to
    # (typically [initial_dcid, local_cid] for dual-DCID demux) to a
    # `(idx, generation)` pair; the generation guard catches stale
    # entries left behind by swap-and-pop.
    var conn_slots: List[ConnSlot[Self.H]]
    var conn_dcid_map: Dict[UInt64, _DcidEntry]
    var next_generation: UInt64

    # TLS backend instance. Declared AFTER conn_slots so that Mojo's
    # declaration-order destruction destroys connections before the library.
    var _tls: TlsBackend

    # QUIC server TLS config wrapper. Destroyed after connections, before
    # the library (declaration order).
    var server_config: QuicServerConfig

    # Ingress staging. pending_rx fills from _drain_recv_stream;
    # _flush_ingress drains it in flush().
    var pending_rx: List[PendingDatagram]

    # Live datagrams from the DatagramStream. Each Datagram holds a
    # LeasedBuffer whose raw pointers are stored in pending_rx. The
    # list keeps the leases alive until _flush_ingress completes; then
    # entries whose refcount reached 0 are released.
    var _live_datagrams: List[Optional[Datagram]]

    # Per-datagram refcount, parallel to _live_datagrams. A GRO-
    # coalesced datagram produces N PendingDatagram entries sharing one
    # buffer lease; the refcount starts at N and decrements as each
    # segment is consumed in _flush_ingress. Non-GRO datagrams use
    # refcount 1 (unified path).
    var _dgram_refcounts: List[UInt16]

    # Egress backlog — packets queued for the next _submit_egress.
    var _egress_backlog: List[EgressPacket]

    # Cross-transport injection staging (from inject_response).
    var _inject_egress: List[EgressPacket]

    # Maximum datagrams that may be packed into one GSO super-buffer.
    # Starts at 1 (no GSO); wired from UdpSocketState in start().
    # Permanently downgraded to 1 on the first GSO send failure.
    var _gso_max_segments: Int

    # Transport capability snapshot probed in start(). Holds GRO/GSO
    # probe results and receives downgrade notifications on GSO failure.
    var _socket_state: Optional[UdpSocketState]

    # WatchLoop recv infrastructure. _recv_pool is the BufferPool
    # backing the multishot recvmsg. _recv_stream is the DatagramStream
    # handle. Both created in start(). The stream is declared AFTER the
    # pool so Mojo's reverse-declaration-order destruction drops the
    # stream before the pool.
    var _recv_pool: Optional[BufferPool]
    var _recv_stream: Optional[DatagramStream]

    # WatchLoop-based timer for QUIC loss detection / idle close.
    # _timer holds the in-flight TimerFuture; _loop_ptr points at the
    # caller's WatchLoop so flush() can re-arm after each expiry.
    var _timer: Optional[TimerFuture]
    var _loop_ptr: Pointer[WatchLoop, MutUntrackedOrigin]

    # Absolute µs deadline the live kernel timer targets; None when no
    # timer is live. `_rearm_timer` only issues a reset when the wanted
    # target is earlier than this by more than 1 ms.
    var _armed_deadline_us: Optional[UInt64]
    # Test-readable timer bookkeeping: the last value handed to
    # `timeout()`/`reset()`, and how many of each were issued.
    var _last_armed_ms: UInt64
    var _reset_count: Int
    var _timeout_count: Int

    # Test-only: how many times `_refresh_deadline` ran. On production
    # paths this is >= the number of `QuicConnection.timeout()` calls
    # (equal when no slot is capped).
    var _deadline_refresh_count: Int

    # Test-only clock override consulted by `_now()`; None in production.
    var _clock_override_us: Optional[UInt64]

    # PROFILE_ACCEPT counters (always present; dead-stripped when
    # PROFILE_ACCEPT=False at compile time).
    var profile: AcceptProfile

    # ── Construction ─────────────────────────────────────────────

    def __init__(
        out self,
        var udp_handle: OwnedHandle,
        var tls: TlsBackend,
        var server_config: QuicServerConfig,
        var transport_params: TransportParams,
        make_handler: def () thin raises -> Self.H,
    ):
        """Construct an H3UdpServer.

        After construction, the caller must heap-allocate the server
        (for pointer stability), then call `wire_context()` followed by
        `start(loop)` before any tick.

        Args:
            udp_handle: Owned UDP socket handle (moved in, wrapped in Socket).
            tls: TLS backend instance (moved in).
            server_config: QUIC server TLS config (moved in).
            transport_params: Transport parameters for new connections. A
                `max_idle_timeout` of 0 is replaced by
                `SERVER_DEFAULT_IDLE_TIMEOUT_MS` in `start()`, silently.
            make_handler: Factory function producing one H per connection.
        """
        self.udp_socket = Socket(udp_handle^)
        self.transport_params = transport_params^
        self.make_handler = make_handler

        self.conn_slots = List[ConnSlot[Self.H]]()
        self.conn_dcid_map = Dict[UInt64, _DcidEntry]()
        self.next_generation = UInt64(0)

        self._tls = tls^
        self.server_config = server_config^

        self.pending_rx = List[PendingDatagram]()
        self._live_datagrams = List[Optional[Datagram]]()
        self._dgram_refcounts = List[UInt16]()

        self._egress_backlog = List[EgressPacket]()
        self._inject_egress = List[EgressPacket]()

        self._gso_max_segments = 1
        self._socket_state = Optional[UdpSocketState](None)

        # Recv pool + stream — created in start() via WatchLoop.
        self._recv_pool = Optional[BufferPool](None)
        self._recv_stream = Optional[DatagramStream](None)

        # Timer — armed in start() via _rearm_timer().
        self._timer = Optional[TimerFuture](None)
        self._loop_ptr = null_ptr[WatchLoop, MutUntrackedOrigin]()
        self._armed_deadline_us = Optional[UInt64](None)
        self._last_armed_ms = UInt64(0)
        self._reset_count = 0
        self._timeout_count = 0
        self._deadline_refresh_count = 0
        self._clock_override_us = Optional[UInt64](None)

        self.profile = AcceptProfile()

    def __init__(out self, *, deinit move: Self):
        self.udp_socket = move.udp_socket^
        self.transport_params = move.transport_params^
        self.make_handler = move.make_handler
        self.conn_slots = move.conn_slots^
        self.conn_dcid_map = move.conn_dcid_map^
        self.next_generation = move.next_generation
        self._tls = move._tls^
        self.server_config = move.server_config^
        self.pending_rx = move.pending_rx^
        self._live_datagrams = move._live_datagrams^
        self._dgram_refcounts = move._dgram_refcounts^
        self._egress_backlog = move._egress_backlog^
        self._inject_egress = move._inject_egress^
        self._gso_max_segments = move._gso_max_segments
        self._socket_state = move._socket_state^
        self._recv_pool = move._recv_pool^
        self._recv_stream = move._recv_stream^
        self._timer = move._timer^
        self._loop_ptr = move._loop_ptr
        self._armed_deadline_us = move._armed_deadline_us^
        self._last_armed_ms = move._last_armed_ms
        self._reset_count = move._reset_count
        self._timeout_count = move._timeout_count
        self._deadline_refresh_count = move._deadline_refresh_count
        self._clock_override_us = move._clock_override_us^
        self.profile = move.profile^

    def __deinit__(deinit self):
        """Free heap allocations owned by the server.

        Walks any live `conn_slots`, destroying their pointees before
        freeing the per-slot heap blocks. The recv stream, buffer pool,
        live datagrams, and timer are cleaned up by their respective
        field destructors. On clean teardown conn_slots is typically
        empty; the walk defends against drop-mid-flight.
        """
        for i in range(len(self.conn_slots)):
            var ptr = self.conn_slots[i].h3
            ptr.unsafe_deinit_pointee()
            ptr.unsafe_free()

    # ── Connection lookup ────────────────────────────────────────

    def _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        """Resolve `dcid → conn_slots index`, returning -1 if absent or
        if the demux entry is stale (slot's generation has moved on)."""
        if dcid_u64 not in self.conn_dcid_map:
            return -1
        try:
            var entry = self.conn_dcid_map[dcid_u64].copy()
            if entry.idx < 0 or entry.idx >= len(self.conn_slots):
                return -1
            if self.conn_slots[entry.idx].generation != entry.generation:
                return -1
            return entry.idx
        except:
            return -1

    # ── Lifecycle — wire_context / start / flush ────────────────

    def wire_context(mut self):
        """No-op kept for lifecycle compatibility.

        Previously wired SendSlabPool context pointers; egress now uses
        WatchLoop.send_msg which manages its own slab internally. Callers
        may still call this between heap-allocation and start() — it
        does nothing.
        """
        pass

    def start(mut self, mut loop: WatchLoop) raises:
        """Probe transport capabilities and create recv/send infrastructure.

        Must be called after wire_context() and before the first tick.
        Probes the socket for GRO/GSO support via `UdpSocketState`,
        sizes the `BufferPool` accordingly, arms a multishot recvmsg
        `DatagramStream` through the WatchLoop, and arms the timer.

        The WatchLoop must outlive this server; `_loop_ptr` is stored
        for re-arming the timer in `flush()`.

        Args:
            loop: The WatchLoop that owns recv, send, and timers.
        """
        # Store loop pointer for re-arming in flush().
        self._loop_ptr = Pointer[WatchLoop, MutUntrackedOrigin](
            unsafe_from_address=Int(Pointer(to=loop))
        )

        # Idle disabled would leak the state of every abandoned
        # handshake on a public server; substitute the server default.
        if self.transport_params.max_idle_timeout == UInt64(0):
            self.transport_params.max_idle_timeout = (
                SERVER_DEFAULT_IDLE_TIMEOUT_MS
            )

        # Probe transport capabilities (ECN, GRO, GSO) on the socket.
        # UdpSocketState enables ECN internally, so no separate
        # set_recv_tos call is needed.
        var state = UdpSocketState(self.udp_socket)
        self._gso_max_segments = state.max_send_segments()

        # Size the buffer pool based on GRO support: fewer, larger
        # buffers when the kernel coalesces datagrams; many small
        # buffers otherwise.
        var buf_count = PBUF_COUNT
        var buf_size = state.recv_buffer_size()
        if state.supports_coalesced_recv():
            buf_count = 128

        self._socket_state = Optional(state^)

        # Create the buffer pool and arm multishot recvmsg.
        self._recv_pool = Optional(
            loop.buffer_pool(buf_count, buf_size)
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

    # ── Clock ────────────────────────────────────────────────────

    def _now(self) -> UInt64:
        """Protocol time in µs: the test override when set, else monotonic."""
        if self._clock_override_us is not None:
            return self._clock_override_us.value()
        return monotonic_us()

    def _set_clock_for_tests(mut self, now_us: UInt64):
        """Pin `_now()` so tests can cross deadlines without sleeping.

        Never call from production code: the kernel timer keeps real time,
        and only the clock gate in `flush()` honours the override.
        """
        self._clock_override_us = Optional[UInt64](now_us)

    def flush(mut self) raises:
        """Drain the recv stream, process ingress, service deadlines, submit egress.

        Called by the external run loop after each step. MUST NOT call
        loop.step() during flush (no-callback-during-flush invariant).

        Order matters: the timer pass runs before egress submission so a
        datagram owed to a deadline (delayed ACK, PTO probe, CLOSE) leaves
        in this flush rather than on the next unrelated wake, and the
        timer is re-armed before `_submit_egress` so its SQE is reserved
        before egress can exhaust the submission queue. Lease release
        stays last because a GRO segment consumed by ingress only frees
        its buffer once every sibling segment is done. Only the slots this
        flush fed or drained are recomputed; the pass gate and the re-arm
        read the per-slot cache.
        """
        # 1. Drain datagrams from the DatagramStream into pending_rx.
        self._drain_recv_stream()

        # 2. Process buffered ingress (DCID routing, QUIC feed, egress
        #    drain) and reap connections that closed while doing so.
        self._flush_ingress()

        # 3. Drain inject_egress (from inject_response cross-transport path).
        while len(self._inject_egress) > 0:
            self._egress_backlog.append(self._inject_egress.pop())

        # 4. Timer pass — by clock, not by kernel completion: run when no
        #    timer is live or the earliest deadline has passed.
        var now = self._now()
        if self._timer_pass_due(now):
            try:
                self._timer_pass(now)
            except:
                pass

        # 5. Re-arm the timer to the new minimum deadline.
        self._rearm_timer()

        # 6. Submit egress from backlog via WatchLoop.send_msg.
        self._submit_egress()

        # 7. Release buffer leases whose refcount reached 0.
        # GRO-coalesced datagrams share one lease across N segments;
        # the refcount for each entry was decremented in _flush_ingress
        # as each segment was consumed. Non-GRO entries have refcount 1.
        # Setting the Optional to None drops the Datagram (and its
        # LeasedBuffer), returning the buffer to the pool.
        for _ri in range(len(self._live_datagrams)):
            if self._dgram_refcounts[_ri] == UInt16(0):
                self._live_datagrams[_ri] = Optional[Datagram](None)
        self._live_datagrams.clear()
        self._dgram_refcounts.clear()
        # Rearm the stream if it disarmed (typically ENOBUFS when
        # all buffers were leased). Now that leases are returned,
        # the pool has capacity again.
        if self._recv_stream is not None:
            if not self._recv_stream.value().armed():
                try:
                    self._recv_stream.value().rearm()
                except:
                    pass  # Will retry next flush.

    # ── Timer ────────────────────────────────────────────────────

    def _next_deadline_us(self) -> Optional[UInt64]:
        """Earliest cached deadline over all slots (a capped slot caches its refresh `now`)."""
        return _earliest_cached_deadline(self.conn_slots)

    def _timer_live(self) -> Bool:
        """True while a kernel timer whose completion has not arrived exists."""
        return self._timer is not None and not self._timer.value().done()

    def _deadline_cache_matches_oracle(self) -> Bool:
        """Test-only: every slot's cache equals `now`/`timeout()` recomputed at its own refresh instant.

        Costs the N recomputes the cache removes, so it is never wired under
        `ASSERT=all`; the test harness calls it after each `flush()`.
        """
        for i in range(len(self.conn_slots)):
            var t = self.conn_slots[i].deadline_refreshed_at_us
            var expect: UInt64
            if self.conn_slots[i].h3[].has_pending_egress():
                expect = t
            else:
                var d = self.conn_slots[i].h3[].timeout(t)
                expect = d.value() if d else NO_DEADLINE_US
            if self.conn_slots[i].next_deadline_us != expect:
                return False
        return True

    def _refresh_deadline(mut self, idx: Int, now: UInt64):
        """Recompute slot `idx`'s cached deadline: `now` while egress is capped, else `timeout(now)`.

        The only production writer of the cache; every server path that
        mutates a connection reaches it before the next reader runs.
        """
        self._deadline_refresh_count += 1
        self.conn_slots[idx].deadline_refreshed_at_us = now
        if self.conn_slots[idx].h3[].has_pending_egress():
            self.conn_slots[idx].next_deadline_us = now
            return
        var t = self.conn_slots[idx].h3[].timeout(now)
        self.conn_slots[idx].next_deadline_us = t.value() if t else NO_DEADLINE_US

    def _timer_pass_due(self, now: UInt64) -> Bool:
        """Pass gate: no live timer, or the minimum cached deadline has passed."""
        if not self._timer_live():
            return True
        var d = self._next_deadline_us()
        return d is not None and d.value() <= now

    def _rearm_timer(mut self):
        """Keep exactly one live kernel timer aimed at the minimum cached deadline.

        Takes a fresh `_now()` so the flush duration does not skew the
        target. A done or absent future is always replaced by a new
        `timeout()`; a live one is `reset` only when the target moved
        earlier by more than 1 ms (an early fire is a harmless no-op
        pass, so a later target is left alone). A `reset` refusal means
        the loop is gone: the future is kept but forgotten as a deadline,
        and nothing dereferences the loop. A raise from `timeout()`
        leaves no timer; the next flush retries through the pass gate.
        """
        if Int(self._loop_ptr) == 0:
            return
        var now = self._now()
        var ms = _timer_arm_ms(self._next_deadline_us(), now)
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
        """Drain only the slots whose cached deadline passed, then reap.

        A capped slot caches `now` at its refresh, so it is due on the next
        pass. Each drained slot either advances its deadline, becomes CLOSED,
        or is still capped (progress by construction), so no slot is drained
        on consecutive passes without progress. Only the drained slots are
        recomputed; the loop itself is an O(N) integer compare.
        """
        for i in range(len(self.conn_slots)):
            if self.conn_slots[i].next_deadline_us > now:
                continue
            try:
                self._drain_and_send(i, now)
            # Silent on purpose: a slot whose send() raises persistently stays due on
            # every pass (>= 1000 lines/s with no peer input); ingress already reports it.
            except:
                pass
        self._reap_closed()

    def _reap_closed(mut self) raises:
        """Free every slot reporting `should_close()`, walking downward.

        Swap-and-pop moves the last slot into the freed index; walking
        from the end guarantees the survivor was already examined. Never
        called while `pending_rx` is being iterated, since its entries
        resolve slot indices through the DCID map.
        """
        var i = len(self.conn_slots) - 1
        while i >= 0:
            if self.conn_slots[i].h3[].should_close():
                self._free_slot(i)
            i -= 1

    def _free_slot(mut self, i: Int) raises:
        """Destroy slot `i`'s connection, drop its DCIDs and swap-and-pop."""
        var slot_h3 = self.conn_slots[i].h3
        slot_h3.unsafe_deinit_pointee()
        slot_h3.unsafe_free()
        # Null out the field immediately so any later read on
        # `conn_slots[i].h3` (before swap-and-pop overwrites the slot or
        # `pop()` discards it) hits a clean null rather than a dangling
        # pointer.
        self.conn_slots[i].h3 = null_ptr[
            H3HandlerServer[Self.H], MutUntrackedOrigin
        ]()

        # B-permissive teardown: pop ALL of dying conn's DCID entries
        # from the demux map (typically 2: initial_dcid + local_cid).
        for dcid_u64 in self.conn_slots[i].dcids:
            _ = self.conn_dcid_map.pop(dcid_u64)

        var last = len(self.conn_slots) - 1
        if i != last:
            # Swap-and-pop: pop the last slot (taking ownership), bump
            # its generation so any stale `(idx=i, old_gen)` entries left
            # in `conn_dcid_map` fail the generation check in
            # `_find_conn_by_dcid`, then remap the survivor's DCIDs.
            var survivor = self.conn_slots.pop()
            var new_gen = self.next_generation
            self.next_generation += UInt64(1)
            survivor.generation = new_gen
            for dcid_u64 in survivor.dcids:
                self.conn_dcid_map[dcid_u64] = _DcidEntry(i, new_gen)
            self.conn_slots[i] = survivor^
        else:
            _ = self.conn_slots.pop()

    def _submit_egress(mut self) raises:
        """Submit queued egress packets via WatchLoop.send_msg.

        When GSO is available (`_gso_max_segments > 1`), consecutive
        packets sharing the same peer address and payload size are
        packed into a single super-buffer with a SOL_UDP/UDP_SEGMENT
        cmsg. The kernel splits the buffer back into individual
        datagrams at the segment boundary, cutting syscall overhead.

        If a GSO sendmsg fails, segmentation offload is permanently
        downgraded to one datagram per syscall and the unsent packets
        are re-queued for the next flush cycle.

        When the loop's send slab is full, remaining packets stay in
        the backlog for the next flush cycle.

        Payloads are moved, never copied: single datagrams move straight
        into their `Message` (and back out of the `MessageFailed` when
        the slab refuses them); the GSO super-buffer is the one copy by
        construction, and its sources stay in place until it is accepted.
        """
        var n = len(self._egress_backlog)
        if n == 0:
            return

        var unsent = List[EgressPacket]()
        var i = 0

        while i < n:
            # ── GSO grouping ─────────────────────────────────
            if self._gso_max_segments > 1:
                var seg_size = len(self._egress_backlog[i].data)
                var run_end = i + 1
                while (
                    run_end < n
                    and run_end - i < self._gso_max_segments
                    and len(self._egress_backlog[run_end].data) == seg_size
                    and _egress_addrs_eq(
                        self._egress_backlog[run_end].addr,
                        self._egress_backlog[i].addr,
                    )
                ):
                    run_end += 1

                var run_len = run_end - i
                if run_len > 1:
                    # Pack payloads contiguously into one super-buffer.
                    var combined = List[UInt8](
                        capacity=seg_size * run_len,
                    )
                    for j in range(i, run_end):
                        combined.extend(
                            Span(self._egress_backlog[j].data)
                        )

                    var msg = Message(
                        combined^,
                        control_capacity=_SEND_CONTROL_CAPACITY_GSO,
                    )
                    _set_msg_peer_raw(
                        msg, self._egress_backlog[i].addr
                    )
                    try:
                        msg.set_ecn(
                            self._egress_backlog[i].ecn_mark
                        )
                    except:
                        pass
                    try:
                        msg.set_gso_segment_size(UInt16(seg_size))
                    except:
                        pass

                    try:
                        _ = self._loop_ptr[].send_msg(
                            self.udp_socket, msg^
                        )
                        i = run_end
                        continue
                    except:
                        # GSO send failed — permanently downgrade.
                        self._gso_max_segments = 1
                        if self._socket_state is not None:
                            self._socket_state.value().downgrade_send_segments()
                        # Re-queue everything from i onward (moved).
                        for j in range(i, n):
                            unsent.append(self._take_backlog_entry(j))
                        break

            # ── Single-packet path (no GSO cmsg) ────────────
            var data = List[UInt8]()
            var addr = List[UInt8]()
            swap(data, self._egress_backlog[i].data)
            swap(addr, self._egress_backlog[i].addr)
            var conn_idx = self._egress_backlog[i].conn_idx
            var ecn_mark = self._egress_backlog[i].ecn_mark
            var msg = Message(
                data^,
                control_capacity=_SEND_CONTROL_CAPACITY,
            )
            _set_msg_peer_raw(msg, addr)
            try:
                msg.set_ecn(ecn_mark)
            except:
                pass

            try:
                _ = self._loop_ptr[].send_msg(self.udp_socket, msg^)
            except e:
                # Slab full — re-queue this and everything after. The
                # refused message comes back with the failure; its
                # payload is moved back into the packet.
                var back = e^.take_message()
                if back is not None:
                    var refused = back.take()
                    unsent.append(EgressPacket(
                        refused^.take_payload(), addr^, conn_idx, ecn_mark,
                    ))
                for j in range(i + 1, n):
                    unsent.append(self._take_backlog_entry(j))
                break
            i += 1

        self._egress_backlog = unsent^

    def _take_backlog_entry(mut self, j: Int) -> EgressPacket:
        """Move `_egress_backlog[j]` out, leaving an empty husk behind.

        Mojo cannot move out of a list subscript; swapping the two lists
        with fresh empties is the O(1) equivalent. The husk is discarded
        when the backlog is replaced at the end of `_submit_egress`.
        """
        var data = List[UInt8]()
        var addr = List[UInt8]()
        swap(data, self._egress_backlog[j].data)
        swap(addr, self._egress_backlog[j].addr)
        return EgressPacket(
            data^,
            addr^,
            self._egress_backlog[j].conn_idx,
            self._egress_backlog[j].ecn_mark,
        )

    # ── Ingress (DatagramStream drain) ─────────────────────────────

    def _drain_recv_stream(mut self):
        """Take all available datagrams from the DatagramStream and
        buffer them into pending_rx for `_flush_ingress`.

        Each Datagram's `LeasedBuffer` is kept alive in
        `_live_datagrams` so the raw pointers stored in PendingDatagram
        remain valid until `_flush_ingress` completes. Truncated and
        empty datagrams are dropped (their leases are returned
        immediately).

        When the kernel has GRO enabled, one Datagram may contain N
        coalesced UDP segments at a fixed stride. The SOL_UDP/UDP_GRO
        cmsg carries the stride; each segment gets its own DCID
        extraction and PendingDatagram entry, all sharing one buffer
        lease via a refcount in `_dgram_refcounts`.
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

            # Extract ECN codepoint from the control messages (shared
            # across all GRO segments — they come from the same source
            # tuple).
            var ecn_mark = UInt8(0)
            var ecn_opt = hdr.control().ecn()
            if ecn_opt is not None:
                ecn_mark = ecn_opt.value()

            # Get peer address region (shared across segments).
            var name = hdr.name()

            # Check for GRO coalescing: when the kernel coalesced
            # multiple datagrams, a SOL_UDP/UDP_GRO cmsg carries the
            # per-segment stride. Without it, the buffer holds one
            # datagram.
            var gro_opt = hdr.control().gro_segment_size()
            var dgram_idx = len(self._live_datagrams)

            if gro_opt is not None and gro_opt.value() > 0:
                # GRO active — split into N segments at fixed stride.
                var seg_size = gro_opt.value()
                var total_len = len(payload)
                var n_segments = (total_len + seg_size - 1) // seg_size

                self._dgram_refcounts.append(UInt16(n_segments))
                self._live_datagrams.append(dgram_opt^)

                for seg_i in range(n_segments):
                    var offset = seg_i * seg_size
                    var seg_len = min(seg_size, total_len - offset)
                    var seg_ptr = payload.unsafe_ptr().unsafe_offset(offset)

                    # Each GRO segment needs its own DCID extraction
                    # (different connections may be coalesced, though
                    # GRO groups by source tuple so this is unlikely).
                    var seg_span = Span[UInt8, MutUntrackedOrigin](
                        unsafe_ptr=seg_ptr, length=seg_len,
                    )
                    var dcid: DcidBuf
                    try:
                        dcid = extract_dcid(seg_span)
                    except:
                        # Undecodable segment — release its share of
                        # the refcount so the buffer can still be freed.
                        self._dgram_refcounts[dgram_idx] -= UInt16(1)
                        continue

                    self.pending_rx.append(
                        PendingDatagram(
                            payload_ptr=seg_ptr,
                            payload_len=seg_len,
                            name_ptr=name.unsafe_ptr(),
                            name_len=len(name),
                            dcid=dcid^,
                            ecn_mark=ecn_mark,
                            dgram_idx=dgram_idx,
                        )
                    )
            else:
                # Non-GRO: single datagram, refcount 1.
                var dcid: DcidBuf
                try:
                    dcid = extract_dcid(payload)
                except:
                    continue

                self._dgram_refcounts.append(UInt16(1))

                self.pending_rx.append(
                    PendingDatagram(
                        payload_ptr=payload.unsafe_ptr(),
                        payload_len=len(payload),
                        name_ptr=name.unsafe_ptr(),
                        name_len=len(name),
                        dcid=dcid^,
                        ecn_mark=ecn_mark,
                        dgram_idx=dgram_idx,
                    )
                )

                # Keep the lease alive until _flush_ingress completes.
                self._live_datagrams.append(dgram_opt^)

    # ── Per-connection construction ──────────────────────────────

    def _construct_conn_handler(
        mut self, dcid: Span[UInt8, _], now: UInt64
    ) raises -> Pointer[H3HandlerServer[Self.H], MutUntrackedOrigin]:
        """Build a fresh per-connection `H3HandlerServer[H]` on the heap.

        Extracted from `_flush_impl`'s new-connection branch so tests can
        exercise the real wiring without standing up an io_uring loop. The
        body mirrors the inline construction exactly, with one difference:
        the accept-profile pointer is threaded into BOTH the QUIC layer and
        the H3 adapter so every counter family stays live in the library
        server (the inline code never did this, leaving them dead).

        # Both pointers wired unconditionally

        `UnsafePointer(to=self.profile)` is passed to `QuicConnection.server`
        and `H3HandlerServer`'s `profile_ptr` kwarg with no compile-time or
        runtime guard. This is cheap by construction:

          * The QUIC-side record sites are `comptime if PROFILE_ACCEPT`
            gated, so a default (`PROFILE_ACCEPT=False`) build dead-strips
            every `record_*` call and pays only for one stored pointer.
          * The `zero_rtt_http_filter_*` record sites are runtime-gated by
            design (they only fire on a 0-RTT-arrived request when the
            policy is on), so wiring the pointer is the only thing that
            lets those counters reach `self.profile` at all.

        # Pointer stability

        `UnsafePointer(to=self.profile)` is only valid while `self` stays
        put. The server must be heap-allocated with `wire_context()` called
        BEFORE any connection exists, so the profile's address is fixed by
        the time the first handler is built; `H3UdpServer` must not be moved
        while handlers hold this pointer. This mirrors the existing
        `_early_data_store` / `_early_data_filter` pointer discipline.

        Args:
            dcid: The client's Initial DCID span (used as both `orig_dcid`
                and, copied, `client_dcid` for the dual-DCID server start).
            now: Current monotonic time in microseconds.

        Returns:
            A heap-allocated, move-initialized `H3HandlerServer[Self.H]`
            pointer. The caller owns it and is responsible for
            `destroy_pointee()` + `free()` (or transferring ownership into
            a `ConnSlot`).

        Raises:
            Propagated from `QuicConnection.server` (TLS handle alloc, key
            derivation) or the `H3HandlerServer` ctor. `_flush_impl` catches
            these per-datagram and releases the inbound buffer rather than
            aborting the whole flush.
        """
        var dcid_copy = List[UInt8](capacity=len(dcid))
        for i in range(len(dcid)):
            dcid_copy.append(dcid[i])

        var quic = QuicConnection.server(
            self._tls.shared(),
            self.server_config,
            self.transport_params.copy(),
            dcid,
            Span(dcid_copy),
            now,
            # The connection stores this alias for its whole lifetime, which
            # outlives what the checker can see of `self.profile`; the field is
            # untracked, so the hand-off is explicit rather than implied.
            Pointer(to=self.profile).unsafe_origin_cast[MutUntrackedOrigin](),
        )

        # Per-conn StreamHandler — produced by the user-supplied factory.
        var handler = self.make_handler()

        # Promote QuicServerConfig._early_data_filter into a raw pointer the
        # H3 adapter dispatches via on `_on_request`. Mirrors how
        # `QuicConnection.server` promotes the `_early_data_store`
        # reference — the pointer is valid for the connection's lifetime
        # because `self.server_config` outlives every connection here.
        # `rebind` lifts the inferred config-bound origin to `MutUntrackedOrigin`
        # so the pointer can be stored alongside the existing
        # `_early_data_store_ptr` shape.
        var early_data_filter_ptr_opt = Optional[
            Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
        ](None)
        if self.server_config._early_data_filter is not None:
            var filter_ptr = rebind[
                Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
            ](Pointer(to=self.server_config._early_data_filter.value()))
            early_data_filter_ptr_opt = Optional[
                Pointer[IdempotentOnlyFilter, MutUntrackedOrigin]
            ](filter_ptr)

        # Thread the policy's predicate-fn (if any) into the per-connection
        # adapter ctor. The fn-pointer is Optional[EarlyDataPredicateFn] —
        # trivially copyable in Mojo 1.0.0 — so no pointer-lifetime
        # threading is needed (unlike the IdempotentOnlyFilter struct above).
        var predicate_fn_opt = self.server_config._early_data_predicate_fn

        var h3 = H3HandlerServer[Self.H](
            quic=quic^,
            handler=handler^,
            profile_ptr=Pointer(to=self.profile).unsafe_origin_cast[
                MutUntrackedOrigin
            ](),
            early_data_filter_ptr=early_data_filter_ptr_opt,
            predicate_fn=predicate_fn_opt,
        )

        var h3_ptr = _heap_alloc[H3HandlerServer[Self.H]](1)
        h3_ptr.unsafe_write(h3^)
        return h3_ptr

    # ── Ingress flush ───────────────────────────────────────────

    def _flush_ingress(mut self) raises:
        """Process all buffered datagrams through QUIC/H3.

        Drains `pending_rx`, routes each packet by DCID, creates new
        connections for Initial packets, feeds datagrams into the QUIC
        stack, and queues egress into `_egress_backlog`. Connections
        that reached CLOSED while being fed are reaped once the loop is
        over (never inside it: `pending_rx` entries resolve their slot
        through the DCID map, which swap-and-pop would invalidate).
        Buffer leases are released by the caller (flush) after this
        method returns.
        """
        var now = self._now()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()

            # DCID-keyed demux. pd.dcid extracted during _drain_recv_stream.
            var dcid_u64 = dcid_to_u64(pd.dcid.as_span())
            var conn_idx = self._find_conn_by_dcid(dcid_u64)

            # RFC 9000 §12.4: only long-header Initial packets create new
            # conns. All other DCID-misses are dropped silently.
            if conn_idx < 0:
                var first_byte_span = Span[UInt8, MutUntrackedOrigin](
                    unsafe_ptr=pd.payload_ptr, length=pd.payload_len)
                if not is_long_header_initial(first_byte_span):
                    self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)
                    continue

            if conn_idx < 0:
                # New conn — drive QuicConnection.server() and wrap in
                # H3HandlerServer via the extracted constructor (which wires
                # the accept-profile pointer through both layers).
                var h3_ptr: Pointer[H3HandlerServer[Self.H], MutUntrackedOrigin]
                try:
                    h3_ptr = self._construct_conn_handler(pd.dcid.as_span(), now)
                except e:
                    print("H3UdpServer: conn construction error:", e)
                    self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)
                    continue

                # B-permissive dual-DCID: both the client's Initial DCID
                # (random ICID) and the server's chosen SCID (local_cid)
                # map to the same conn_idx so the ICID→SCID transition
                # is transparent during the handshake.
                debug_assert(
                    len(h3_ptr[]._h3._quic.initial_dcid) == 8,
                    "initial_dcid != 8 bytes",
                )
                debug_assert(
                    len(h3_ptr[]._h3._quic.local_cid) == 8,
                    "local_cid != 8 bytes",
                )

                var icid_u64 = dcid_to_u64(Span(h3_ptr[]._h3._quic.initial_dcid))
                var lcid_u64 = dcid_to_u64(Span(h3_ptr[]._h3._quic.local_cid))

                # Build peer address from the delivery header name region
                # for sendmsg routing. Stored as a raw sockaddr blob (16 or
                # 28 bytes) — _set_msg_peer_raw() parses this layout.
                var addr = List[UInt8](capacity=pd.name_len)
                for j in range(pd.name_len):
                    addr.append(pd.name_ptr[unsafe_offset=j])

                conn_idx = len(self.conn_slots)
                var gen = self.next_generation
                self.next_generation += UInt64(1)

                self.conn_dcid_map[icid_u64] = _DcidEntry(conn_idx, gen)
                self.conn_dcid_map[lcid_u64] = _DcidEntry(conn_idx, gen)

                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)

                self.conn_slots.append(
                    ConnSlot[Self.H](h3_ptr, addr^, dcids^, gen)
                )
                # Provisional cache so no live slot ever holds the sentinel;
                # this iteration's `_drain_and_send` replaces it.
                self.conn_slots[conn_idx].next_deadline_us = now
                self.conn_slots[conn_idx].deadline_refreshed_at_us = now

                # Seed `peer_addr` exactly once at conn creation so
                # the sentinel zero PathKey is replaced. From this point
                # forward, `peer_addr` only mutates inside
                # `on_path_response_received` after a verified match.
                var bootstrap_key = _sockaddr_to_path_key(
                    pd.name_ptr, 0, pd.name_len
                )
                self.conn_slots[conn_idx].h3[].bootstrap_peer_addr(
                    bootstrap_key^
                )

            # Build a structured PathKey for path-validation bookkeeping
            # — used for address-change detection, anti-amp
            # accounting, and the per-datagram RECV-addr cursor
            # consumed by `_dispatch_frame` when a PATH_RESPONSE
            # arrives in this same datagram.
            var from_path = _sockaddr_to_path_key(
                pd.name_ptr, 0, pd.name_len
            )

            # Detect path change vs the validated peer_addr.
            # On migration-disabled, close_transport(0x0A) — the
            # connection-close frame goes out in the next flush. On
            # migration-allowed mismatch, kick off PATH_CHALLENGE. Always
            # credits per-path bytes_received for the unvalidated case.
            try:
                self.conn_slots[conn_idx].h3[].on_ingress_from(
                    PathKey(copy=from_path), pd.payload_len, now
                )
            except e:
                print("H3UdpServer: on_ingress_from error:", e)

            # Stamp the receive-addr cursor so the inner
            # _dispatch_frame can match an incoming PATH_RESPONSE against
            # the address that carried it. Set BEFORE feed_datagram so
            # the coalesced packets in this datagram all see the same
            # cursor.
            self.conn_slots[conn_idx].h3[].set_current_recv_addr(
                PathKey(copy=from_path)
            )

            # Feed datagram into the QuicConnection with ECN mark.
            try:
                self.conn_slots[conn_idx].h3[].feed_datagram_from_buffer(
                    pd.payload_ptr, pd.payload_len, now, pd.ecn_mark
                )
            except e:
                print("H3UdpServer: feed_datagram error:", e)

            # Refresh the raw sockaddr blob used by sendmsg routing. The
            # `conn_slots[i].addr` blob targets the most-recent observed
            # source addr regardless of validation state — sendmsg uses
            # it as the destination of every outbound datagram. Path
            # validation gates whether OUTBOUND traffic is allowed
            # (anti-amp + close on migration-disabled); it does NOT
            # influence where the datagram is delivered (the peer
            # decides where to listen). Two exceptions: the blob is only
            # rebuilt when the bytes differ, and it is frozen once the
            # connection is closing (checked AFTER the feed, so the very
            # datagram that triggers the close cannot move it): path
            # validation is suppressed in those states, so a spoofed
            # source with a valid DCID would otherwise redirect the
            # reflected CONNECTION_CLOSE to an unvalidated address.
            if not self.conn_slots[conn_idx].h3[].is_closing_or_draining():
                if not _sockaddr_matches(
                    self.conn_slots[conn_idx].addr, pd.name_ptr, pd.name_len
                ):
                    var addr_update = List[UInt8](capacity=pd.name_len)
                    for j in range(pd.name_len):
                        addr_update.append(pd.name_ptr[unsafe_offset=j])
                    self.conn_slots[conn_idx].addr = addr_update^

            # Egress — drain QUIC + H3 packets and queue sendmsg submits.
            try:
                self._drain_and_send(conn_idx, now)
            except e:
                print("H3UdpServer: drain_and_send error:", e)

            # Release this segment's share of the buffer refcount.
            self._dgram_refcounts[pd.dgram_idx] -= UInt16(1)

        self.pending_rx.clear()

        # Reap connections the ingress drove to CLOSED, now that no
        # `pending_rx` entry can resolve to a moved slot.
        self._reap_closed()

    # ── Egress ───────────────────────────────────────────────────

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain a connection's datagrams into the egress backlog, then refresh its cached deadline.

        RFC 9000 §8.1 anti-amplification: for each datagram the server
        intends to send to the current peer addr, gate via
        `can_send_to(target, n)`. If the peer's address has a pending
        PATH_CHALLENGE, the per-path 3x budget caps the bytes we may
        emit until validation completes. Datagrams refused by the gate
        are dropped; they'll be regenerated on the next flush after
        more bytes arrive from the peer (or after validation lifts the
        gate entirely). On a successful queue we credit the per-path
        bytes_sent so subsequent emissions stay within budget.
        """
        try:
            var datagrams = self.conn_slots[conn_idx].h3[].drain_datagrams(
                now
            )

            # Resolve the structured peer key once per flush. The server
            # tracks the latest sockaddr blob in `conn_slots[i].addr`, which
            # was just refreshed in `_flush_ingress` to match the source addr
            # of the datagram that triggered this flush — i.e. the same
            # address sendmsg will route to.
            var target_key = _sockaddr_to_path_key(
                self.conn_slots[conn_idx].addr.unsafe_ptr(),
                0,
                len(self.conn_slots[conn_idx].addr),
            )

            # ECN mark from the connection's probing/capability state.
            var ecn = self.conn_slots[conn_idx].h3[]._h3._quic.ecn_mark()

            for i in range(len(datagrams)):
                # Move the payload out of the drained list (swap with an
                # empty husk) rather than copying 1200 bytes per datagram.
                var pkt = List[UInt8]()
                swap(pkt, datagrams[i])
                if len(pkt) == 0:
                    continue

                # Per-path anti-amp gate. No-op when `target_key` has
                # no pending challenge (validated path → returns True). The
                # validator's `can_send_bytes` includes the QUIC header +
                # AEAD ciphertext (i.e. the full UDP payload), matching RFC
                # 9000 section 8.1's measurement convention.
                if not self.conn_slots[conn_idx].h3[].can_send_to(
                    target_key, len(pkt)
                ):
                    # Budget exhausted on the unvalidated path. Drop the
                    # datagram; loss recovery will regenerate the contents
                    # once the peer credits more bytes or validation lifts
                    # the gate. NOT a fatal error.
                    continue

                var pkt_len = len(pkt)
                var addr_copy = List[UInt8](
                    copy=self.conn_slots[conn_idx].addr
                )

                self._egress_backlog.append(
                    EgressPacket(pkt^, addr_copy^, conn_idx, ecn)
                )

                # Credit per-path bytes_sent. No-op on validated paths.
                self.conn_slots[conn_idx].h3[].record_send_to(
                    target_key, pkt_len
                )
        finally:
            # A raise above (drain, anti-amp accounting) still leaves a
            # fresh cache: the PTO armed by the dropped datagrams must be
            # visible to the timer before the caller's `except` runs.
            self._refresh_deadline(conn_idx, now)

    # ── Out-of-band response injection (cross-transport wake) ─────

    def has_stream(self, conn_id: UInt64, sid: Int) -> Bool:
        """Return True if `(conn_id, sid)` names an open stream.

        `conn_id` is the stable per-connection identity surfaced to the
        handler via `caps.conn_id` (the server SCID as a u64). It is
        resolved through the generation-guarded DCID demux map, so a
        `conn_id` whose connection was torn down (and whose slot index was
        reused by swap-and-pop) reports False rather than aliasing onto an
        unrelated connection."""
        var conn_idx = self._find_conn_by_dcid(conn_id)
        if conn_idx < 0:
            return False
        return self.conn_slots[conn_idx].h3[].has_stream(sid)

    def inject_response(
        mut self,
        conn_id: UInt64,
        sid: Int,
        var status: StatusCode,
        var headers: Headers,
        var body: List[UInt8],
        end: Bool,
    ) raises:
        """Write a response into an open H3 stream from OUTSIDE the inbound
        datagram path, then stage its egress for the next flush().

        This is the public hook a reverse-proxy driver calls when a backend
        round-trip — running on a different transport (TCP) and waking on a
        different Completion — produces the response (or a 502 on connect
        failure). It routes to the owning connection's
        `H3HandlerServer.inject_response`, which stages status/headers/body
        into the stream's `ResponseWriter`, then drains datagrams into
        `_inject_egress` for the next flush() cycle.

        `conn_id` is resolved via the generation-guarded DCID demux map
        (the server SCID surfaced as `caps.conn_id`). A stale or
        torn-down `conn_id`, or an `sid` that is no longer open, is a clean
        no-op — the client simply never receives a late response for a
        connection or stream that has already gone away. This makes
        cross-connection misdelivery structurally impossible: the response
        can only reach the exact connection that issued the request.

        One-tick latency is acceptable for cross-transport responses.

        Args:
            conn_id: Stable connection identity from `caps.conn_id`.
            sid: H3 request stream id from `caps.stream_id`.
            status: Response status code.
            headers: Response headers (hop-by-hop already stripped).
            body: Full response body bytes.
            end: When True, terminates the response (FIN).
        """
        var conn_idx = self._find_conn_by_dcid(conn_id)
        if conn_idx < 0:
            return
        var now = self._now()
        try:
            self.conn_slots[conn_idx].h3[].inject_response(
                sid, status^, headers^, body^, end
            )
            var datagrams = self.conn_slots[conn_idx].h3[].drain_datagrams(
                now
            )
            var ecn = self.conn_slots[conn_idx].h3[]._h3._quic.ecn_mark()
            for i in range(len(datagrams)):
                var pkt = List[UInt8]()
                swap(pkt, datagrams[i])
                if len(pkt) == 0:
                    continue
                var addr_copy = List[UInt8](
                    copy=self.conn_slots[conn_idx].addr
                )
                self._inject_egress.append(
                    EgressPacket(pkt^, addr_copy^, conn_idx, ecn)
                )
        finally:
            # New sendable data or a PTO armed by the drain must reach the
            # timer even if staging or draining raised midway. This also
            # runs when `h3[].inject_response` raised before mutating
            # anything: one spurious refresh, accepted over a second
            # try/except just to skip it.
            self._refresh_deadline(conn_idx, now)


