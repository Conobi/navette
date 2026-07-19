"""H3UdpServer — generic UDP + QUIC + H3 server (proactor model).

Drives multiple H3 connections off a single UDP socket using
per-operation Completions with batch-then-flush dispatch.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H3UdpServer[H: StreamHandler]            io_uring + IoUringDriver
    │                                        │
    │  _on_recvmsg (Completion callback) ──┘   (CQE)
    │  ├─ buffers packet into pending_rx
    │  SendSlab._on_sendmsg_complete ──────┘
    │  ├─ releases slab slot
    │  _on_timeout (Completion callback) ──┘
    │  ├─ sets housekeeping flag
    │
    │  flush(driver) ──── (after each run_once/tick)
    │  └─ _flush_ingress: demux pending_rx by DCID, route to
    │                     H3HandlerServer[H] per conn, drain egress
    │  └─ _submit_egress: submit sendmsg SQEs via slab pool
    │  └─ recycle BufRing buffers, re-arm multishot/timeout
    │
    └─ conn_slots[i]: ConnSlot[H] (h3 ptr + addr + dcids + generation)
         └─ owns a QuicConnection + an H instance
```

# Per-conn handler factory

`H` is the per-request handler trait (`StreamHandler`). Each new
QUIC connection allocates a fresh `H3HandlerServer[H]` on the heap,
which owns its own `H`. The library makes a new `H` for each conn
via `H()` (default constructor) — implement `H.__init__(out self)`
with whatever setup your handler needs. Per-conn state lives on the
handler instance; shared state lives behind a pointer the handler
holds.

# Lifetime / ownership

The `OwnedHandle` wrapping the UDP fd is moved into the server;
RAII keeps it alive for the entire io_uring loop. The `TlsBackend`
and `QuicServerConfig` are moved into the server and destroyed
after all connections.

# Integration

After construction, the caller must:
  1. Heap-allocate the server (pointer stability).
  2. Call `wire_context()` to set Completion context pointers.
  3. Call `start(driver)` to register BufRing and submit initial ops.
  4. In the run loop: `driver.tick(wait=True)` then `server.flush(driver)`.
"""

from std.collections import Optional
from std.collections.dict import Dict
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.handle import RawHandle, OwnedHandle
from boucle.proactor.completion import Completion
from boucle.proactor.bufring import BufRing
from boucle.drivers.io_uring import IoUringDriver
from boucle._sys.linux.raw import (
    msghdr,
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_BUFFER_SHIFT,
)
from boucle._sys.linux.raw.ctypes import c_void

from navette.tls.lib import TlsBackend
from navette.tls.config import QuicServerConfig
from navette.tls.early_data_filter import EarlyDataPredicateFn, IdempotentOnlyFilter
from navette.http.handler import StreamHandler
from navette.http.headers import Headers
from navette.http.status import StatusCode
from navette.h3.h3_handler_server import H3HandlerServer
from navette.quic.cid import dcid_to_u64
from navette.quic.connection import QuicConnection
from navette.quic.packet import is_long_header_initial, extract_dcid
from navette.quic.path_validator import PathKey
from navette.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us
from navette.quic.trans_param import TransportParams
from navette.h3.send_slab import SendSlab, SendSlabPool
from navette.util.null_ptr import null_ptr


# ── Wire constants ────────────────────────────────────────────────────────────


comptime _MSGHDR_SIZE: Int = 56
comptime _IOVEC_SIZE: Int = 16
comptime _ADDR_SIZE: Int = 28        # sockaddr_in6
comptime _TIMESPEC_SIZE: Int = 16    # __kernel_timespec
comptime _RECVMSG_OUT_HDR_SIZE: Int = 16

# Provided-buffer ring sizing for multishot recvmsg.
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600
comptime PBUF_GROUP_ID: UInt16 = 0

# Egress backpressure: when backlog exceeds capacity * multiplier,
# BufRing recycling is delayed to throttle ingress at the kernel level.
comptime _BACKLOG_CAP_MULTIPLIER: Int = 2


@always_inline
def _read_u32_le(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> UInt32:
    return (
        UInt32(ptr[0])
        | (UInt32(ptr[1]) << 8)
        | (UInt32(ptr[2]) << 16)
        | (UInt32(ptr[3]) << 24)
    )


def _sockaddr_to_path_key(
    buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
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
        Int(buf_ptr[addr_offset]) | (Int(buf_ptr[addr_offset + 1]) << 8)
    )
    # Port is network-order (big-endian).
    var port_hi = UInt16(buf_ptr[addr_offset + 2])
    var port_lo = UInt16(buf_ptr[addr_offset + 3])
    var port = (port_hi << 8) | port_lo

    if family == Int32(2):
        # AF_INET — 4-octet address at offset+4.
        if addr_len < 8:
            return PathKey.zero()
        return PathKey.from_v4(
            buf_ptr[addr_offset + 4],
            buf_ptr[addr_offset + 5],
            buf_ptr[addr_offset + 6],
            buf_ptr[addr_offset + 7],
            port,
        )
    elif family == Int32(10):
        # AF_INET6 — 16-octet address at offset+8.
        if addr_len < 24:
            return PathKey.zero()
        var bytes = List[UInt8](capacity=16)
        for i in range(16):
            bytes.append(buf_ptr[addr_offset + 8 + i])
        return PathKey(Int32(10), bytes^, port)
    else:
        return PathKey.zero()


# ── Pending datagram (ingress queue) ──────────────────────────────────────────


struct PendingDatagram(Copyable, Movable):
    """A single inbound UDP datagram parked between recvmsg CQE and flush.

    `buf_id` is the provided-buffer-ring slot the kernel picked. The
    payload lives at `payload_ptr` (an offset into `buf_ptr`); the peer
    sockaddr lives at `buf_ptr[addr_offset .. addr_offset + addr_len]`.
    `dcid` is the QUIC destination connection ID extracted from the
    payload's first ~16 bytes (long-header or short-header).
    """
    var buf_id: UInt16
    var buf_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_ptr: UnsafePointer[UInt8, MutAnyOrigin]
    var payload_len: Int
    var addr_offset: Int
    var addr_len: Int
    var dcid: List[UInt8]

    def __init__(out self, buf_id: UInt16,
                 buf_ptr: UnsafePointer[UInt8, MutAnyOrigin],
                 payload_ptr: UnsafePointer[UInt8, MutAnyOrigin],
                 payload_len: Int, addr_offset: Int, addr_len: Int,
                 var dcid: List[UInt8]):
        self.buf_id = buf_id
        self.buf_ptr = buf_ptr
        self.payload_ptr = payload_ptr
        self.payload_len = payload_len
        self.addr_offset = addr_offset
        self.addr_len = addr_len
        self.dcid = dcid^

    def __init__(out self, *, other: Self):
        self.buf_id = other.buf_id
        self.buf_ptr = other.buf_ptr
        self.payload_ptr = other.payload_ptr
        self.payload_len = other.payload_len
        self.addr_offset = other.addr_offset
        self.addr_len = other.addr_len
        self.dcid = List[UInt8](copy=other.dcid)

    def __init__(out self, *, deinit take: Self):
        self.buf_id = take.buf_id
        self.buf_ptr = take.buf_ptr
        self.payload_ptr = take.payload_ptr
        self.payload_len = take.payload_len
        self.addr_offset = take.addr_offset
        self.addr_len = take.addr_len
        self.dcid = take.dcid^


# ── Egress packet (queued for flush submission) ─────────────────────────────


struct EgressPacket(Movable):
    """A queued egress datagram — payload + destination address.

    Buffered during CQE callbacks (timeout drains) and injected
    cross-transport responses. Submitted via SendSlabPool in
    flush()'s _submit_egress phase.
    """

    var data: List[UInt8]
    var addr: List[UInt8]
    var conn_idx: Int

    def __init__(
        out self,
        var data: List[UInt8],
        var addr: List[UInt8],
        conn_idx: Int,
    ):
        """Construct an egress packet with payload, peer address, and
        originating connection index.

        Args:
            data: Packet payload bytes (moved in).
            addr: Peer sockaddr bytes for sendmsg routing (moved in).
            conn_idx: Index into conn_slots for bookkeeping.
        """
        self.data = data^
        self.addr = addr^
        self.conn_idx = conn_idx

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.data = take.data^
        self.addr = take.addr^
        self.conn_idx = take.conn_idx


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

    def __init__(out self, *, other: Self):
        self.idx = other.idx
        self.generation = other.generation

    def __init__(out self, *, deinit take: Self):
        self.idx = take.idx
        self.generation = take.generation


struct ConnSlot[H: StreamHandler](Copyable, Movable):
    """One QUIC/H3 connection's parallel-list-collapsing record.

    Holds the `H3HandlerServer[H]` pointer, peer sockaddr bytes, every
    DCID this connection responds to (typically `[initial_dcid, local_cid]`),
    and a generation counter. Generation increments every time the slot
    is overwritten by a swap-and-pop survivor, so stale demux entries
    can be detected at lookup time.

    `Copyable` is required by `List[ConnSlot[H]]` storage; aliasing
    `h3` across copies matches the prior `List[UnsafePointer[...]]`
    semantics (the underlying pointer was already trivially copied
    when the list grew).
    """
    var h3: UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin]
    var addr: List[UInt8]
    var dcids: List[UInt64]
    var generation: UInt64

    def __init__(
        out self,
        h3: UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin],
        var addr: List[UInt8],
        var dcids: List[UInt64],
        generation: UInt64,
    ):
        self.h3 = h3
        self.addr = addr^
        self.dcids = dcids^
        self.generation = generation

    def __init__(out self, *, other: Self):
        self.h3 = other.h3
        self.addr = List[UInt8](copy=other.addr)
        self.dcids = List[UInt64](copy=other.dcids)
        self.generation = other.generation

    def __init__(out self, *, deinit take: Self):
        self.h3 = take.h3
        self.addr = take.addr^
        self.dcids = take.dcids^
        self.generation = take.generation


# ── H3UdpServer ──────────────────────────────────────────────────────────────


struct H3UdpServer[H: StreamHandler](Movable):
    """Generic UDP + QUIC + H3 server (proactor model).

    Parameterised on `H: StreamHandler`. Each accepted connection
    allocates a heap-owned `H3HandlerServer[H]` which owns its own
    `H` instance plus the underlying `QuicConnection` + `H3Connection`.

    Uses per-operation Completions with batch-then-flush dispatch:
    CQE callbacks buffer work (pending_rx for recvmsg, slab release
    for sendmsg). An explicit `flush(driver)` method processes
    buffered packets through QUIC, submits egress sendmsg SQEs,
    recycles BufRing buffers, and re-arms multishot if ended.

    `make_handler` is a user-provided factory function called once per
    new QUIC connection. The factory owns construction policy — share
    state via captured pointers (Mojo doesn't have closures yet, so
    factories typically read from a module-level singleton or take
    state via the surrounding context the user threads through).
    """

    # Listening UDP fd, owned via OwnedHandle. RAII keeps the fd alive
    # across the entire io_uring loop's lifetime (closes on server
    # destruction). Use `self.udp_handle.raw()` wherever a RawHandle is
    # needed for io_uring submission.
    var udp_handle: OwnedHandle

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

    # Ingress staging. pending_rx fills from _on_recvmsg callback (one
    # per recvmsg CQE); _flush_ingress drains it in flush().
    var pending_rx: List[PendingDatagram]

    # buf-ring lifecycle ledger. _inflight_bufs[i] == True iff buf-id i
    # is currently userspace-owned (between recvmsg CQE and the matching
    # _bufs_to_recycle.append). Under ASSERT=all, _release_buf catches
    # double-returns (would silently corrupt kernel state under load).
    var _inflight_bufs: List[Bool]

    # Buffer IDs consumed during CQE processing, recycled in flush().
    var _bufs_to_recycle: List[UInt16]

    # io_uring multishot recvmsg infrastructure.
    var _pbuf_pool: UnsafePointer[UInt8, MutAnyOrigin]
    var _msghdr_template: UnsafePointer[UInt8, MutAnyOrigin]
    var _multishot_active: Bool

    # Owned Completions for recvmsg and timeout.
    var _recvmsg_cmp: Completion
    var _timeout_cmp: Completion

    # Sendmsg slab pool (owns per-slot Completions).
    var _send_pool: SendSlabPool

    # BufRing for zero-SQE buffer recycling. Initialized in start().
    var _bufring: BufRing

    # Egress backpressure — packets that couldn't be submitted
    # (slab exhausted or SQ full).
    var _egress_backlog: List[EgressPacket]

    # Cross-transport injection staging (from inject_response).
    var _inject_egress: List[EgressPacket]

    # Multishot re-arm flag (set by recvmsg callback when F_MORE clears).
    var _needs_multishot_rearm: Bool

    # Periodic timeout for QUIC loss detection / idle close.
    var _timeout_ts: UnsafePointer[UInt8, MutAnyOrigin]

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
        `start(driver)` before any io_uring tick.

        Args:
            udp_handle: Owned UDP socket handle (moved in).
            tls: TLS backend instance (moved in).
            server_config: QUIC server TLS config (moved in).
            transport_params: Transport parameters for new connections.
            make_handler: Factory function producing one H per connection.
        """
        self.udp_handle = udp_handle^
        self.transport_params = transport_params^
        self.make_handler = make_handler

        self.conn_slots = List[ConnSlot[Self.H]]()
        self.conn_dcid_map = Dict[UInt64, _DcidEntry]()
        self.next_generation = UInt64(0)

        self._tls = tls^
        self.server_config = server_config^

        self.pending_rx = List[PendingDatagram]()

        self._inflight_bufs = List[Bool]()
        for _ in range(PBUF_COUNT):
            self._inflight_bufs.append(False)

        self._bufs_to_recycle = List[UInt16]()

        self._pbuf_pool = _heap_alloc[UInt8](PBUF_COUNT * PBUF_SIZE).as_unsafe_any_origin()
        for i in range(PBUF_COUNT * PBUF_SIZE):
            self._pbuf_pool[i] = 0

        self._msghdr_template = _heap_alloc[UInt8](_MSGHDR_SIZE).as_unsafe_any_origin()
        for i in range(_MSGHDR_SIZE):
            self._msghdr_template[i] = 0
        # msg_namelen at offset 8 = sizeof(sockaddr_in6). The kernel populates
        # the peer address in the provided buffer (controlled via iov_len=0
        # below — recvmsg-multishot ignores iov when buf-ring is in use).
        self._msghdr_template[8] = 28
        self._multishot_active = False

        # Completions — context set by wire_context() after heap allocation.
        self._recvmsg_cmp = Completion(
            invoke=_on_recvmsg[Self.H],
            context=null_ptr[NoneType, MutAnyOrigin](),
        )
        self._timeout_cmp = Completion(
            invoke=_on_timeout[Self.H],
            context=null_ptr[NoneType, MutAnyOrigin](),
        )

        # Slab pool — 256 slots, PBUF_SIZE bytes max per packet.
        self._send_pool = SendSlabPool(capacity=256, buf_size=PBUF_SIZE)

        # BufRing — initialized in start() via driver.register_buf_ring().
        self._bufring = BufRing()

        self._egress_backlog = List[EgressPacket]()
        self._inject_egress = List[EgressPacket]()
        self._needs_multishot_rearm = False

        # 50ms periodic timeout — tv_sec=0, tv_nsec=50_000_000 LE.
        self._timeout_ts = _heap_alloc[UInt8](_TIMESPEC_SIZE).as_unsafe_any_origin()
        for i in range(_TIMESPEC_SIZE):
            self._timeout_ts[i] = 0
        self._timeout_ts[8] = 0x80
        self._timeout_ts[9] = 0xF0
        self._timeout_ts[10] = 0xFA
        self._timeout_ts[11] = 0x02

        self.profile = AcceptProfile()

    def __init__(out self, *, deinit take: Self):
        """Move constructor."""
        self.udp_handle = take.udp_handle^
        self.transport_params = take.transport_params^
        self.make_handler = take.make_handler
        self.conn_slots = take.conn_slots^
        self.conn_dcid_map = take.conn_dcid_map^
        self.next_generation = take.next_generation
        self._tls = take._tls^
        self.server_config = take.server_config^
        self.pending_rx = take.pending_rx^
        self._inflight_bufs = take._inflight_bufs^
        self._bufs_to_recycle = take._bufs_to_recycle^
        self._pbuf_pool = take._pbuf_pool
        self._msghdr_template = take._msghdr_template
        self._multishot_active = take._multishot_active
        self._recvmsg_cmp = take._recvmsg_cmp^
        self._timeout_cmp = take._timeout_cmp^
        self._send_pool = take._send_pool^
        self._bufring = take._bufring^
        self._egress_backlog = take._egress_backlog^
        self._inject_egress = take._inject_egress^
        self._needs_multishot_rearm = take._needs_multishot_rearm
        self._timeout_ts = take._timeout_ts
        self.profile = take.profile^

    def __del__(deinit self):
        """Free heap allocations owned by the server.

        Walks any live `conn_slots`, destroying their pointees before
        freeing the per-slot heap blocks. Tears down the send slab pool.
        `_pbuf_pool`, `_msghdr_template`, and `_timeout_ts` are raw byte
        buffers — no pointee destructor. The BufRing is cleaned up by
        its own destructor. On clean teardown conn_slots is typically
        empty; the walk defends against drop-mid-flight.
        """
        for i in range(len(self.conn_slots)):
            var ptr = self.conn_slots[i].h3
            ptr.destroy_pointee()
            ptr.free()
        self._send_pool.teardown()
        self._pbuf_pool.free()
        self._msghdr_template.free()
        self._timeout_ts.free()

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

    # ── Buf-ring lifecycle ledger ────────────────────────────────

    def _acquire_buf(mut self, buf_id: UInt16):
        """Mark `buf_id` as userspace-owned after the kernel hands it
        back via a recvmsg CQE. Aborts under ASSERT=all if the kernel
        somehow returned a buf-id that we still consider in-flight —
        that would mean either a kernel buf-ring bug or a missed
        `_release_buf` on a prior CQE."""
        debug_assert(
            not self._inflight_bufs[Int(buf_id)],
            "buf-ring: kernel handed back buf_id already userspace-owned",
        )
        self._inflight_bufs[Int(buf_id)] = True

    def _release_buf(mut self, buf_id: UInt16):
        """Queue `buf_id` for BufRing recycling in flush(). Aborts
        under ASSERT=all if buf_id is not currently userspace-owned —
        catches double-returns (would corrupt the buf-ring) and stray
        returns of never-acquired buf-ids."""
        debug_assert(
            self._inflight_bufs[Int(buf_id)],
            "buf-ring: releasing buf_id that is not userspace-owned",
        )
        self._inflight_bufs[Int(buf_id)] = False
        self._bufs_to_recycle.append(buf_id)

    # ── Lifecycle — wire_context / start / flush ────────────────

    def wire_context(mut self):
        """Set Completion context pointers to this server's heap address.

        Must be called after the H3UdpServer is at its final heap address
        (pointer stability guaranteed) and before any SQE submission.
        Also wires the SendSlabPool's per-slot backpointers.
        """
        var self_ctx = UnsafePointer[NoneType, MutAnyOrigin](
            unsafe_from_address=Int(UnsafePointer(to=self))
        )
        self._recvmsg_cmp.context = self_ctx
        self._timeout_cmp.context = self_ctx
        self._send_pool.wire_completions()

    def start(mut self, mut driver: IoUringDriver) raises:
        """Submit initial operations onto the driver.

        Must be called after wire_context() and before the first tick.
        Registers the BufRing, submits multishot recvmsg, and submits
        the initial periodic timeout.

        Args:
            driver: The IoUringDriver to submit operations on.
        """
        # Register BufRing.
        self._bufring = driver.register_buf_ring(
            self._pbuf_pool, UInt32(PBUF_SIZE), PBUF_COUNT, PBUF_GROUP_ID
        )

        # Submit multishot recvmsg.
        var recvmsg_cmp_ptr = UnsafePointer[Completion, MutAnyOrigin](
            unsafe_from_address=Int(UnsafePointer(to=self._recvmsg_cmp))
        )
        var msg_ptr = UnsafePointer[msghdr, MutAnyOrigin](
            unsafe_from_address=Int(self._msghdr_template)
        )
        driver.submit_multishot_recvmsg(
            self.udp_handle.raw(), msg_ptr, PBUF_GROUP_ID, recvmsg_cmp_ptr
        )
        self._multishot_active = True

        # Submit initial timeout.
        var timeout_cmp_ptr = UnsafePointer[Completion, MutAnyOrigin](
            unsafe_from_address=Int(UnsafePointer(to=self._timeout_cmp))
        )
        var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
            unsafe_from_address=Int(self._timeout_ts)
        )
        driver.submit_timeout(ts_ptr, timeout_cmp_ptr)

    def flush(mut self, mut driver: IoUringDriver) raises:
        """Process buffered ingress, submit egress, recycle buffers.

        Called by the external run loop after each tick. MUST NOT call
        driver.tick() or any CQE-dispatching method (no-callback-during-flush
        invariant).

        Args:
            driver: The IoUringDriver for submitting new SQEs.
        """
        # 1. Process buffered ingress (DCID routing, QUIC feed, egress drain).
        self._flush_ingress()

        # 2. Drain inject_egress (from inject_response cross-transport path).
        while len(self._inject_egress) > 0:
            self._egress_backlog.append(self._inject_egress.pop())

        # 3. Submit egress from backlog via slab pool.
        self._submit_egress(driver)

        # 4. Egress backpressure: if backlog exceeds 2x slab capacity,
        # delay BufRing recycling to throttle ingress at the kernel level.
        # Without available buffers, the kernel pauses multishot recvmsg.
        var backlog_over_cap = len(self._egress_backlog) > (
            self._send_pool.capacity * _BACKLOG_CAP_MULTIPLIER
        )
        if not backlog_over_cap:
            for i in range(len(self._bufs_to_recycle)):
                self._bufring.add_buffer(self._bufs_to_recycle[i])
            self._bufs_to_recycle.clear()
        # else: delay recycling — kernel pauses multishot (no available buffers)

        # 5. Re-arm multishot recvmsg if it ended.
        if self._needs_multishot_rearm:
            var cmp_ptr = UnsafePointer[Completion, MutAnyOrigin](
                unsafe_from_address=Int(
                    UnsafePointer(to=self._recvmsg_cmp)
                )
            )
            var msg_ptr = UnsafePointer[msghdr, MutAnyOrigin](
                unsafe_from_address=Int(self._msghdr_template)
            )
            driver.submit_multishot_recvmsg(
                self.udp_handle.raw(),
                msg_ptr,
                PBUF_GROUP_ID,
                cmp_ptr,
            )
            self._multishot_active = True
            self._needs_multishot_rearm = False

        # 6. Re-arm timeout.
        var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
            unsafe_from_address=Int(self._timeout_ts)
        )
        var timeout_cmp_ptr = UnsafePointer[Completion, MutAnyOrigin](
            unsafe_from_address=Int(UnsafePointer(to=self._timeout_cmp))
        )
        try:
            driver.submit_timeout(ts_ptr, timeout_cmp_ptr)
        except:
            pass  # SQ full — will retry next tick.

    def _submit_egress(
        mut self, mut driver: IoUringDriver
    ) raises:
        """Submit queued egress packets via the slab pool.

        Drains _egress_backlog FIFO. When the slab is exhausted or the
        SQ is full, remaining packets stay in the backlog for the next
        flush cycle.

        Args:
            driver: The IoUringDriver for submitting sendmsg SQEs.
        """
        var remaining = List[EgressPacket]()
        while len(self._egress_backlog) > 0:
            var pkt = self._egress_backlog.pop()
            var slot_idx = self._send_pool.acquire()
            if slot_idx < 0:
                # Slab exhausted — put back and stop.
                remaining.append(pkt^)
                break
            var slab = self._send_pool.slot_ptr(slot_idx)
            slab[].fill(pkt.data, pkt.addr)
            var msg_ptr = UnsafePointer[msghdr, MutAnyOrigin](
                unsafe_from_address=Int(slab[].msghdr_ptr())
            )
            var cmp_ptr = self._send_pool.completion_ptr(slot_idx)
            try:
                driver.submit_sendmsg(
                    self.udp_handle.raw(), msg_ptr, cmp_ptr
                )
            except:
                # SQ full — release slot and re-queue.
                self._send_pool.release(slot_idx)
                remaining.append(pkt^)
                break
        # Put unsubmitted packets back (preserve FIFO order).
        while len(remaining) > 0:
            self._egress_backlog.append(remaining.pop())

    # ── Ingress (recvmsg multishot) ──────────────────────────────

    def _handle_recvmsg_impl(mut self, result: Int32, flags: UInt32) raises:
        """Process a single recvmsg CQE — parse the datagram and buffer
        it into pending_rx for flush() processing.

        Called from the static _on_recvmsg callback.

        Args:
            result: io_uring CQE result (bytes received or negative errno).
            flags: io_uring CQE flags (F_MORE, F_BUFFER, buffer ID).
        """
        # Track multishot lifecycle. F_MORE clears when the kernel stops
        # the multishot — flush() re-arms it.
        if (flags & UInt32(IORING_CQE_F_MORE)) == 0:
            self._needs_multishot_rearm = True

        # Error or cancelled — nothing to process. We swallow rather than
        # raise because per-CQE errors (mostly ENOBUFS under burst) are
        # routine and the loop must stay alive.
        if result <= 0:
            return

        # Must have a buffer attached.
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            return

        # Extract buffer ID from CQE flags and mark it userspace-owned.
        var buf_id = UInt16(flags >> UInt32(IORING_CQE_BUFFER_SHIFT))
        self._acquire_buf(buf_id)
        var buf_ptr = self._pbuf_pool + Int(buf_id) * PBUF_SIZE

        # Parse the io_uring_recvmsg_out 16-byte header:
        #   [namelen: u32][controllen: u32][payloadlen: u32][flags: u32]
        if result < Int32(_RECVMSG_OUT_HDR_SIZE):
            self._release_buf(buf_id)
            return

        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr + 4))
        var payloadlen = Int(_read_u32_le(buf_ptr + 8))
        var msg_flags = _read_u32_le(buf_ptr + 12)

        # MSG_TRUNC (0x20) — drop truncated datagrams (PBUF_SIZE was too
        # small for the datagram).
        if (msg_flags & UInt32(0x20)) != 0:
            self._release_buf(buf_id)
            return

        # Address starts after the 16-byte header.
        var addr_offset = _RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen

        # Payload starts after header + name + control.
        var payload_offset = _RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr + payload_offset

        if payloadlen <= 0:
            self._release_buf(buf_id)
            return

        # Extract DCID directly from the provided buffer — no copy.
        var dcid: List[UInt8]
        try:
            dcid = extract_dcid(
                Span[UInt8, MutAnyOrigin](ptr=payload_ptr, length=payloadlen)
            )
        except:
            self._release_buf(buf_id)
            return

        self.pending_rx.append(
            PendingDatagram(
                buf_id=buf_id,
                buf_ptr=buf_ptr,
                payload_ptr=payload_ptr,
                payload_len=payloadlen,
                addr_offset=addr_offset,
                addr_len=addr_len,
                dcid=dcid^,
            )
        )

    # ── Per-connection construction ──────────────────────────────

    def _construct_conn_handler(
        mut self, dcid: Span[UInt8, _], now: UInt64
    ) raises -> UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin]:
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
            UnsafePointer(to=self.profile),
        )

        # Per-conn StreamHandler — produced by the user-supplied factory.
        var handler = self.make_handler()

        # Promote QuicServerConfig._early_data_filter into a raw pointer the
        # H3 adapter dispatches via on `_on_request`. Mirrors how
        # `QuicConnection.server` promotes the `_early_data_store`
        # reference — the pointer is valid for the connection's lifetime
        # because `self.server_config` outlives every connection here.
        # `rebind` lifts the inferred config-bound origin to `MutAnyOrigin`
        # so the pointer can be stored alongside the existing
        # `_early_data_store_ptr` shape.
        var early_data_filter_ptr_opt = Optional[
            UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
        ](None)
        if self.server_config._early_data_filter is not None:
            var filter_ptr = rebind[
                UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
            ](UnsafePointer(to=self.server_config._early_data_filter.value()))
            early_data_filter_ptr_opt = Optional[
                UnsafePointer[IdempotentOnlyFilter, MutAnyOrigin]
            ](filter_ptr)

        # Thread the policy's predicate-fn (if any) into the per-connection
        # adapter ctor. The fn-pointer is Optional[EarlyDataPredicateFn] —
        # trivially copyable in Mojo 1.0.0b1 — so no pointer-lifetime
        # threading is needed (unlike the IdempotentOnlyFilter struct above).
        var predicate_fn_opt = self.server_config._early_data_predicate_fn

        var h3 = H3HandlerServer[Self.H](
            quic=quic^,
            handler=handler^,
            profile_ptr=UnsafePointer(to=self.profile),
            early_data_filter_ptr=early_data_filter_ptr_opt,
            predicate_fn=predicate_fn_opt,
        )

        var h3_ptr = _heap_alloc[H3HandlerServer[Self.H]](1).as_unsafe_any_origin()
        h3_ptr.init_pointee_move(h3^)
        return h3_ptr

    # ── Ingress flush ───────────────────────────────────────────

    def _flush_ingress(mut self) raises:
        """Process all buffered recvmsg packets through QUIC/H3.

        Drains `pending_rx`, routes each packet by DCID, creates new
        connections for Initial packets, feeds datagrams into the QUIC
        stack, and queues egress into `_egress_backlog`.
        """
        var now = monotonic_us()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()

            # DCID-keyed demux. pd.dcid extracted during _handle_recvmsg_impl.
            var dcid_u64 = dcid_to_u64(Span(pd.dcid))
            var conn_idx = self._find_conn_by_dcid(dcid_u64)

            # RFC 9000 §12.4: only long-header Initial packets create new
            # conns. All other DCID-misses are dropped silently.
            if conn_idx < 0:
                var first_byte_span = Span[UInt8, MutAnyOrigin](
                    ptr=pd.payload_ptr, length=pd.payload_len)
                if not is_long_header_initial(first_byte_span):
                    self._release_buf(pd.buf_id)
                    continue

            if conn_idx < 0:
                # New conn — drive QuicConnection.server() and wrap in
                # H3HandlerServer via the extracted constructor (which wires
                # the accept-profile pointer through both layers).
                var h3_ptr: UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin]
                try:
                    h3_ptr = self._construct_conn_handler(Span(pd.dcid), now)
                except e:
                    print("H3UdpServer: conn construction error:", e)
                    self._release_buf(pd.buf_id)
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

                # Build peer address from the provided buffer for sendmsg
                # routing. Stored as a raw sockaddr blob (16 or 28 bytes)
                # — SendSlab.fill() consumes the same layout. The structured
                # `PathKey` lives on the QuicConnection (peer_addr +
                # path_validator); the server keeps the raw blob only for
                # sendmsg msg_name.
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[pd.addr_offset + j])

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

                # Seed `peer_addr` exactly once at conn creation so
                # the sentinel zero PathKey is replaced. From this point
                # forward, `peer_addr` only mutates inside
                # `on_path_response_received` after a verified match.
                var bootstrap_key = _sockaddr_to_path_key(
                    pd.buf_ptr, pd.addr_offset, pd.addr_len
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
                pd.buf_ptr, pd.addr_offset, pd.addr_len
            )

            # Detect path change vs the validated peer_addr.
            # On migration-disabled, close_transport(0x0A) — the
            # connection-close frame goes out in the next flush. On
            # migration-allowed mismatch, kick off PATH_CHALLENGE. Always
            # credits per-path bytes_received for the unvalidated case.
            try:
                self.conn_slots[conn_idx].h3[].on_ingress_from(
                    PathKey(other=from_path), pd.payload_len, now
                )
            except e:
                print("H3UdpServer: on_ingress_from error:", e)

            # Stamp the receive-addr cursor so the inner
            # _dispatch_frame can match an incoming PATH_RESPONSE against
            # the address that carried it. Set BEFORE feed_datagram so
            # the coalesced packets in this datagram all see the same
            # cursor.
            self.conn_slots[conn_idx].h3[].set_current_recv_addr(
                PathKey(other=from_path)
            )

            # Feed datagram into the QuicConnection.
            try:
                self.conn_slots[conn_idx].h3[].feed_datagram_from_buffer(
                    pd.payload_ptr, pd.payload_len, now
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
            # decides where to listen).
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[pd.addr_offset + j])
            self.conn_slots[conn_idx].addr = addr_update^

            # Egress — drain QUIC + H3 packets and queue sendmsg submits.
            try:
                self._drain_and_send(conn_idx, now)
            except e:
                print("H3UdpServer: drain_and_send error:", e)

            self._release_buf(pd.buf_id)

        self.pending_rx.clear()

    # ── Egress ───────────────────────────────────────────────────

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain outgoing datagrams from a connection and queue them
        as EgressPacket entries for flush()'s _submit_egress phase.

        RFC 9000 §8.1 anti-amplification: for each datagram the server
        intends to send to the current peer addr, gate via
        `can_send_to(target, n)`. If the peer's address has a pending
        PATH_CHALLENGE, the per-path 3x budget caps the bytes we may
        emit until validation completes. Datagrams refused by the gate
        are dropped; they'll be regenerated on the next flush after
        more bytes arrive from the peer (or after validation lifts the
        gate entirely). On a successful queue we credit the per-path
        bytes_sent so subsequent emissions stay within budget.

        Args:
            conn_idx: Index into conn_slots for the connection to drain.
            now: Current monotonic time in microseconds.
        """
        var datagrams = self.conn_slots[conn_idx].h3[].drain_datagrams(now)

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

        for i in range(len(datagrams)):
            var pkt = List[UInt8](copy=datagrams[i])
            if len(pkt) == 0:
                continue

            # Per-path anti-amp gate. No-op when `target_key` has
            # no pending challenge (validated path → returns True). The
            # validator's `can_send_bytes` includes the QUIC header +
            # AEAD ciphertext (i.e. the full UDP payload), matching RFC
            # 9000 §8.1's measurement convention.
            if not self.conn_slots[conn_idx].h3[].can_send_to(
                target_key, len(pkt)
            ):
                # Budget exhausted on the unvalidated path. Drop the
                # datagram; loss recovery will regenerate the contents
                # once the peer credits more bytes or validation lifts
                # the gate. NOT a fatal error.
                continue

            var pkt_len = len(pkt)
            var addr_copy = List[UInt8](copy=self.conn_slots[conn_idx].addr)

            self._egress_backlog.append(
                EgressPacket(pkt^, addr_copy^, conn_idx)
            )

            # Credit per-path bytes_sent. No-op on validated paths.
            self.conn_slots[conn_idx].h3[].record_send_to(
                target_key, pkt_len
            )

    def _handle_timeout_impl(mut self, result: Int32) raises:
        """Periodic timeout — advance each conn's QUIC clock, drain
        any pending retransmissions, and remove conns that signal
        `should_close()` (idle timeout or graceful close).

        Timer re-arm is handled by flush() — this method only
        processes connections and queues egress.

        Args:
            result: io_uring CQE result (negative errno on error).
        """
        var now = monotonic_us()

        # Walk conns (index-based; we mutate conn_slots mid-iter via
        # swap-and-pop). `should_close()` collapses idle, closed,
        # and drain-complete states into one signal.
        var i = 0
        while i < len(self.conn_slots):
            try:
                self._drain_and_send(i, now)
            except:
                pass

            if self.conn_slots[i].h3[].should_close():
                var slot_h3 = self.conn_slots[i].h3
                slot_h3.destroy_pointee()
                slot_h3.free()
                # Null out the field immediately so any later read on
                # `conn_slots[i].h3` (before swap-and-pop overwrites
                # the slot or `pop()` discards it) hits a clean null
                # rather than a dangling pointer.
                self.conn_slots[i].h3 = null_ptr[
                    H3HandlerServer[Self.H], MutAnyOrigin
                ]()

                # B-permissive teardown: pop ALL of dying conn's DCID
                # entries from the demux map (typically 2: initial_dcid
                # + local_cid). NOT first-match-break — that was a
                # pre-dual-DCID bug.
                for dcid_u64 in self.conn_slots[i].dcids:
                    _ = self.conn_dcid_map.pop(dcid_u64)

                var last = len(self.conn_slots) - 1
                if i != last:
                    # Swap-and-pop: pop the last slot (taking ownership),
                    # bump its generation so any stale `(idx=i, old_gen)`
                    # entries left in `conn_dcid_map` fail the generation
                    # check in `_find_conn_by_dcid`, then remap the
                    # survivor's DCIDs to `(i, new_gen)`.
                    var survivor = self.conn_slots.pop()
                    var new_gen = self.next_generation
                    self.next_generation += UInt64(1)
                    survivor.generation = new_gen
                    for dcid_u64 in survivor.dcids:
                        self.conn_dcid_map[dcid_u64] = _DcidEntry(i, new_gen)
                    self.conn_slots[i] = survivor^
                else:
                    _ = self.conn_slots.pop()
                continue  # re-check the swapped-in element at index i
            i += 1

        # Timer re-arm is handled by flush() — no action needed here.

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
        self.conn_slots[conn_idx].h3[].inject_response(
            sid, status^, headers^, body^, end
        )
        var now = monotonic_us()
        var datagrams = self.conn_slots[conn_idx].h3[].drain_datagrams(now)
        var addr_copy = List[UInt8](copy=self.conn_slots[conn_idx].addr)
        for i in range(len(datagrams)):
            var pkt = List[UInt8](copy=datagrams[i])
            if len(pkt) == 0:
                continue
            self._inject_egress.append(
                EgressPacket(pkt^, List[UInt8](copy=addr_copy), conn_idx)
            )


# ── Static callbacks (module-level for Mojo parameterised-struct compat) ─────


def _on_recvmsg[H: StreamHandler](
    ctx: UnsafePointer[NoneType, MutAnyOrigin],
    result: Int32,
    flags: UInt32,
):
    """Multishot recvmsg CQE callback. Buffers received packet into
    the server's pending_rx queue.

    Defined at module level (rather than as a static method on the
    parameterised struct) to avoid Mojo limitations with static
    methods on generic structs.

    Args:
        ctx: Type-erased pointer to the owning H3UdpServer instance.
        result: io_uring CQE result (bytes received or negative errno).
        flags: io_uring CQE flags.
    """
    var self_ptr = UnsafePointer[H3UdpServer[H], MutAnyOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        self_ptr[]._handle_recvmsg_impl(result, flags)
    except e:
        print("H3UdpServer: _on_recvmsg error:", e)


def _on_timeout[H: StreamHandler](
    ctx: UnsafePointer[NoneType, MutAnyOrigin],
    result: Int32,
    flags: UInt32,
):
    """Periodic timeout CQE callback. Walks connections, drains egress,
    reaps closed connections.

    Defined at module level for parameterised-struct compatibility.

    Args:
        ctx: Type-erased pointer to the owning H3UdpServer instance.
        result: io_uring CQE result (negative errno on error).
        flags: io_uring CQE flags (unused for timeout).
    """
    var self_ptr = UnsafePointer[H3UdpServer[H], MutAnyOrigin](
        unsafe_from_address=Int(ctx)
    )
    try:
        self_ptr[]._handle_timeout_impl(result)
    except e:
        print("H3UdpServer: _on_timeout error:", e)
