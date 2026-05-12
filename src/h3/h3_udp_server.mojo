"""H3UdpServer — generic UDP + QUIC + H3 server (callback model).

Drives multiple H3 connections off a single UDP socket using boucle's
`BatchCompletionLoop` via the `UdpIo` trait.

# Architecture

```text
  Mojo land                                Kernel
  ─────────                                ──────

  H3UdpServer[H: StreamHandler]            io_uring
    │                                        │
    │  on_complete(token, result, flags) ───┘   (CQE)
    │  ├─ recvmsg CQE → parse, queue PendingDatagram, reprovide buf
    │  ├─ sendmsg CQE → free UdpTxSlot           (Stage B1c)
    │  └─ timeout CQE → walk conn_h3s, drain     (Stage B1d)
    │
    │  on_flush() ─────────── (after all CQEs in this batch)
    │  └─ _flush_impl: demux pending_rx by DCID, route to
    │                  H3HandlerServer[H] per conn, drain egress,
    │                  enqueue sendmsg PendingSubmits
    │
    │  outer driver: tick() → drain_pending_submits() ───→ SQE  (Stage B1d)
    │
    └─ conn_h3s[i]: UnsafePointer[H3HandlerServer[H]]
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

`udp_fd` is a `RawHandle` (not owned). The caller owns the
`OwnedHandle` from `udp_listener()` and must keep it alive across
the server's lifetime. Same for the `RustlsLibrary` instance —
`lib_addr` stores its address but does not own it.
"""

from collections import Dict
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.handle import RawHandle
from boucle.completion import BatchCompletionHandler, BatchCompletionLoop
from boucle._sys.linux.raw.ctypes import c_void
from boucle._sys.linux.raw.x86_64.io_uring import (
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_BUFFER_SHIFT,
)

from src.http.handler import StreamHandler
from src.h3.h3_handler_server import H3HandlerServer
from src.quic.cid import dcid_to_u64
from src.quic.connection import QuicConnection
from src.quic.packet import is_long_header_initial, extract_dcid
from src.quic.profile import AcceptProfile, PROFILE_ACCEPT, monotonic_us
from src.quic.trans_param import TransportParams


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

# Token encoding — low byte = op kind, high 56 bits = slot id / counter.
# Matches the bench convention so the wire-format is preserved when bench
# refactors onto this server in Stage B3.
comptime OP_RECVMSG: UInt8 = 0
comptime OP_SENDMSG: UInt8 = 1
comptime OP_TIMEOUT: UInt8 = 2
comptime OP_PROVIDE_BUF: UInt8 = 3


fn _encode_token(slot_idx: UInt64, op_kind: UInt8) -> UInt64:
    return (slot_idx << 8) | UInt64(op_kind)


@always_inline
fn _read_u32_le(ptr: UnsafePointer[UInt8, MutAnyOrigin]) -> UInt32:
    return (
        UInt32(ptr[0])
        | (UInt32(ptr[1]) << 8)
        | (UInt32(ptr[2]) << 16)
        | (UInt32(ptr[3]) << 24)
    )


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


# ── Egress slot ──────────────────────────────────────────────────────────────


struct UdpTxSlot(Movable):
    """Heap-allocated msghdr + iovec + addr + payload tuple for one
    sendmsg. Owned by the H3UdpServer's tx_slots list and freed in
    `_handle_sendmsg` after the CQE arrives.
    """
    var msghdr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var iov_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var addr_buf: UnsafePointer[UInt8, MutAnyOrigin]
    var data_buf: UnsafePointer[UInt8, MutAnyOrigin]

    def __init__(out self, var data: List[UInt8], addr: List[UInt8]):
        var data_len = len(data)

        self.msghdr_buf = _heap_alloc[UInt8](_MSGHDR_SIZE).as_any_origin()
        self.iov_buf = _heap_alloc[UInt8](_IOVEC_SIZE).as_any_origin()
        self.addr_buf = _heap_alloc[UInt8](_ADDR_SIZE).as_any_origin()
        self.data_buf = _heap_alloc[UInt8](data_len).as_any_origin()

        # Copy payload.
        for i in range(data_len):
            self.data_buf[i] = data[i]

        # Copy peer addr; pad with zeroes to sockaddr_in6 size.
        var addr_len = len(addr)
        for i in range(_ADDR_SIZE):
            if i < addr_len:
                self.addr_buf[i] = addr[i]
            else:
                self.addr_buf[i] = 0

        # Zero msghdr + iov.
        for i in range(_MSGHDR_SIZE):
            self.msghdr_buf[i] = 0
        for i in range(_IOVEC_SIZE):
            self.iov_buf[i] = 0

        var msghdr = self.msghdr_buf

        # offset 0 — msg_name = &addr_buf
        var addr_ptr_val = UInt64(Int(self.addr_buf))
        var addr_ptr_bytes = UnsafePointer(to=addr_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[i] = addr_ptr_bytes[i]

        # offset 8 — msg_namelen = sizeof(sockaddr_in6)
        var namelen = UInt32(_ADDR_SIZE)
        var namelen_bytes = UnsafePointer(to=namelen).bitcast[UInt8]()
        for i in range(4):
            msghdr[8 + i] = namelen_bytes[i]

        # offset 16 — msg_iov = &iov_buf
        var iov_ptr_val = UInt64(Int(self.iov_buf))
        var iov_ptr_bytes = UnsafePointer(to=iov_ptr_val).bitcast[UInt8]()
        for i in range(8):
            msghdr[16 + i] = iov_ptr_bytes[i]

        # offset 24 — msg_iovlen = 1
        var iovlen = UInt64(1)
        var iovlen_bytes = UnsafePointer(to=iovlen).bitcast[UInt8]()
        for i in range(8):
            msghdr[24 + i] = iovlen_bytes[i]

        # iov[0].iov_base = &data_buf
        var iov = self.iov_buf
        var data_ptr_val = UInt64(Int(self.data_buf))
        var data_ptr_bytes = UnsafePointer(to=data_ptr_val).bitcast[UInt8]()
        for i in range(8):
            iov[i] = data_ptr_bytes[i]

        # iov[0].iov_len = data_len
        var iov_len = UInt64(data_len)
        var iov_len_bytes = UnsafePointer(to=iov_len).bitcast[UInt8]()
        for i in range(8):
            iov[8 + i] = iov_len_bytes[i]

    def __init__(out self, *, deinit take: Self):
        self.msghdr_buf = take.msghdr_buf
        self.iov_buf = take.iov_buf
        self.addr_buf = take.addr_buf
        self.data_buf = take.data_buf

    def free(mut self):
        self.msghdr_buf.free()
        self.iov_buf.free()
        self.addr_buf.free()
        self.data_buf.free()


# ── Pending submit (queued from on_complete; drained after tick) ─────────────


struct PendingSubmit(Copyable, Movable):
    var kind: UInt8       # OP_SENDMSG or OP_TIMEOUT
    var slot_idx: UInt64

    def __init__(out self, kind: UInt8, slot_idx: UInt64):
        self.kind = kind
        self.slot_idx = slot_idx

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.slot_idx = other.slot_idx

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.slot_idx = take.slot_idx


# ── H3UdpServer ──────────────────────────────────────────────────────────────


struct H3UdpServer[H: StreamHandler](BatchCompletionHandler):
    """Generic UDP + QUIC + H3 server.

    Parameterised on `H: StreamHandler`. Each accepted connection
    allocates a heap-owned `H3HandlerServer[H]` which owns its own
    `H` instance plus the underlying `QuicConnection` + `H3Connection`.

    `make_handler` is a user-provided factory function called once per
    new QUIC connection. The factory owns construction policy — share
    state via captured pointers (Mojo doesn't have closures yet, so
    factories typically read from a module-level singleton or take
    state via the surrounding context the user threads through).
    """

    # Listening UDP fd. RawHandle (unowned); caller's OwnedHandle keeps
    # the fd alive across the server's lifetime.
    var udp_fd: RawHandle

    # rustls library pointer (cast to UInt64 to thread through QuicConnection
    # FFI). Caller owns the RustlsLibrary instance.
    var lib_addr: UInt64

    # rustls server config handle (from src/tls/lib.mojo). Cloned per
    # new conn via the QuicConnection.server() FFI path.
    var server_config: Int32

    # Transport params reused for every new QuicConnection.server() call.
    var transport_params: TransportParams

    # Per-conn handler factory.
    var make_handler: fn () raises -> Self.H

    # Per-conn book-keeping. conn_h3s[i] is paired with conn_addrs[i]
    # (peer sockaddr) + conn_dcids[i] (every DCID this conn responds
    # to — typically [initial_dcid, local_cid] for dual-DCID demux).
    var conn_h3s: List[UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin]]
    var conn_dcid_map: Dict[UInt64, Int]
    var conn_dcids: List[List[UInt64]]
    var conn_addrs: List[List[UInt8]]

    # Ingress staging. pending_rx fills from on_complete (one per
    # recvmsg CQE); _flush_impl drains it in on_flush.
    var pending_rx: List[PendingDatagram]
    var consumed_bufs: List[UInt16]

    # io_uring multishot recvmsg infrastructure.
    var pbuf_pool: UnsafePointer[UInt8, MutAnyOrigin]
    var msghdr_template: UnsafePointer[UInt8, MutAnyOrigin]
    var multishot_active: Bool

    # Egress slot pool — sendmsg buffers.
    var tx_slots: List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]
    var tx_slot_tokens: List[UInt64]
    var tx_slot_idx_by_token: Dict[UInt64, Int]
    var next_tx_id: UInt64

    # Pending submits queued from on_complete; drained after tick().
    var pending_submits: List[PendingSubmit]

    # Periodic timeout for QUIC loss detection / idle close.
    var timeout_ts: UnsafePointer[UInt8, MutAnyOrigin]

    # PROFILE_ACCEPT counters (always present; dead-stripped when
    # PROFILE_ACCEPT=False at compile time).
    var profile: AcceptProfile

    # ── Construction ─────────────────────────────────────────────

    fn __init__(
        out self,
        udp_fd: RawHandle,
        lib_addr: UInt64,
        server_config: Int32,
        var transport_params: TransportParams,
        make_handler: fn () raises -> Self.H,
    ):
        self.udp_fd = udp_fd
        self.lib_addr = lib_addr
        self.server_config = server_config
        self.transport_params = transport_params^
        self.make_handler = make_handler

        self.conn_h3s = List[UnsafePointer[H3HandlerServer[Self.H], MutAnyOrigin]]()
        self.conn_dcid_map = Dict[UInt64, Int]()
        self.conn_dcids = List[List[UInt64]]()
        self.conn_addrs = List[List[UInt8]]()

        self.pending_rx = List[PendingDatagram]()
        self.consumed_bufs = List[UInt16]()

        self.pbuf_pool = _heap_alloc[UInt8](PBUF_COUNT * PBUF_SIZE).as_any_origin()
        for i in range(PBUF_COUNT * PBUF_SIZE):
            self.pbuf_pool[i] = 0

        self.msghdr_template = _heap_alloc[UInt8](_MSGHDR_SIZE).as_any_origin()
        for i in range(_MSGHDR_SIZE):
            self.msghdr_template[i] = 0
        # msg_namelen at offset 8 = sizeof(sockaddr_in6). The kernel populates
        # the peer address in the provided buffer (controlled via iov_len=0
        # below — recvmsg-multishot ignores iov when buf-ring is in use).
        self.msghdr_template[8] = 28
        self.multishot_active = False

        self.tx_slots = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_tokens = List[UInt64]()
        self.tx_slot_idx_by_token = Dict[UInt64, Int]()
        self.next_tx_id = UInt64(0)

        self.pending_submits = List[PendingSubmit]()

        # 50ms periodic timeout — tv_sec=0, tv_nsec=50_000_000 LE.
        self.timeout_ts = _heap_alloc[UInt8](_TIMESPEC_SIZE).as_any_origin()
        for i in range(_TIMESPEC_SIZE):
            self.timeout_ts[i] = 0
        self.timeout_ts[8] = 0x80
        self.timeout_ts[9] = 0xF0
        self.timeout_ts[10] = 0xFA
        self.timeout_ts[11] = 0x02

        self.profile = AcceptProfile()

    # ── Connection lookup ────────────────────────────────────────

    fn _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int:
        if dcid_u64 in self.conn_dcid_map:
            try:
                return self.conn_dcid_map[dcid_u64]
            except:
                return -1
        return -1

    # ── BatchCompletionHandler conformance ───────────────────────

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        """CQE dispatch. Decodes op kind from token's low byte and
        routes to the matching handler."""
        try:
            self._dispatch(token, result, flags)
        except e:
            print("H3UdpServer: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)
        if op_kind == OP_RECVMSG:
            self._handle_recvmsg(result, flags)
        elif op_kind == OP_SENDMSG:
            self._handle_sendmsg(token >> 8, result)
        elif op_kind == OP_TIMEOUT:
            # Stage B1d: _handle_timeout(result)
            pass
        elif op_kind == OP_PROVIDE_BUF:
            pass  # provide_buffers completion — nothing to do.

    # ── Ingress (recvmsg multishot) ──────────────────────────────

    def _handle_recvmsg(mut self, result: Int32, flags: UInt32) raises:
        # Track multishot lifecycle. F_MORE clears when the kernel stops
        # the multishot — caller re-arms in the outer drain loop.
        if (flags & UInt32(IORING_CQE_F_MORE)) == 0:
            self.multishot_active = False

        # Error or cancelled — nothing to process. We swallow rather than
        # raise because per-CQE errors (mostly ENOBUFS under burst) are
        # routine and the loop must stay alive.
        if result <= 0:
            return

        # Must have a buffer attached.
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            return

        # Extract buffer ID from CQE flags.
        var buf_id = UInt16(flags >> UInt32(IORING_CQE_BUFFER_SHIFT))
        var buf_ptr = self.pbuf_pool + Int(buf_id) * PBUF_SIZE

        # Parse the io_uring_recvmsg_out 16-byte header:
        #   [namelen: u32][controllen: u32][payloadlen: u32][flags: u32]
        if result < Int32(_RECVMSG_OUT_HDR_SIZE):
            self.consumed_bufs.append(buf_id)
            return

        var namelen = Int(_read_u32_le(buf_ptr))
        var controllen = Int(_read_u32_le(buf_ptr + 4))
        var payloadlen = Int(_read_u32_le(buf_ptr + 8))
        var msg_flags = _read_u32_le(buf_ptr + 12)

        # MSG_TRUNC (0x20) — drop truncated datagrams (PBUF_SIZE was too
        # small for the datagram).
        if (msg_flags & UInt32(0x20)) != 0:
            self.consumed_bufs.append(buf_id)
            return

        # Address starts after the 16-byte header.
        var addr_offset = _RECVMSG_OUT_HDR_SIZE
        var addr_len = namelen

        # Payload starts after header + name + control.
        var payload_offset = _RECVMSG_OUT_HDR_SIZE + namelen + controllen
        var payload_ptr = buf_ptr + payload_offset

        if payloadlen <= 0:
            self.consumed_bufs.append(buf_id)
            return

        # Extract DCID directly from the provided buffer — no copy.
        var dcid: List[UInt8]
        try:
            dcid = extract_dcid(
                Span[UInt8, MutAnyOrigin](ptr=payload_ptr, length=payloadlen)
            )
        except:
            self.consumed_bufs.append(buf_id)
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

    # ── Batch flush ──────────────────────────────────────────────

    fn on_flush(mut self):
        """Batch-end callback. Drains `pending_rx`, runs QUIC ingress
        + H3 dispatch + egress for each conn."""
        try:
            self._flush_impl()
        except e:
            print("H3UdpServer: on_flush error:", e)

    def _flush_impl(mut self) raises:
        var now = monotonic_us()

        for i in range(len(self.pending_rx)):
            var pd = self.pending_rx[i].copy()

            # DCID-keyed demux. pd.dcid extracted during _handle_recvmsg.
            var dcid_u64 = dcid_to_u64(Span(pd.dcid))
            var conn_idx = self._find_conn_by_dcid(dcid_u64)

            # RFC 9000 §12.4: only long-header Initial packets create new
            # conns. All other DCID-misses are dropped silently.
            if conn_idx < 0:
                var first_byte_span = Span[UInt8, MutAnyOrigin](
                    ptr=pd.payload_ptr, length=pd.payload_len)
                if not is_long_header_initial(first_byte_span):
                    self.consumed_bufs.append(pd.buf_id)
                    continue

            if conn_idx < 0:
                # New conn — drive QuicConnection.server() and wrap in
                # H3HandlerServer.
                var dcid_copy = List[UInt8](copy=pd.dcid)
                var quic: QuicConnection
                try:
                    quic = QuicConnection.server(
                        self.lib_addr,
                        self.server_config,
                        self.transport_params.copy(),
                        Span(pd.dcid),
                        Span(dcid_copy),
                        now,
                    )
                except e:
                    print("H3UdpServer: QuicConnection.server error:", e)
                    self.consumed_bufs.append(pd.buf_id)
                    continue

                # B-permissive dual-DCID: both the client's Initial DCID
                # (random ICID) and the server's chosen SCID (local_cid)
                # map to the same conn_idx so the ICID→SCID transition
                # is transparent during the handshake.
                debug_assert(len(quic.initial_dcid) == 8, "initial_dcid != 8 bytes")
                debug_assert(len(quic.local_cid) == 8, "local_cid != 8 bytes")

                var icid_u64 = dcid_to_u64(Span(quic.initial_dcid))
                var lcid_u64 = dcid_to_u64(Span(quic.local_cid))

                # Per-conn StreamHandler — produced by the user-supplied
                # factory. The factory's free to share state via captured
                # module globals or external pointers.
                var handler = self.make_handler()
                var h3: H3HandlerServer[Self.H]
                try:
                    h3 = H3HandlerServer[Self.H](
                        quic=quic^,
                        handler=handler^,
                    )
                except e:
                    print("H3UdpServer: H3HandlerServer init error:", e)
                    self.consumed_bufs.append(pd.buf_id)
                    continue

                var h3_ptr = _heap_alloc[H3HandlerServer[Self.H]](1).as_any_origin()
                h3_ptr.init_pointee_move(h3^)

                # Build peer address from the provided buffer for sendmsg
                # routing.
                var addr = List[UInt8](capacity=pd.addr_len)
                for j in range(pd.addr_len):
                    addr.append(pd.buf_ptr[pd.addr_offset + j])

                conn_idx = len(self.conn_h3s)
                self.conn_dcid_map[icid_u64] = conn_idx
                self.conn_dcid_map[lcid_u64] = conn_idx
                self.conn_h3s.append(h3_ptr)
                self.conn_addrs.append(addr^)

                var dcids = List[UInt64]()
                dcids.append(icid_u64)
                dcids.append(lcid_u64)
                self.conn_dcids.append(dcids^)

            # Feed datagram into the QuicConnection.
            try:
                self.conn_h3s[conn_idx][].feed_datagram_from_buffer(
                    pd.payload_ptr, pd.payload_len, now
                )
            except e:
                print("H3UdpServer: feed_datagram error:", e)

            # Update peer address (datagrams may arrive from new ports
            # post-handshake; RFC 9000 §9 allows path migration but bench
            # tracks the latest seen address regardless).
            var addr_update = List[UInt8](capacity=pd.addr_len)
            for j in range(pd.addr_len):
                addr_update.append(pd.buf_ptr[pd.addr_offset + j])
            self.conn_addrs[conn_idx] = addr_update^

            # Egress — drain QUIC + H3 packets and queue sendmsg submits.
            try:
                self._drain_and_send(conn_idx, now)
            except e:
                print("H3UdpServer: drain_and_send error:", e)

            self.consumed_bufs.append(pd.buf_id)

        self.pending_rx.clear()

    # ── Egress ───────────────────────────────────────────────────

    def _drain_and_send(mut self, conn_idx: Int, now: UInt64) raises:
        """Drain outgoing datagrams from a connection and queue sendmsg
        submissions for the outer driver to issue post-tick.
        """
        var datagrams = self.conn_h3s[conn_idx][].drain_datagrams(now)
        for i in range(len(datagrams)):
            var pkt = List[UInt8](copy=datagrams[i])
            if len(pkt) == 0:
                continue

            var tx_id = self.next_tx_id
            self.next_tx_id += 1
            var token = _encode_token(tx_id, OP_SENDMSG)

            var addr_copy = List[UInt8](copy=self.conn_addrs[conn_idx])

            var tx_ptr = _heap_alloc[UdpTxSlot](1).as_any_origin()
            tx_ptr.init_pointee_move(UdpTxSlot(pkt^, addr_copy))

            var slot_idx = len(self.tx_slots)
            self.tx_slots.append(tx_ptr)
            self.tx_slot_tokens.append(token)
            self.tx_slot_idx_by_token[token] = slot_idx

            self.pending_submits.append(
                PendingSubmit(kind=OP_SENDMSG, slot_idx=tx_id)
            )

    def _handle_sendmsg(mut self, tx_id: UInt64, result: Int32) raises:
        """Sendmsg CQE — free the UdpTxSlot whose buffers the kernel
        consumed. `result` is the bytes-sent count or negative errno;
        partial sends are not retried (UDP semantics)."""
        var token = _encode_token(tx_id, OP_SENDMSG)
        if token not in self.tx_slot_idx_by_token:
            return
        var idx = self.tx_slot_idx_by_token[token]

        # Free the 4 heap buffers behind the slot.
        var ptr = self.tx_slots[idx]
        ptr[].free()
        ptr.free()

        # Swap-and-pop: move last slot into freed index, fix up the
        # token→idx map so the swapped slot's lookup still resolves.
        var last_idx = len(self.tx_slots) - 1
        if idx != last_idx:
            var last_ptr = self.tx_slots[last_idx]
            var last_token = self.tx_slot_tokens[last_idx]
            self.tx_slots[idx] = last_ptr
            self.tx_slot_tokens[idx] = last_token
            self.tx_slot_idx_by_token[last_token] = idx
        _ = self.tx_slots.pop()
        _ = self.tx_slot_tokens.pop()
        _ = self.tx_slot_idx_by_token.pop(token)


# ── Outer driver helpers ─────────────────────────────────────────────────────


fn drain_pending_submits[H: StreamHandler](
    mut io: BatchCompletionLoop[H3UdpServer[H]]
) raises:
    """Consume the server's `pending_submits` queue and issue the
    underlying io_uring submissions (sendmsg / timeout).

    Must be called after each `io.poll()` returns — the on_complete
    callback appends to `pending_submits` rather than re-entering the
    loop directly (boucle holds a mutable borrow on itself during
    poll, so handler bodies can't call `submit_*` inline).

    Pending submits exceeding the current SQ capacity stay in the
    queue and get retried on the next tick — caller is responsible
    for ensuring the SQ has room (typically by leaving headroom in
    `sq_entries` at construction).
    """
    var submits = io._handler.pending_submits^
    io._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        if s.kind == OP_SENDMSG:
            var tx_id = s.slot_idx
            var token = _encode_token(tx_id, OP_SENDMSG)
            if token not in io._handler.tx_slot_idx_by_token:
                continue
            var tx_idx = io._handler.tx_slot_idx_by_token[token]
            var msghdr_addr = Int(io._handler.tx_slots[tx_idx][].msghdr_buf)
            var msghdr_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=msghdr_addr
            )
            try:
                io.submit_sendmsg(io._handler.udp_fd, msghdr_ptr, token)
            except:
                # SQ full — re-queue for next tick.
                io._handler.pending_submits.append(s.copy())
        elif s.kind == OP_TIMEOUT:
            var ts_addr = Int(io._handler.timeout_ts)
            var ts_ptr = UnsafePointer[c_void, StaticConstantOrigin](
                unsafe_from_address=ts_addr
            )
            var token = _encode_token(s.slot_idx, OP_TIMEOUT)
            try:
                io.submit_timeout(ts_ptr, token)
            except:
                io._handler.pending_submits.append(s.copy())
