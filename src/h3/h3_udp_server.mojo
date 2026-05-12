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
    │  ├─ sendmsg CQE → free UdpTxSlot
    │  └─ timeout CQE → walk conn_h3s, drain timeouts
    │
    │  on_flush() ─────────── (after all CQEs in this batch)
    │  └─ _flush_impl: demux pending_rx by DCID, route to
    │                  H3HandlerServer[H] per conn, drain egress,
    │                  enqueue sendmsg PendingSubmits
    │
    │  outer driver: tick() → drain_pending_submits() ───→ SQE
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
the server's lifetime. Typical pattern:

```mojo
var fd = udp_listener(443)              # OwnedHandle, owns the fd
var server = H3UdpServer[MyHandler](fd.raw(), tls_config, ...)
var io = IoUringUdp[H3UdpServer[MyHandler]](server^, sq_entries=4096)
# ... serve_forever drains the loop ...
# fd.__del__ closes the socket at end of scope
```

Stage B1 — initial skeleton. The on_complete / on_flush bodies stub
in this commit; Stage B1b ports the bench's demux + flush_impl + egress
machinery from bench/h3_server.mojo.
"""

from collections import Dict
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.handle import RawHandle
from boucle.completion import BatchCompletionHandler

from src.http.handler import StreamHandler
from src.h3.h3_handler_server import H3HandlerServer
from src.quic.profile import AcceptProfile


# ── Wire constants ────────────────────────────────────────────────────────────


comptime _MSGHDR_SIZE: Int = 56
comptime _IOVEC_SIZE: Int = 16
comptime _ADDR_SIZE: Int = 28        # sockaddr_in6
comptime _TIMESPEC_SIZE: Int = 16    # __kernel_timespec

# Provided-buffer ring sizing for multishot recvmsg.
comptime PBUF_COUNT: Int = 1024
comptime PBUF_SIZE: Int = 1600
comptime PBUF_GROUP_ID: UInt16 = 0

# Token encoding — high byte = op kind, low 56 bits = counter / slot id.
comptime _OP_SHIFT: UInt64 = 56
comptime _OP_RECVMSG: UInt64 = 1
comptime _OP_SENDMSG: UInt64 = 2
comptime _OP_TIMEOUT: UInt64 = 3
comptime _OP_PROVIDE: UInt64 = 4


fn _encode_token(counter: UInt64, op: UInt64) -> UInt64:
    return (op << _OP_SHIFT) | (counter & ((UInt64(1) << _OP_SHIFT) - 1))


fn _decode_token_op(token: UInt64) -> UInt64:
    return token >> _OP_SHIFT


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
    var kind: UInt8       # 1 = sendmsg, 2 = timeout
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
    """

    # Listening UDP fd. RawHandle (unowned); caller's OwnedHandle keeps
    # the fd alive across the server's lifetime.
    var udp_fd: RawHandle

    # rustls server config handle (from src/tls/lib.mojo). Cloned per
    # new conn.
    var server_config: Int32

    # TransportParams blob — serialized once at __init__ and reused
    # for every new conn's `QuicConnection.server(...)` call.
    var transport_params: List[UInt8]

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
        server_config: Int32,
        var transport_params: List[UInt8],
    ):
        self.udp_fd = udp_fd
        self.server_config = server_config
        self.transport_params = transport_params^

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
        # msg_namelen at offset 8 = sizeof(sockaddr_in6).
        self.msghdr_template[8] = 28
        self.multishot_active = False

        self.tx_slots = List[UnsafePointer[UdpTxSlot, MutAnyOrigin]]()
        self.tx_slot_tokens = List[UInt64]()
        self.tx_slot_idx_by_token = Dict[UInt64, Int]()
        self.next_tx_id = UInt64(0)

        self.pending_submits = List[PendingSubmit]()

        # 50ms periodic timeout — tv_sec=0, tv_nsec=50_000_000.
        self.timeout_ts = _heap_alloc[UInt8](_TIMESPEC_SIZE).as_any_origin()
        for i in range(_TIMESPEC_SIZE):
            self.timeout_ts[i] = 0
        self.timeout_ts[8] = 0x80
        self.timeout_ts[9] = 0xF0
        self.timeout_ts[10] = 0xFA
        self.timeout_ts[11] = 0x02

        self.profile = AcceptProfile()

    # ── BatchCompletionHandler conformance ───────────────────────

    fn on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        """CQE dispatch. Decodes op kind from token's high byte and
        routes to the matching handler. **Stage B1b** wires the
        recvmsg / sendmsg / timeout bodies."""
        var _op = _decode_token_op(token)
        # TODO(B1b): port _handle_recvmsg / _handle_sendmsg / _handle_timeout
        # from bench/h3_server.mojo. Bodies live there at lines:
        #   recvmsg:  bench/h3_server.mojo:737-783
        #   sendmsg:  bench/h3_server.mojo (search _handle_sendmsg)
        #   timeout:  bench/h3_server.mojo (search _handle_timeout)
        pass

    fn on_flush(mut self):
        """Batch-end callback. Drains `pending_rx`, runs QUIC ingress
        + H3 dispatch + egress for each conn, enqueues sendmsg
        `PendingSubmit`s. **Stage B1b** ports the body from
        bench/h3_server.mojo's `_flush_impl`."""
        # TODO(B1b): port _flush_impl from bench/h3_server.mojo.
        pass
