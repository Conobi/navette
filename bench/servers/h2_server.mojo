# bench/h2_server.mojo
#
# HTTP/2 TLS benchmark server on port 8443 (TCP).
#
# Uses boucle CompletionLoop + CompletionHandler, TLS via librustls-mojo,
# and H2CoroServer with bench_h2_body_fn from handler.mojo.
#
# Layout:
#   - Token encoding helpers
#   - PendingSubmit
#   - H2Conn — per-connection state (TLS + H2CoroServer)
#   - H2ServerHandler — CompletionHandler implementation
#   - _drain_pending_submits
#   - main

from std.collections import Dict
from std.ffi import external_call
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from navette.util.owned_alloc import Owned

from navette.tls import TlsServerConfig, TlsConnection
from navette.tls.lib import TlsBackend, SharedLibrary
from navette.h2.h2_sync_server import H2CoroServer
from bench.lib.handler import (
    bench_h2_body_fn,
    BenchState,
    StaticEntry,
    _load_static_files,
    _load_dataset,
)

from boucle import CompletionLoop, CompletionHandler
from boucle.completion import (
    BufRing,
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_BUFFER_SHIFT,
)
from boucle.handle import OwnedHandle
from boucle.net.socket import Socket
from boucle.net.addr import SocketAddrV4
from boucle.net.options import Backlog

from interop.file_io import read_file, getenv_opt


# ---------------------------------------------------------------------------
# Token encoding
# ---------------------------------------------------------------------------
comptime OP_ACCEPT: UInt8 = 0
comptime OP_RECV: UInt8 = 1
comptime OP_SEND: UInt8 = 2
comptime LISTENER_CONN_ID: UInt64 = 0


def encode_token(conn_id: UInt64, op_kind: UInt8) -> UInt64:
    return (conn_id << 8) | UInt64(op_kind)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
comptime _RECV_BUF_SIZE: Int = 8192
comptime _LISTEN_PORT: UInt16 = 8443
comptime SO_REUSEPORT: Int32 = 15
# Slice H2 plaintext into ~one-TLS-record-sized chunks before encrypting so
# each batch of HTTP/2 frames lands in its own TLS record on the wire. This
# matches what real servers (nginx) emit and gives clients more cut points
# to interleave inbound WINDOW_UPDATEs and new HEADERS with our outbound
# response stream.
comptime _TLS_RECORD_CHUNK: Int = 16384
# Per-worker registered buffer ring (IORING_REGISTER_PBUF_RING). Returning
# a consumed buffer is a userspace store on `BufRing.add_buffer(buf_id)` —
# no SQE, no syscall, no kernel buffer-pool tree.
comptime _BUF_GROUP_ID: UInt16 = 1
comptime _BUF_RING_SIZE: Int = 1024  # 1024 × 8 KB = 8 MiB resident per worker
comptime _ENOBUFS: Int32 = -105


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------
comptime _PHASE_TLS_HANDSHAKE: UInt8 = 0
comptime _PHASE_H2_READY: UInt8 = 1
comptime _PHASE_DONE: UInt8 = 2


# ---------------------------------------------------------------------------
# PendingSubmit
# ---------------------------------------------------------------------------
comptime _SUBMIT_ACCEPT: UInt8 = 0
comptime _SUBMIT_RECV: UInt8 = 1            # legacy, unused with multishot
comptime _SUBMIT_SEND: UInt8 = 2
comptime _SUBMIT_RECV_MULTISHOT: UInt8 = 3


struct PendingSubmit(Copyable, Movable):
    var kind: UInt8
    var fd: Int32
    var conn_id: UInt64
    var op_kind: UInt8

    def __init__(out self, kind: UInt8, fd: Int32, conn_id: UInt64, op_kind: UInt8):
        self.kind = kind
        self.fd = fd
        self.conn_id = conn_id
        self.op_kind = op_kind

    def __init__(out self, *, other: Self):
        self.kind = other.kind
        self.fd = other.fd
        self.conn_id = other.conn_id
        self.op_kind = other.op_kind

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.fd = take.fd
        self.conn_id = take.conn_id
        self.op_kind = take.op_kind


# ---------------------------------------------------------------------------
# H2Conn — per-connection state
# ---------------------------------------------------------------------------


struct H2Conn(Movable):
    var conn_id: UInt64
    var handle: OwnedHandle
    var tls: TlsConnection
    var h2: H2CoroServer
    var phase: UInt8
    var send_buf: List[UInt8]
    var send_pending: List[UInt8]
    var send_in_flight: Bool
    # `recv_in_flight` now means "kernel multishot recv is registered" —
    # set at accept-time submit, cleared when a CQE arrives without
    # IORING_CQE_F_MORE. (No per-conn recv_buf — buffers come from the
    # registered ring.)
    var recv_in_flight: Bool
    var closed: Bool

    def __init__(
        out self,
        conn_id: UInt64,
        var handle: OwnedHandle,
        var tls: TlsConnection,
        var h2: H2CoroServer,
    ):
        self.conn_id = conn_id
        self.handle = handle^
        self.tls = tls^
        self.h2 = h2^
        self.phase = _PHASE_TLS_HANDSHAKE
        self.send_buf = List[UInt8]()
        self.send_pending = List[UInt8]()
        self.send_in_flight = False
        self.recv_in_flight = False
        self.closed = False

    def __init__(out self, *, deinit take: Self):
        self.conn_id = take.conn_id
        self.handle = take.handle^
        self.tls = take.tls^
        self.h2 = take.h2^
        self.phase = take.phase
        self.send_buf = take.send_buf^
        self.send_pending = take.send_pending^
        self.send_in_flight = take.send_in_flight
        self.recv_in_flight = take.recv_in_flight
        self.closed = take.closed


# ---------------------------------------------------------------------------
# H2ServerHandler — CompletionHandler
# ---------------------------------------------------------------------------


struct H2ServerHandler(CompletionHandler):
    var listener_fd: Int32
    var connections: List[UnsafePointer[H2Conn, MutAnyOrigin]]
    var next_conn_id: UInt64
    var tls_lib: SharedLibrary
    var server_tls_config: TlsServerConfig
    var state_ptr: UnsafePointer[BenchState, MutAnyOrigin]
    var pending_submits: List[PendingSubmit]
    # Registered provided-buffer ring. CQE.flags >> IORING_CQE_BUFFER_SHIFT
    # gives buf_id; the buffer pointer is bring.buf_base + buf_id * buf_size.
    # Returning a buffer is bring.add_buffer(buf_id) — userspace store.
    var bring: BufRing

    def __init__(
        out self,
        listener_fd: Int32,
        var tls_lib: SharedLibrary,
        var server_tls_config: TlsServerConfig,
        state_ptr: UnsafePointer[BenchState, MutAnyOrigin],
        var bring: BufRing,
    ):
        self.listener_fd = listener_fd
        self.connections = List[UnsafePointer[H2Conn, MutAnyOrigin]]()
        self.next_conn_id = 1
        self.tls_lib = tls_lib^
        self.server_tls_config = server_tls_config^
        self.state_ptr = state_ptr
        self.pending_submits = List[PendingSubmit]()
        self.bring = bring^

    def __init__(out self, *, deinit take: Self):
        self.listener_fd = take.listener_fd
        self.connections = take.connections^
        self.next_conn_id = take.next_conn_id
        self.tls_lib = take.tls_lib^
        self.server_tls_config = take.server_tls_config^
        self.state_ptr = take.state_ptr
        self.pending_submits = take.pending_submits^
        self.bring = take.bring^

    # --- Conn lookup ---

    def _find_index(self, conn_id: UInt64) -> Int:
        for i in range(len(self.connections)):
            if self.connections[i][].conn_id == conn_id:
                return i
        return -1

    # --- on_complete dispatch ---

    def on_complete(mut self, token: UInt64, result: Int32, flags: UInt32):
        try:
            self._dispatch(token, result, flags)
        except e:
            print("h2-bench: on_complete error:", e)

    def _dispatch(mut self, token: UInt64, result: Int32, flags: UInt32) raises:
        var op_kind = UInt8(token & 0xFF)
        var conn_id = token >> 8

        if op_kind == OP_ACCEPT:
            self._handle_accept(result, flags)
            return

        var idx = self._find_index(conn_id)
        if idx < 0:
            return

        # Multishot recv lifetime: clear `recv_in_flight` only when the
        # multishot ends (no F_MORE). Until then the kernel keeps
        # producing CQEs into ring buffers, so the connection must stay
        # alive for buf_id-decoded reads to be valid.
        var multishot_ended = False
        if op_kind == OP_RECV:
            multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0

        # If connection is marked closed (deferred), clear in-flight flag
        # and free if no more operations are outstanding.
        if self.connections[idx][].closed:
            if op_kind == OP_RECV and multishot_ended:
                self.connections[idx][].recv_in_flight = False
            elif op_kind == OP_SEND:
                self.connections[idx][].send_in_flight = False
            if (
                not self.connections[idx][].recv_in_flight
                and not self.connections[idx][].send_in_flight
            ):
                self._free_connection(idx)
            return

        if op_kind == OP_RECV:
            self._handle_recv(idx, result, flags)
        elif op_kind == OP_SEND:
            self._handle_send(idx, result)

    # --- Submit queue helpers ---

    def _queue_accept(mut self):
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_ACCEPT,
                fd=self.listener_fd,
                conn_id=LISTENER_CONN_ID,
                op_kind=OP_ACCEPT,
            )
        )

    def _queue_recv_multishot(mut self, idx: Int) raises:
        """Submit a multishot recv for the connection — produces one CQE
        per arrival until the multishot ends (peer close, error, or
        ENOBUFS). Idempotent."""
        if self.connections[idx][].recv_in_flight:
            return
        self.connections[idx][].recv_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_RECV_MULTISHOT,
                fd=self.connections[idx][].handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_RECV,
            )
        )

    def _queue_send(mut self, idx: Int) raises:
        if self.connections[idx][].send_in_flight:
            return
        if len(self.connections[idx][].send_buf) == 0:
            return
        self.connections[idx][].send_in_flight = True
        self.pending_submits.append(
            PendingSubmit(
                kind=_SUBMIT_SEND,
                fd=self.connections[idx][].handle.raw(),
                conn_id=self.connections[idx][].conn_id,
                op_kind=OP_SEND,
            )
        )

    # --- Outbound staging ---

    def _stage_send(mut self, idx: Int, var ct: List[UInt8]) raises:
        if len(ct) == 0:
            return
        if self.connections[idx][].send_in_flight:
            # Bulk move into pending (was per-byte append: ~16% self).
            self.connections[idx][].send_pending.extend(ct^)
            return
        self.connections[idx][].send_buf = ct^
        self._queue_send(idx)

    # --- Accept ---

    def _handle_accept(mut self, result: Int32, flags: UInt32) raises:
        var more = (flags & UInt32(2)) != 0

        if result < 0:
            print("h2-bench: accept failed:", result)
            if not more:
                self._queue_accept()
            return

        var client_fd = result
        var conn_id = self.next_conn_id
        self.next_conn_id += 1

        var tls_conn = TlsConnection.new_server(
            SharedLibrary(other=self.tls_lib), self.server_tls_config
        )

        var noneptr = UnsafePointer[NoneType, MutUntrackedOrigin](
            unsafe_from_address=Int(self.state_ptr)
        )
        var h2 = H2CoroServer(
            body_fn=bench_h2_body_fn, extra_data=noneptr
        )

        var client_handle = OwnedHandle(raw=client_fd)
        var conn = H2Conn(
            conn_id=conn_id,
            handle=client_handle^,
            tls=tls_conn^,
            h2=h2^,
        )

        var conn_ptr = _heap_alloc[H2Conn](1).as_unsafe_any_origin()
        conn_ptr.init_pointee_move(conn^)
        self.connections.append(conn_ptr)
        var idx = len(self.connections) - 1

        self._queue_recv_multishot(idx)
        if not more:
            self._queue_accept()

    # --- RECV ---

    def _handle_recv(mut self, idx: Int, result: Int32, flags: UInt32) raises:
        # Multishot lifetime: clear in_flight only when this CQE marks
        # the multishot's end (no F_MORE).
        var multishot_ended = (flags & UInt32(IORING_CQE_F_MORE)) == 0
        if multishot_ended:
            self.connections[idx][].recv_in_flight = False

        # -ENOBUFS: ring transiently empty when data arrived. Kernel ends
        # the multishot; re-arm it. (Should be rare with a 1024-buffer
        # ring; stays defensive in case of a burst.)
        if result == _ENOBUFS:
            if multishot_ended and not self.connections[idx][].closed:
                self._queue_recv_multishot(idx)
            return

        if result < 0:
            self._close_connection(idx)
            return

        # result == 0: peer closed cleanly.
        if result == 0:
            self._close_connection(idx)
            return

        # Successful recv: kernel selected a buffer for us. Decode buf_id
        # from the upper 16 bits of `flags` and read directly from the
        # ring-mapped buffer.
        if (flags & UInt32(IORING_CQE_F_BUFFER)) == 0:
            if multishot_ended:
                self._close_connection(idx)
            return

        var buf_id_u32 = (flags >> UInt32(IORING_CQE_BUFFER_SHIFT)) & UInt32(0xFFFF)
        var buf_id = UInt16(buf_id_u32)
        var n = Int(result)
        var buf_ptr = self.bring.buf_base + (Int(buf_id) * _RECV_BUF_SIZE)

        # TLS receive_data forwards to rustls' read_tls FFI synchronously
        # (the rustls C call deframes + copies into its internal state
        # before returning), so a Span over the ring slot is safe — the
        # kernel can only re-use this buf_id after add_buffer() runs,
        # which we sequence AFTER receive_data returns.
        self.connections[idx][].tls.receive_data(
            Span[UInt8](ptr=buf_ptr, length=n)
        )

        # Userspace store — no SQE, no syscall.
        self.bring.add_buffer(buf_id)

        # If the multishot ended on this CQE, re-arm it.
        if multishot_ended and not self.connections[idx][].closed:
            self._queue_recv_multishot(idx)

        # If TLS has ciphertext to send (handshake reply), stage it
        if self.connections[idx][].tls.wants_write():
            var ct = self.connections[idx][].tls.drain_ciphertext()
            self._stage_send(idx, ct^)

        # Still handshaking — multishot keeps draining.
        if self.connections[idx][].tls.is_handshaking():
            return

        # TLS handshake done — drain plaintext
        var plaintext = self.connections[idx][].tls.drain_plaintext()

        # On first post-TLS recv, flush the H2 server preface
        if self.connections[idx][].phase == _PHASE_TLS_HANDSHAKE:
            var preface_bytes = self.connections[idx][].h2.drain()
            if len(preface_bytes) > 0:
                self.connections[idx][].tls.send_data(Span(preface_bytes))
                var ct2 = self.connections[idx][].tls.drain_ciphertext()
                self._stage_send(idx, ct2^)
            self.connections[idx][].phase = _PHASE_H2_READY

        # Feed plaintext into H2CoroServer
        if len(plaintext) > 0:
            self.connections[idx][].h2.feed(Span(plaintext))
            var h2_out = self.connections[idx][].h2.drain()
            var total = len(h2_out)
            var off = 0
            while off < total:
                var end = off + _TLS_RECORD_CHUNK
                if end > total:
                    end = total
                self.connections[idx][].tls.send_data(Span(h2_out)[off:end])
                var ct = self.connections[idx][].tls.drain_ciphertext()
                if len(ct) > 0:
                    self._stage_send(idx, ct^)
                off = end

    # --- SEND ---

    def _handle_send(mut self, idx: Int, result: Int32) raises:
        self.connections[idx][].send_in_flight = False

        if result < 0:
            self._close_connection(idx)
            return

        var sent = Int(result)
        var buf_len = len(self.connections[idx][].send_buf)
        if sent < buf_len:
            # Partial send — keep unsent tail. Bulk-extend (was per-byte loop).
            var remaining = List[UInt8](capacity=buf_len - sent)
            remaining.extend(Span(self.connections[idx][].send_buf)[sent:buf_len])
            self.connections[idx][].send_buf = remaining^
            self._queue_send(idx)
            return

        self.connections[idx][].send_buf = List[UInt8]()

        if len(self.connections[idx][].send_pending) > 0:
            # Bulk-extend send_buf from a Span over pending; cheaper than
            # the prior per-byte append loop. (A direct field-move
            # through `connections[idx][]` is rejected by Mojo's origin
            # checker; this is a single bulk memcpy instead.)
            var n = len(self.connections[idx][].send_pending)
            var fresh = List[UInt8](capacity=n)
            fresh.extend(Span(self.connections[idx][].send_pending))
            self.connections[idx][].send_pending = List[UInt8]()
            self.connections[idx][].send_buf = fresh^
            self._queue_send(idx)
            return

        if self.connections[idx][].phase == _PHASE_DONE:
            self._close_connection(idx)
            return

    # --- Close ---

    def _close_connection(mut self, idx: Int):
        if self.connections[idx][].closed:
            return
        self.connections[idx][].closed = True
        # If no io_uring operations are in-flight, free immediately.
        # Otherwise, keep the connection alive so the kernel can still
        # access its buffers.  The deferred path in _dispatch will call
        # _free_connection once all outstanding CQEs have drained.
        if (
            not self.connections[idx][].recv_in_flight
            and not self.connections[idx][].send_in_flight
        ):
            self._free_connection(idx)

    def _free_connection(mut self, idx: Int):
        var ptr = self.connections[idx]
        var last = len(self.connections) - 1
        if idx != last:
            self.connections[idx] = self.connections[last]
        _ = self.connections.pop()
        ptr.destroy_pointee()
        ptr.free()


# ---------------------------------------------------------------------------
# _drain_pending_submits
# ---------------------------------------------------------------------------


def _drain_pending_submits(mut loop: CompletionLoop[H2ServerHandler]) raises:
    var submits = loop._handler.pending_submits^
    loop._handler.pending_submits = List[PendingSubmit]()

    for i in range(len(submits)):
        var s = submits[i].copy()
        var token = encode_token(s.conn_id, s.op_kind)

        if s.kind == _SUBMIT_ACCEPT:
            try:
                loop.submit_accept_multishot(s.fd, token)
            except:
                # SQ full — re-queue for next poll iteration.
                loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_RECV_MULTISHOT:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            try:
                loop.submit_recv_multishot(s.fd, _BUF_GROUP_ID, token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                loop._handler.connections[idx][].recv_in_flight = False
                loop._handler.pending_submits.append(s.copy())
        elif s.kind == _SUBMIT_SEND:
            var idx = loop._handler._find_index(s.conn_id)
            if idx < 0:
                continue
            var n = len(loop._handler.connections[idx][].send_buf)
            if n == 0:
                continue
            var raw_addr = Int(
                loop._handler.connections[idx][].send_buf.unsafe_ptr()
            )
            var buf_ptr = UnsafePointer[Int8, StaticConstantOrigin](
                unsafe_from_address=raw_addr
            )
            try:
                loop.submit_send(s.fd, buf_ptr, UInt(n), token)
            except:
                # SQ full — mark not-in-flight so it can be re-queued.
                loop._handler.connections[idx][].send_in_flight = False
                loop._handler.pending_submits.append(s.copy())


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() raises:
    # Load certs
    var certs_dir_opt = getenv_opt("CERTS_DIR")
    var certs_dir: String
    if Bool(certs_dir_opt):
        certs_dir = certs_dir_opt.unsafe_take()
    else:
        certs_dir = String("/certs")

    var static_dir_opt = getenv_opt("STATIC_DIR")
    var static_dir: String
    if Bool(static_dir_opt):
        static_dir = static_dir_opt.unsafe_take()
    else:
        static_dir = String("/data/static")

    var cert_pem = read_file(certs_dir + "/server.crt")
    var key_pem = read_file(certs_dir + "/server.key")

    # TLS setup
    var tls = TlsBackend()
    var shared = tls.shared()
    var server_config = TlsServerConfig(
        shared, Span(cert_pem), Span(key_pem)
    )
    var server_alpn = List[String]()
    server_alpn.append("h2")
    server_config.set_alpn_protocols(server_alpn)

    # Load static files
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
    var state_ptr = _heap_alloc[BenchState](1).as_unsafe_any_origin()
    state_ptr.init_pointee_move(bstate^)

    # Listening socket
    var listener = Socket.tcp_v4()
    # Set SO_REUSEPORT for multi-worker support.
    var reuseport_val_buf = Owned[UInt8](4)
    var reuseport_val = reuseport_val_buf.ptr()
    reuseport_val[0] = 1
    reuseport_val[1] = 0
    reuseport_val[2] = 0
    reuseport_val[3] = 0
    var rp_rc = external_call["setsockopt", Int32](
        listener.raw(), Int32(1), SO_REUSEPORT, reuseport_val, Int32(4)
    )
    # Keep reuseport_val alive across the setsockopt FFI call above.
    _ = reuseport_val_buf
    if rp_rc < 0:
        print("h2-bench: warning: setsockopt(SO_REUSEPORT) failed")
    var bind_addr = SocketAddrV4(0, 0, 0, 0, port=_LISTEN_PORT)
    listener.bind(bind_addr)
    listener.listen(Backlog.DEFAULT)
    var listener_fd = listener.raw()

    var worker_id_opt = getenv_opt("BENCH_WORKER_ID")
    var prefix: String
    if worker_id_opt.__bool__():
        prefix = "[h2-w" + worker_id_opt.value() + "] "
    else:
        prefix = ""
    print(prefix + "h2-bench: listening on https://127.0.0.1:" + String(_LISTEN_PORT))

    # Allocate the per-worker buffer pool (data buffers; the ring
    # metadata is allocated separately by register_buf_ring).
    var buf_base = _heap_alloc[UInt8](_BUF_RING_SIZE * _RECV_BUF_SIZE).as_unsafe_any_origin()

    # Build handler with an empty BufRing, then move-replace after the
    # CompletionLoop is built (since register_buf_ring is on the loop).
    var handler = H2ServerHandler(
        listener_fd=listener_fd,
        tls_lib=tls.shared(),
        server_tls_config=server_config^,
        state_ptr=state_ptr,
        bring=BufRing(),
    )
    var loop = CompletionLoop[H2ServerHandler](handler^, sq_entries=4096)

    # Register the buffer ring with the kernel and move the resulting
    # BufRing handle into the handler. From here on, returning a buffer
    # is a userspace store (BufRing.add_buffer).
    var bring = loop.register_buf_ring(
        buf_base,
        buf_size=UInt32(_RECV_BUF_SIZE),
        count=_BUF_RING_SIZE,
        group_id=_BUF_GROUP_ID,
    )
    loop._handler.bring = bring^

    loop.submit_accept_multishot(listener_fd, encode_token(LISTENER_CONN_ID, OP_ACCEPT))

    while True:
        loop.poll(wait_nr=1)
        _drain_pending_submits(loop)
        _ = listener
