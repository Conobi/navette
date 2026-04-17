# H3CoroServer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `H3CoroServer` — a coroutine-based HTTP/3 server adapter that mirrors `H2CoroServer` (M2.6) but drives `H3Connection` over QUIC datagrams instead of TCP bytes.
**Architecture:** `H3CoroServer` wraps a `QuicConnection` (creating `H3Connection.server(quic^)` internally), holds a `CoroBody` function pointer, and maintains a `Dict[Int, _CoroStreamPtr]` of heap-allocated per-stream contexts. Each incoming request spawns a `CoroHandle`; events resume it; `_drain_responses` flushes queued response data back through `H3Connection`.
**Tech Stack:** Mojo 0.26.2, `boucle.stackful` (CoroHandle/CoroYielder), `src/h3/` (H3Connection, H3Event), `src/http/` (RecvBody, ResponseWriter, Capabilities), `src/quic/connection` (QuicConnection).

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `src/h3/h3_coro_server.mojo` | Create | CoroStreamCtx, _CoroStreamPtr, _free_stream, H3CoroServer |
| `tests/test_h3_coro_server.mojo` | Create | All 6 tests + coroutine bodies + pump helper |
| `src/h3/__init__.mojo` | Modify | Add H3CoroServer export |
| `scripts/run_tests.sh` | Modify | Add test_h3_coro_server with boucle include |

---

## Key patterns (read before implementing)

- **Pop-before-free**: `_ = self._streams.pop(sid)` ALWAYS before `_free_stream(ctx_ptr)`. No exceptions.
- **take_pointee discipline**: after `ctx_ptr.take_pointee()`, slot is uninit; must call `ctx_ptr.init_pointee_move(ctx^)` or `ptr.free()` — never access the slot again otherwise.
- **Insert before first resume**: in `_on_request`, insert into `_streams` BEFORE calling `_resume_and_handle_error` so `_drain_responses` can find the stream if the coroutine yields immediately.
- **ev.fin in _on_request**: if `ev.fin == True` (bodyless GET), set `ctx.request_ended = True` + `ctx.recv_body._set_end()` before first resume.
- **No flow-control ACK**: QUIC FC is internal; never call `acknowledge_received_data`.
- **Dict copy-mutate-write-back**: access Dict entries via `ptr()` + `take_pointee()` → mutate → `init_pointee_move(ctx^)`.
- **H3Event access**: `ev.kind`, `ev.stream_id: UInt64`, `ev.fields: List[QpackHeaderField]`, `ev.data: List[UInt8]`, `ev.fin: Bool`, `ev.error_code: UInt64`.
- **H3Event constants**: `H3Event.HEADERS_RECEIVED=3`, `DATA_RECEIVED=4`, `STREAM_ENDED=5`, `STREAM_RESET=6`, `GOAWAY_RECEIVED=7`, `CONNECTION_CLOSED=8`.
- **CoroBody signature**: `fn (mut CoroYielder) raises -> None`. Access ctx from body: `UnsafePointer[CoroStreamCtx, MutAnyOrigin](unsafe_from_address=Int(y.user_data()))`.
- **Loopback test setup**: inlined in each test (no helper function due to Mojo Tuple move restriction). Reuse pattern from `tests/test_h3_e2e.mojo` exactly.
- **extra_data**: heap-allocate via `_heap_alloc[Int](1)`, init, pass address as `UnsafePointer[NoneType, MutExternalOrigin](unsafe_from_address=Int(ptr))`. Free after test.

---

### Task 0: H3CoroServer module + simple GET test

**Files:**
- Create: `src/h3/h3_coro_server.mojo`
- Create: `tests/test_h3_coro_server.mojo`

- [ ] **Step 1: Write failing test**

Create `tests/test_h3_coro_server.mojo`:

```mojo
# tests/test_h3_coro_server.mojo
#
# Tests for H3CoroServer (M5c).
# Run with:
#   uv run mojo run -I . -I conformance -I "$HOME/Projets/perso/boucle" -D ASSERT=all tests/test_h3_coro_server.mojo

from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.python import Python, PythonObject

from boucle.stackful import CoroYielder

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection
from src.quic.trans_param import TransportParams, default_transport_params
from src.h3.connection import H3Connection, H3Event
from src.h3.h3_coro_server import H3CoroServer, CoroStreamCtx
from src.h3.qpack import QpackHeaderField
from src.http.handler import RecvBody, ResponseWriter, StreamError, Capabilities
from src.http.headers import Headers
from src.http.body import BodyFrame
from src.http.status import StatusCode
from tests._test_util import assert_true, assert_equal_int


# ── Shared loopback helpers ──────────────────────────────────────────────


def py_bytes_to_mojo(raw: PythonObject) raises -> List[UInt8]:
    var builtins = Python.import_module("builtins")
    var result = List[UInt8]()
    for i in range(Int(py=builtins.len(raw))):
        result.append(UInt8(Int(py=raw[i])))
    return result^


def generate_ephemeral_cert() raises -> Tuple[List[UInt8], List[UInt8]]:
    var ec_mod = Python.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    var x509_mod = Python.import_module("cryptography.x509")
    var oid_mod = Python.import_module("cryptography.x509.oid")
    var ser_mod = Python.import_module("cryptography.hazmat.primitives.serialization")
    var hash_mod = Python.import_module("cryptography.hazmat.primitives.hashes")
    var dt_mod = Python.import_module("datetime")
    var builtins = Python.import_module("builtins")
    var py_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    var name_attrs = builtins.list()
    name_attrs.append(x509_mod.NameAttribute(oid_mod.NameOID.COMMON_NAME, "localhost"))
    var subject = x509_mod.Name(name_attrs)
    var san_list = builtins.list()
    san_list.append(x509_mod.DNSName("localhost"))
    var py_cert = (
        x509_mod.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(py_key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(dt_mod.datetime(2024, 1, 1))
        .not_valid_after(dt_mod.datetime(2034, 1, 1))
        .add_extension(
            x509_mod.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(py_key, hash_mod.SHA256())
    )
    var cert_bytes = py_bytes_to_mojo(py_cert.public_bytes(ser_mod.Encoding.PEM))
    var key_bytes = py_bytes_to_mojo(
        py_key.private_bytes(ser_mod.Encoding.PEM, ser_mod.PrivateFormat.PKCS8, ser_mod.NoEncryption())
    )
    return (cert_bytes^, key_bytes^)


def _h3_default_params() -> TransportParams:
    var p = default_transport_params()
    p.max_idle_timeout = UInt64(30_000)
    p.initial_max_data = UInt64(1_048_576)
    p.initial_max_stream_data_bidi_local = UInt64(65_536)
    p.initial_max_stream_data_bidi_remote = UInt64(65_536)
    p.initial_max_streams_bidi = UInt64(100)
    p.initial_max_streams_uni = UInt64(100)
    return p^


def _make_lib_and_configs() raises -> Tuple[UInt64, Int32, Int32]:
    """Return (lib_addr, server_config_handle, client_config_handle)."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var ck = generate_ephemeral_cert()
    var cert_bytes = ck[0].copy()
    var key_bytes = ck[1].copy()
    var cert_ptr = cert_bytes.unsafe_ptr().as_any_origin()
    var key_ptr = key_bytes.unsafe_ptr().as_any_origin()
    var cert_len = Int32(len(cert_bytes))
    var key_len = Int32(len(key_bytes))
    var alpn_ptr = _heap_alloc[UInt8](2).as_any_origin()
    alpn_ptr[0] = UInt8(ord("h"))
    alpn_ptr[1] = UInt8(ord("3"))
    var alpn_len = Int32(2)
    var srv_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_server_config_new(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len, srv_cfg_ptr)
    var srv_cfg = srv_cfg_ptr[0]
    srv_cfg_ptr.free()
    var cli_cfg_ptr = _heap_alloc[Int32](1).as_any_origin()
    _ = lib_ptr[].quic_client_config_with_ca(cert_ptr, cert_len, alpn_ptr, alpn_len, cli_cfg_ptr)
    var cli_cfg = cli_cfg_ptr[0]
    cli_cfg_ptr.free()
    alpn_ptr.free()
    return (lib_addr, srv_cfg, cli_cfg)


def _pump_coro_client(
    mut server: H3CoroServer,
    mut client: H3Connection,
    mut now: UInt64,
    rounds: Int = 5,
) raises -> UInt64:
    """Exchange QUIC datagrams between H3CoroServer and client H3Connection."""
    for _ in range(rounds):
        now += UInt64(10_000)
        var s_dgs = server.drain_datagrams(now)
        for i in range(len(s_dgs)):
            try:
                client.feed_datagram(Span(s_dgs[i]), now)
            except:
                pass
        var c_dgs = client.drain_datagrams(now)
        for i in range(len(c_dgs)):
            try:
                server.feed_datagram(Span(c_dgs[i]), now)
            except:
                pass
    return now


# ── Coroutine bodies ─────────────────────────────────────────────────────


fn _simple_get_body(mut y: CoroYielder) raises:
    """Respond immediately with 200 OK + 'hello' body."""
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), Headers())
    var body = List[UInt8]()
    var src = String("hello").as_bytes()
    for i in range(len(src)):
        body.append(src[i])
    _ = ctx_ptr[].resp_writer.try_send_body(BodyFrame.data(body^))
    ctx_ptr[].resp_writer.end()


# ── Tests ────────────────────────────────────────────────────────────────


def test_h3_coro_simple_get() raises:
    """GET / → coroutine responds immediately with 200 OK + 'hello'."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    # Inline loopback setup (Tuple move restriction prevents helper)
    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    # Handshake + H3 bootstrap
    now = _pump_coro_client(server, client, now, 50)

    # Send GET / with fin=True (no body)
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "GET"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, True)  # fin=True

    now = _pump_coro_client(server, client, now, 20)

    # Collect response events
    var got_200 = False
    var body_bytes = List[UInt8]()
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
        elif e.kind == H3Event.DATA_RECEIVED:
            for i in range(len(e.data)):
                body_bytes.append(e.data[i])

    assert_true(got_200, "client did not receive 200 OK")
    var body_str = String(unsafe_from_utf8=body_bytes)
    assert_true(body_str == "hello", "response body expected 'hello', got: " + body_str)
    print("  test_h3_coro_simple_get: PASS")


def main() raises:
    print("=== test_h3_coro_server ===")
    test_h3_coro_simple_get()
    print("All H3CoroServer tests passed.")
```

- [ ] **Step 2: Verify it fails**

Run: `uv run mojo run -I . -I conformance -I "$HOME/Projets/perso/boucle" -D ASSERT=all tests/test_h3_coro_server.mojo`

Expected: FAIL — compilation error: `cannot find 'h3_coro_server' in 'src.h3'`

- [ ] **Step 3: Write the implementation**

Create `src/h3/h3_coro_server.mojo`:

```mojo
# src/h3/h3_coro_server.mojo
#
# HTTP/3 server-side coroutine adapter. Sans-I/O: feed inbound QUIC datagrams,
# drain outbound datagrams. Translates H3Connection events into per-stream
# stackful coroutines (boucle.stackful) instead of StreamHandler callbacks.
# (M5c)

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from boucle.stackful import CoroHandle, CoroYielder, CoroBody

from src.quic.connection import QuicConnection
from src.h3.connection import H3Connection, H3Event
from src.h3.error import H3_REQUEST_CANCELLED
from src.h3.qpack import QpackHeaderField
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.request import Request
from src.http.headers import Headers
from src.http.method import Method
from src.http.version import Version
from src.http.body import BodyFrame
from src.http.status import StatusCode


# ---------------------------------------------------------------------------
# CoroStreamCtx — per-stream shared state (heap-allocated, move-only)
# ---------------------------------------------------------------------------


struct CoroStreamCtx(Movable):
    """Per-stream context for coroutine-based H3 serving. Heap-allocated so
    both the adapter and the coroutine body can access it via pointer.
    No unacked_bytes field — QUIC handles flow control internally."""

    var request:        Request
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var caps:           Capabilities
    var stream_id:      UInt64
    var extra_data:     UnsafePointer[NoneType, MutExternalOrigin]
    var coro_addr:      UInt64   # address of heap-allocated CoroHandle (0 = none)
    var request_ended:  Bool
    var response_ended: Bool
    var headers_sent:   Bool

    def __init__(
        out self,
        var request: Request,
        caps: Capabilities,
        stream_id: UInt64,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin],
    ):
        self.request = request^
        self.recv_body = RecvBody()
        self.resp_writer = ResponseWriter()
        self.caps = Capabilities(other=caps)
        self.stream_id = stream_id
        self.extra_data = extra_data
        self.coro_addr = UInt64(0)
        self.request_ended = False
        self.response_ended = False
        self.headers_sent = False

    def __init__(out self, *, deinit take: Self):
        self.request = take.request^
        self.recv_body = take.recv_body^
        self.resp_writer = take.resp_writer^
        self.caps = take.caps^
        self.stream_id = take.stream_id
        self.extra_data = take.extra_data
        self.coro_addr = take.coro_addr
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent

    def coro_ptr(self) -> UnsafePointer[CoroHandle, MutAnyOrigin]:
        return UnsafePointer[CoroHandle, MutAnyOrigin](
            unsafe_from_address=Int(self.coro_addr)
        )


# ---------------------------------------------------------------------------
# _CoroStreamPtr — thin Copyable+Movable wrapper for Dict storage
# ---------------------------------------------------------------------------


struct _CoroStreamPtr(Copyable, Movable):
    var addr: UInt64

    def __init__(out self, addr: UInt64):
        self.addr = addr

    def __init__(out self, *, other: Self):
        self.addr = other.addr

    def __init__(out self, *, deinit take: Self):
        self.addr = take.addr

    def ptr(self) -> UnsafePointer[CoroStreamCtx, MutAnyOrigin]:
        return UnsafePointer[CoroStreamCtx, MutAnyOrigin](
            unsafe_from_address=Int(self.addr)
        )


# ---------------------------------------------------------------------------
# _free_stream — single cleanup path for CoroHandle + CoroStreamCtx
# ---------------------------------------------------------------------------


def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    """Free both the CoroHandle (if allocated) and the CoroStreamCtx.
    ALWAYS call _streams.pop(sid) BEFORE calling this function."""
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()


# ---------------------------------------------------------------------------
# H3CoroServer — server adapter using per-stream coroutines
# ---------------------------------------------------------------------------


struct H3CoroServer(Movable):
    """Drive per-stream coroutines from an HTTP/3 H3Connection. Sans-I/O:
    caller feeds inbound QUIC datagrams via `feed_datagram` and drains
    outbound datagrams via `drain_datagrams`. Each new request spawns a
    stackful coroutine that is resumed as events arrive."""

    var _h3:         H3Connection
    var _body_fn:    CoroBody
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _streams:    Dict[Int, _CoroStreamPtr]

    # --- Constructors -------------------------------------------------------

    def __init__(
        out self,
        *,
        var quic: QuicConnection,
        body_fn: CoroBody,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        self._h3 = H3Connection.server(quic^)
        self._body_fn = body_fn
        self._extra_data = extra_data
        self._streams = Dict[Int, _CoroStreamPtr]()

    def __init__(out self, *, deinit take: Self):
        self._h3 = take._h3^
        self._body_fn = take._body_fn
        self._extra_data = take._extra_data
        self._streams = take._streams^

    fn __del__(deinit self):
        """Destroy all heap-allocated stream contexts. Push connection-closed
        error into suspended coroutines so they can unwind cleanly."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            try:
                var ctx_ptr = self._streams[keys[i]].ptr()
                var ctx = ctx_ptr.take_pointee()
                ctx.recv_body._set_error(StreamError.connection_closed())
                ctx_ptr.init_pointee_move(ctx^)
                if ctx_ptr[].coro_addr != UInt64(0):
                    var coro_p = ctx_ptr[].coro_ptr()
                    if coro_p[].can_resume():
                        try:
                            coro_p[].resume()
                        except:
                            pass
                _free_stream(ctx_ptr)
            except:
                pass

    # --- Transport API -------------------------------------------------------

    def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
        """Feed one inbound QUIC datagram. Dispatches H3 events and drains
        pending response data."""
        self._h3.feed_datagram(data, now)
        self._dispatch_h3_events(now)
        if self._h3.is_established():
            self._drain_responses(now)

    def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
        """Return outbound QUIC datagrams accumulated since last call."""
        return self._h3.drain_datagrams(now)

    def should_close(self) -> Bool:
        """True when the H3 connection has reached terminal state."""
        return self._h3.is_closed()

    def send_goaway(mut self, last_stream_id: UInt64) raises:
        """Send GOAWAY via the underlying H3Connection."""
        self._h3.send_goaway(last_stream_id)

    # --- Internal: helpers --------------------------------------------------

    def _has_stream(self, sid: Int) -> Bool:
        return sid in self._streams

    def _resume_and_handle_error(mut self, stream_id: Int) raises:
        """Resume a stream's coroutine. On raise, send RST_STREAM and free."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].coro_addr == UInt64(0):
            return
        var coro_p = ctx_ptr[].coro_ptr()
        if not coro_p[].can_resume():
            return
        try:
            coro_p[].resume()
        except:
            try:
                self._h3.reset_stream(UInt64(stream_id), H3_REQUEST_CANCELLED)
            except:
                pass
            self._cleanup_stream(stream_id)
            return
        if coro_p[].is_done():
            self._maybe_cleanup_stream(stream_id)

    def _cleanup_stream(mut self, stream_id: Int) raises:
        """Unconditionally free stream context. Pop BEFORE free."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        _ = self._streams.pop(stream_id)   # pop FIRST
        _free_stream(ctx_ptr)

    def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
        """Free stream context if both request and response sides are done."""
        if not self._has_stream(stream_id):
            return
        var ctx_ptr = self._streams[stream_id].ptr()
        if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
            _ = self._streams.pop(stream_id)   # pop FIRST
            _free_stream(ctx_ptr)

    # --- Internal: event dispatch -------------------------------------------

    def _dispatch_h3_events(mut self, now: UInt64) raises:
        """Poll and dispatch all pending H3 events."""
        while True:
            var ev_opt = self._h3.poll_event()
            if not ev_opt:
                break
            var ev = ev_opt.unsafe_take()
            if ev.kind == H3Event.HEADERS_RECEIVED:
                if Int(ev.stream_id) not in self._streams:
                    self._on_request(ev)
                else:
                    self._on_trailers(ev)
            elif ev.kind == H3Event.DATA_RECEIVED:
                self._on_data(ev)
            elif ev.kind == H3Event.STREAM_ENDED:
                self._on_stream_ended(ev)
            elif ev.kind == H3Event.STREAM_RESET:
                self._on_stream_reset(ev)
            elif ev.kind == H3Event.GOAWAY_RECEIVED or ev.kind == H3Event.CONNECTION_CLOSED:
                self._on_goaway(ev)

    def _on_request(mut self, ev: H3Event) raises:
        """First HEADERS_RECEIVED: parse pseudo-fields into Request, allocate
        CoroStreamCtx + CoroHandle on heap, insert into _streams, first resume.
        If ev.fin==True (bodyless GET), set request_ended + recv_body._set_end()."""
        var method_str = String("GET")
        var path_str = String("/")
        var authority_str = String("")
        var user_headers = Headers()

        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            var value = ev.fields[i].value
            if name == ":method":
                method_str = value
            elif name == ":path":
                path_str = value
            elif name == ":authority":
                authority_str = value
            elif name == ":scheme":
                pass
            else:
                user_headers.add(name, value)

        var req_headers = Headers()
        if authority_str != "":
            req_headers.add("host", authority_str)
        for i in range(len(user_headers)):
            req_headers.add(user_headers.name_at(i), user_headers.value_at(i))

        var req = Request(
            method=Method.custom(method_str),
            target=path_str,
            version=Version.http_3(),
            headers=req_headers^,
        )

        var ctx_ptr = _heap_alloc[CoroStreamCtx](1).as_any_origin()
        var ctx = CoroStreamCtx(
            request=req^,
            caps=Capabilities.for_h3(),
            stream_id=ev.stream_id,
            extra_data=self._extra_data,
        )

        # FIN on HEADERS = bodyless request (e.g. GET) — mark ended immediately
        if ev.fin:
            ctx.request_ended = True
            ctx.recv_body._set_end()

        ctx_ptr.init_pointee_move(ctx^)

        # Allocate CoroHandle on heap
        var user_data = UnsafePointer[NoneType, MutExternalOrigin](
            unsafe_from_address=Int(ctx_ptr)
        )
        var coro_heap = _heap_alloc[CoroHandle](1).as_any_origin()
        var coro = CoroHandle(self._body_fn, user_data)
        coro_heap.init_pointee_move(coro^)
        ctx_ptr[].coro_addr = UInt64(Int(coro_heap))

        # Insert BEFORE first resume so _drain_responses can find the stream
        var sid = Int(ev.stream_id)
        self._streams[sid] = _CoroStreamPtr(UInt64(Int(ctx_ptr)))

        self._resume_and_handle_error(sid)

    def _on_trailers(mut self, ev: H3Event) raises:
        """Second HEADERS_RECEIVED on an open stream = trailers.
        Push as BodyFrame.trailers (skip pseudo-headers). Resume coroutine."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var trailer_headers = Headers()
        for i in range(len(ev.fields)):
            var name = ev.fields[i].name
            if not name.startswith(":"):
                trailer_headers.add(name, ev.fields[i].value)
        ctx.recv_body._push(BodyFrame.trailers(trailer_headers^))
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_and_handle_error(sid)

    def _on_data(mut self, ev: H3Event) raises:
        """DATA_RECEIVED: push data into RecvBody, resume coroutine.
        No flow-control ACK — QUIC handles FC internally."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var data_copy = List[UInt8](copy=ev.data)
        ctx.recv_body._push(BodyFrame.data(data_copy^))
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_and_handle_error(sid)

    def _on_stream_ended(mut self, ev: H3Event) raises:
        """STREAM_ENDED: mark body ended, resume coroutine."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        if ctx_ptr[].request_ended:
            return
        var ctx = ctx_ptr.take_pointee()
        ctx.request_ended = True
        ctx.recv_body._set_end()
        ctx_ptr.init_pointee_move(ctx^)
        self._resume_and_handle_error(sid)
        self._maybe_cleanup_stream(sid)

    def _on_stream_reset(mut self, ev: H3Event) raises:
        """STREAM_RESET: push error, resume once, pop BEFORE free."""
        var sid = Int(ev.stream_id)
        if not self._has_stream(sid):
            return
        var ctx_ptr = self._streams[sid].ptr()
        var ctx = ctx_ptr.take_pointee()
        var err = StreamError.rst_stream(UInt32(ev.error_code))
        ctx.recv_body._set_error(StreamError(other=err))
        ctx_ptr.init_pointee_move(ctx^)
        if ctx_ptr[].coro_addr != UInt64(0):
            var coro_p = ctx_ptr[].coro_ptr()
            if coro_p[].can_resume():
                try:
                    coro_p[].resume()
                except:
                    pass
        _ = self._streams.pop(sid)   # pop BEFORE free
        _free_stream(ctx_ptr)

    def _on_goaway(mut self, ev: H3Event) raises:
        """GOAWAY_RECEIVED / CONNECTION_CLOSED: broadcast error to all open
        streams, resume each once, pop BEFORE free for each."""
        var keys = List[Int]()
        for key in self._streams.keys():
            keys.append(key)
        for i in range(len(keys)):
            var sid = keys[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            ctx.recv_body._set_error(StreamError.connection_closed())
            ctx_ptr.init_pointee_move(ctx^)
            if ctx_ptr[].coro_addr != UInt64(0):
                var coro_p = ctx_ptr[].coro_ptr()
                if coro_p[].can_resume():
                    try:
                        coro_p[].resume()
                    except:
                        pass
            _ = self._streams.pop(sid)   # pop BEFORE free
            _free_stream(ctx_ptr)

    # --- Internal: response drain -------------------------------------------

    def _drain_responses(mut self, now: UInt64) raises:
        """Drain pending response data from stream contexts into H3Connection.
        Snapshot stream IDs first to avoid mutating dict while iterating."""
        var stream_ids = List[Int]()
        for key in self._streams.keys():
            stream_ids.append(key)
        for i in range(len(stream_ids)):
            var sid = stream_ids[i]
            if not self._has_stream(sid):
                continue
            var ctx_ptr = self._streams[sid].ptr()
            var ctx = ctx_ptr.take_pointee()
            if ctx.response_ended:
                ctx_ptr.init_pointee_move(ctx^)
                self._maybe_cleanup_stream(sid)
                continue
            if not ctx.headers_sent and not ctx.resp_writer._has_status():
                ctx_ptr.init_pointee_move(ctx^)
                continue
            # Send response headers
            if not ctx.headers_sent and ctx.resp_writer._has_status():
                var status_opt = ctx.resp_writer._take_status()
                var headers_opt = ctx.resp_writer._take_headers()
                var status = status_opt.unsafe_take()
                var resp_headers: Headers
                if Bool(headers_opt):
                    resp_headers = headers_opt.unsafe_take()
                else:
                    resp_headers = Headers()
                var fields = List[QpackHeaderField]()
                fields.append(QpackHeaderField(":status", String(Int(status.code()))))
                for j in range(len(resp_headers)):
                    fields.append(QpackHeaderField(resp_headers.name_at(j), resp_headers.value_at(j)))
                try:
                    self._h3.send_headers(UInt64(sid), fields, False)
                except:
                    pass
                ctx.headers_sent = True
            # Drain body frames
            while True:
                var f_opt = ctx.resp_writer._pop_body_frame()
                if not Bool(f_opt):
                    break
                var f = f_opt.unsafe_take()
                if f.is_data():
                    var data_copy = f.data().copy()
                    try:
                        self._h3.send_data(UInt64(sid), data_copy^, False)
                    except:
                        pass
                elif f.is_end():
                    try:
                        self._h3.send_data(UInt64(sid), List[UInt8](), True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
                elif f.is_trailers():
                    var trailer_hdrs = f.trailers().copy()
                    var t_fields = List[QpackHeaderField]()
                    for j in range(len(trailer_hdrs)):
                        t_fields.append(QpackHeaderField(trailer_hdrs.name_at(j), trailer_hdrs.value_at(j)))
                    try:
                        self._h3.send_headers(UInt64(sid), t_fields, True)
                    except:
                        pass
                    ctx.response_ended = True
                    break
            ctx_ptr.init_pointee_move(ctx^)
            self._maybe_cleanup_stream(sid)
```

- [ ] **Step 4: Verify it passes**

Run: `uv run mojo run -I . -I conformance -I "$HOME/Projets/perso/boucle" -D ASSERT=all tests/test_h3_coro_server.mojo`

Expected: `test_h3_coro_simple_get: PASS` and `All H3CoroServer tests passed.`

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message: `feat: H3CoroServer coroutine adapter with simple GET test`

---

### Task 1: Remaining 4 tests

**Files:**
- Modify: `tests/test_h3_coro_server.mojo`

- [ ] **Step 1: Write 4 additional coroutine bodies and tests**

Add to `tests/test_h3_coro_server.mojo` — insert new coroutine bodies after `_simple_get_body`, then the 4 test functions before `main()`, and add all 4 calls to `main()`:

**New coroutine bodies (add after `_simple_get_body`):**

```mojo
fn _echo_body_coro(mut y: CoroYielder) raises:
    """Read full request body (yielding when empty), respond with body length."""
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    var total = 0
    while True:
        var frame = ctx_ptr[].recv_body.try_read()
        if not frame:
            y.yield_to_caller()
            continue
        var f = frame.unsafe_take()
        if f.is_data():
            total += len(f.data())
        elif f.is_end():
            break
        elif f.is_error():
            return
    var resp_headers = Headers()
    resp_headers.add("x-body-length", String(total))
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), resp_headers^)
    ctx_ptr[].resp_writer.end()


fn _trailer_check_coro(mut y: CoroYielder) raises:
    """Read body frames including trailers; write 1 to extra_data if x-custom-trailer seen."""
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    var found_ptr = UnsafePointer[Int, MutAnyOrigin](
        unsafe_from_address=Int(ctx_ptr[].extra_data)
    )
    while True:
        var frame = ctx_ptr[].recv_body.try_read()
        if not frame:
            y.yield_to_caller()
            continue
        var f = frame.unsafe_take()
        if f.is_trailers():
            var hdrs = f.trailers()
            for i in range(len(hdrs)):
                if hdrs.name_at(i) == "x-custom-trailer":
                    found_ptr[] = 1
            break
        elif f.is_end():
            break
        elif f.is_error():
            return
    ctx_ptr[].resp_writer.send_status(StatusCode.ok(), Headers())
    ctx_ptr[].resp_writer.end()


fn _blocking_body_coro(mut y: CoroYielder) raises:
    """Block waiting for body data; write 42 to extra_data on error (RST or GOAWAY)."""
    var ctx_ptr = UnsafePointer[CoroStreamCtx, MutAnyOrigin](
        unsafe_from_address=Int(y.user_data())
    )
    var signal_ptr = UnsafePointer[Int, MutAnyOrigin](
        unsafe_from_address=Int(ctx_ptr[].extra_data)
    )
    while True:
        var frame = ctx_ptr[].recv_body.try_read()
        if not frame:
            y.yield_to_caller()
            continue
        var f = frame.unsafe_take()
        if f.is_error():
            signal_ptr[] = 42
            return
        elif f.is_end():
            return
```

**New test functions (add before `main()`):**

```mojo
def test_h3_coro_post_with_body() raises:
    """POST /upload with body 'hello world' → server echoes body length 11."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_echo_body_coro)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/upload"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)  # no fin yet

    var body_data = List[UInt8]()
    var src = String("hello world").as_bytes()
    for i in range(len(src)):
        body_data.append(src[i])
    client.send_data(stream_id, body_data^, True)  # fin=True with body

    now = _pump_coro_client(server, client, now, 30)

    var got_200 = False
    var got_body_length = String("")
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.HEADERS_RECEIVED:
            for i in range(len(e.fields)):
                if e.fields[i].name == ":status" and e.fields[i].value == "200":
                    got_200 = True
                elif e.fields[i].name == "x-body-length":
                    got_body_length = e.fields[i].value

    assert_true(got_200, "did not receive 200 OK")
    assert_true(got_body_length == "11", "expected body length 11, got: " + got_body_length)
    print("  test_h3_coro_post_with_body: PASS")


def test_h3_coro_trailers() raises:
    """POST with trailers → coroutine reads trailer header x-custom-trailer."""
    var found_ptr = _heap_alloc[Int](1).as_any_origin()
    found_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(found_ptr)
    )

    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_trailer_check_coro, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    var body_data = List[UInt8]()
    body_data.append(UInt8(65))  # 'A'
    client.send_data(stream_id, body_data^, False)

    # Send trailers (second HEADERS frame, fin=True)
    var trailer_fields = List[QpackHeaderField]()
    trailer_fields.append(QpackHeaderField("x-custom-trailer", "test"))
    client.send_headers(stream_id, trailer_fields, True)

    now = _pump_coro_client(server, client, now, 30)

    var found_val = found_ptr[]
    found_ptr.destroy_pointee()
    found_ptr.free()
    assert_equal_int(found_val, 1, "trailer header x-custom-trailer not received by coroutine")
    print("  test_h3_coro_trailers: PASS")


def test_h3_coro_rst_stream() raises:
    """Client resets a stream → coroutine receives StreamError (signal=42)."""
    var signal_ptr = _heap_alloc[Int](1).as_any_origin()
    signal_ptr.init_pointee_move(Int(0))
    var extra = UnsafePointer[NoneType, MutExternalOrigin](
        unsafe_from_address=Int(signal_ptr)
    )

    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_blocking_body_coro, extra_data=extra)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

    # Send POST without fin — coroutine yields waiting for body
    var stream_id = client.open_bidi_stream()
    var req_fields = List[QpackHeaderField]()
    req_fields.append(QpackHeaderField(":method", "POST"))
    req_fields.append(QpackHeaderField(":path", "/"))
    req_fields.append(QpackHeaderField(":scheme", "https"))
    req_fields.append(QpackHeaderField(":authority", "localhost"))
    client.send_headers(stream_id, req_fields, False)

    now = _pump_coro_client(server, client, now, 10)

    # Client resets the stream
    client.reset_stream(stream_id, UInt64(0x010c))   # H3_REQUEST_CANCELLED

    now = _pump_coro_client(server, client, now, 20)

    var signal_val = signal_ptr[]
    signal_ptr.destroy_pointee()
    signal_ptr.free()
    assert_equal_int(signal_val, 42, "coroutine did not receive stream reset error")
    print("  test_h3_coro_rst_stream: PASS")


def test_h3_coro_goaway() raises:
    """Server sends GOAWAY → client receives GOAWAY_RECEIVED event."""
    var configs = _make_lib_and_configs()
    var lib_addr = configs[0]
    var srv_cfg = configs[1]
    var cli_cfg = configs[2]
    var params = _h3_default_params()
    var now = UInt64(1_000_000)

    var client_quic = QuicConnection.client(lib_addr, cli_cfg, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var client_dcid = List[UInt8](copy=client_quic.initial_dcid)
    var server_quic = QuicConnection.server(
        lib_addr, srv_cfg, params, Span(orig_dcid), Span(client_dcid), now,
    )
    var server = H3CoroServer(quic=server_quic^, body_fn=_simple_get_body)
    var client = H3Connection.client(client_quic^)

    now = _pump_coro_client(server, client, now, 50)

    # Server sends GOAWAY before any request
    server.send_goaway(UInt64(0))
    now = _pump_coro_client(server, client, now, 20)

    # Client should receive GOAWAY_RECEIVED event
    var got_goaway = False
    while True:
        var ev = client.poll_event()
        if not ev:
            break
        var e = ev.unsafe_take()
        if e.kind == H3Event.GOAWAY_RECEIVED:
            got_goaway = True

    assert_true(got_goaway, "client did not receive GOAWAY from server")
    print("  test_h3_coro_goaway: PASS")
```

**Update `main()` to include all 5 tests:**

```mojo
def main() raises:
    print("=== test_h3_coro_server ===")
    test_h3_coro_simple_get()
    test_h3_coro_post_with_body()
    test_h3_coro_trailers()
    test_h3_coro_rst_stream()
    test_h3_coro_goaway()
    print("All H3CoroServer tests passed.")
```

- [ ] **Step 2: Verify all 5 tests pass**

Run: `uv run mojo run -I . -I conformance -I "$HOME/Projets/perso/boucle" -D ASSERT=all tests/test_h3_coro_server.mojo`

Expected:
```
=== test_h3_coro_server ===
  test_h3_coro_simple_get: PASS
  test_h3_coro_post_with_body: PASS
  test_h3_coro_trailers: PASS
  test_h3_coro_rst_stream: PASS
  test_h3_coro_goaway: PASS
All H3CoroServer tests passed.
```

If any test fails, fix the production code in `src/h3/h3_coro_server.mojo` until all pass.

- [ ] **Step 3: Commit**

Use the `commit-smart` skill. Message: `test: add POST body, trailers, RST, and GOAWAY tests for H3CoroServer`

---

### Task 2: Export + test runner

**Files:**
- Modify: `src/h3/__init__.mojo:54`
- Modify: `scripts/run_tests.sh`

- [ ] **Step 1: Add H3CoroServer export**

In `src/h3/__init__.mojo`, add after line 54 (`from src.h3.h3_session import H3Session`):

```mojo
from src.h3.h3_coro_server import H3CoroServer
```

- [ ] **Step 2: Add test_h3_coro_server to run_tests.sh**

In `scripts/run_tests.sh`, find the line:
```bash
    test_h2_coro_server
```
Add `test_h3_coro_server` immediately after it in the TESTS array.

Then find the block:
```bash
    if [ "$t" = "test_h2_coro_server" ]; then
        EXTRA_I=(-I conformance -I "$HOME/Projets/perso/boucle")
    fi
```
Add a parallel block for the H3 test immediately after it:
```bash
    if [ "$t" = "test_h3_coro_server" ]; then
        EXTRA_I=(-I conformance -I "$HOME/Projets/perso/boucle")
    fi
```

- [ ] **Step 3: Run full test suite**

Run: `bash scripts/run_tests.sh`

Expected: all tests pass (previously 62 + new test = 63 total, or 62+5 depending on counting).

- [ ] **Step 4: Commit**

Use the `commit-smart` skill. Message: `feat: export H3CoroServer and add to run_tests.sh`
