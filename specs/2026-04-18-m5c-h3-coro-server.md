# M5c — H3CoroServer

**Date:** 2026-04-18
**Depends on:** M5b (H3Connection, H3HandlerServer, H3Session — done)
**Estimated LoC:** 380–450 (production) + 350–420 (tests)

---

## Goal

Add a coroutine-based HTTP/3 server adapter (`H3CoroServer`) that mirrors `H2CoroServer`
(M2.6) but drives `H3Connection` instead of `H2Connection`. Handlers are stackful
coroutines (via `boucle.stackful`) rather than `StreamHandler` callbacks. The transport
surface is datagram-based (QUIC) instead of byte-stream-based (TCP).

---

## Scope

- `src/h3/h3_coro_server.mojo` — new file
- `src/h3/__init__.mojo` — add `H3CoroServer` export
- `tests/test_h3_coro_server.mojo` — new test file
- `scripts/run_tests.sh` — add `test_h3_coro_server`

Out of scope:
- Client-side coroutine adapter (no H3CoroClient)
- H1CoroServer, H1CoroClient
- QPACK dynamic table (already deferred to M6)
- Any change to H3HandlerServer, H3Session, or H3Connection

---

## 1. `CoroStreamCtx` struct

Per-stream shared state. Heap-allocated so both H3CoroServer and the coroutine body
can access it via pointer.

```mojo
struct CoroStreamCtx(Movable):
    var request:        Request
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var caps:           Capabilities
    var stream_id:      UInt64    # H3 uses UInt64 (vs UInt32 in H2CoroServer)
    var extra_data:     UnsafePointer[NoneType, MutExternalOrigin]
    var coro_addr:      UInt64    # address of heap-allocated CoroHandle (0 = none)
    var request_ended:  Bool
    var response_ended: Bool
    var headers_sent:   Bool
    # NOTE: no unacked_bytes — QUIC flow control is internal to QuicConnection
```

Constructors: `__init__(out self, var request, caps, stream_id, extra_data)` and
`__init__(out self, *, deinit take: Self)`. `coro_ptr()` helper returns
`UnsafePointer[CoroHandle, MutAnyOrigin]` from `coro_addr`.

---

## 2. `_CoroStreamPtr` struct

Thin `Copyable + Movable` wrapper around a `UInt64` heap address, identical to
`H2CoroServer._CoroStreamPtr` except it points to `CoroStreamCtx` instead of the H2
variant.

```mojo
struct _CoroStreamPtr(Copyable, Movable):
    var addr: UInt64
    def ptr(self) -> UnsafePointer[CoroStreamCtx, MutAnyOrigin]
```

---

## 3. `_free_stream` helper

Single cleanup path for both the `CoroHandle` and `CoroStreamCtx` allocations.
Identical to H2CoroServer's `_free_stream`:

```mojo
def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    if ctx_ptr[].coro_addr != UInt64(0):
        var coro_p = ctx_ptr[].coro_ptr()
        coro_p.destroy_pointee()
        coro_p.free()
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()
```

---

## 4. `H3CoroServer` struct

```mojo
struct H3CoroServer(Movable):
    var _h3:         H3Connection
    var _body_fn:    CoroBody
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _streams:    Dict[Int, _CoroStreamPtr]
```

### 4.1 Constructors

```mojo
def __init__(
    out self,
    *,
    var quic: QuicConnection,
    body_fn: CoroBody,
    extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[NoneType, MutExternalOrigin](),
) raises:
    self._h3 = H3Connection.server(quic^)
    self._body_fn = body_fn
    self._extra_data = extra_data
    self._streams = Dict[Int, _CoroStreamPtr]()

def __init__(out self, *, deinit take: Self):
    # standard move constructor
```

### 4.2 Destructor

Push `StreamError.connection_closed()` into every suspended stream's `recv_body`,
resume each coroutine once so it can unwind, then `_free_stream` all contexts.
Identical logic to H2CoroServer `__del__`.

```mojo
fn __del__(deinit self):
    # snapshot keys, push error + resume + free for each
```

---

## 5. Transport API

```mojo
def feed_datagram(mut self, data: Span[UInt8, _], now: UInt64) raises:
    """Feed one inbound QUIC datagram. Dispatches H3 events, drains responses."""
    self._h3.feed_datagram(data, now)
    self._dispatch_h3_events(now)
    if self._h3.is_established():
        self._drain_responses(now)

def drain_datagrams(mut self, now: UInt64) raises -> List[List[UInt8]]:
    """Return outbound QUIC datagrams accumulated since last call."""
    return self._h3.drain_datagrams(now)

def should_close(self) -> Bool:
    return self._h3.is_closed()

def send_goaway(mut self, last_stream_id: UInt64) raises:
    self._h3.send_goaway(last_stream_id)
```

---

## 6. Event dispatch

```mojo
def _dispatch_h3_events(mut self, now: UInt64) raises:
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
```

### 6.1 `_on_request`

Parse QPACK pseudo-fields into a `Request` (same logic as `H3HandlerServer._on_request`):
`:method` → `Method.custom(...)`, `:path` → target, `:authority` → `host` header,
`:scheme` ignored, remaining fields → user headers.

Then:
1. Allocate `CoroStreamCtx` on heap via `_heap_alloc[CoroStreamCtx](1).as_any_origin()`
2. Initialize with `request^`, `Capabilities.for_h3()`, `ev.stream_id`, `self._extra_data`
3. If `ev.fin` is `True` (e.g. GET with no body): set `ctx.request_ended = True` and call `ctx.recv_body._set_end()` before storing on heap.
4. Allocate `CoroHandle` on heap; `user_data` points to the ctx
5. Set `ctx_ptr[].coro_addr`
6. Insert into `self._streams[Int(ev.stream_id)]`
7. Call `self._resume_and_handle_error(Int(ev.stream_id))`

**Important:** insert into `_streams` BEFORE first `_resume_and_handle_error` so that
`_drain_responses` can find the stream if the coroutine yields immediately.

### 6.2 `_on_trailers`

Second `HEADERS_RECEIVED` on an already-open stream = trailers.

```mojo
def _on_trailers(mut self, ev: H3Event) raises:
    var sid = Int(ev.stream_id)
    if sid not in self._streams:
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
```

### 6.3 `_on_data`

Push `BodyFrame.data(...)` into `recv_body`. No flow-control ACK (QUIC handles FC
internally). Resume coroutine.

```mojo
def _on_data(mut self, ev: H3Event) raises:
    var sid = Int(ev.stream_id)
    if sid not in self._streams:
        return
    var ctx_ptr = self._streams[sid].ptr()
    var ctx = ctx_ptr.take_pointee()
    var data_copy = List[UInt8](copy=ev.data)
    ctx.recv_body._push(BodyFrame.data(data_copy^))
    ctx_ptr.init_pointee_move(ctx^)
    self._resume_and_handle_error(sid)
```

### 6.4 `_on_stream_ended`

```mojo
def _on_stream_ended(mut self, ev: H3Event) raises:
    var sid = Int(ev.stream_id)
    if sid not in self._streams:
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
```

### 6.5 `_on_stream_reset`

Push `StreamError.rst_stream(UInt32(ev.error_code))` into `recv_body`. Resume once
(so coroutine unwinds). Pop from `_streams` before `_free_stream`.

```mojo
def _on_stream_reset(mut self, ev: H3Event) raises:
    var sid = Int(ev.stream_id)
    if sid not in self._streams:
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
```

### 6.6 `_on_goaway`

Broadcast `StreamError.connection_closed()` to all open streams, resume each once,
pop + free all.

---

## 7. Internal helpers

### 7.1 `_resume_and_handle_error`

```mojo
def _resume_and_handle_error(mut self, stream_id: Int) raises:
    if stream_id not in self._streams:
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
        self._h3.reset_stream(UInt64(stream_id), H3_REQUEST_CANCELLED)
        self._cleanup_stream(stream_id)
        return
    if coro_p[].is_done():
        self._maybe_cleanup_stream(stream_id)
```

### 7.2 `_cleanup_stream`

Unconditionally remove from dict then free. Pop MUST precede `_free_stream`:

```mojo
def _cleanup_stream(mut self, stream_id: Int) raises:
    if stream_id not in self._streams:
        return
    var ctx_ptr = self._streams[stream_id].ptr()
    _ = self._streams.pop(stream_id)   # pop FIRST
    _free_stream(ctx_ptr)
```

### 7.3 `_maybe_cleanup_stream`

Same pop-before-free discipline, guarded by lifecycle flags:

```mojo
def _maybe_cleanup_stream(mut self, stream_id: Int) raises:
    if stream_id not in self._streams:
        return
    var ctx_ptr = self._streams[stream_id].ptr()
    if ctx_ptr[].request_ended and ctx_ptr[].response_ended:
        _ = self._streams.pop(stream_id)   # pop FIRST
        _free_stream(ctx_ptr)
```

---

## 8. Response drain

```mojo
def _drain_responses(mut self, now: UInt64) raises:
    var stream_ids = List[Int]()
    for key in self._streams.keys():
        stream_ids.append(key)
    for i in range(len(stream_ids)):
        var sid = stream_ids[i]
        if sid not in self._streams:
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

---

## 9. Exports and runner

**`src/h3/__init__.mojo`**: add `from src.h3.h3_coro_server import H3CoroServer`.

**`scripts/run_tests.sh`**: add `test_h3_coro_server` to TESTS array with `-I conformance`
guard.

---

## 10. Tests (`tests/test_h3_coro_server.mojo`)

All tests use the same QUIC loopback pair setup as `test_h3_e2e.mojo`
(inlined, not via a helper, due to Mojo Tuple move restriction).

A test coroutine body reads request data via `CoroYielder` and writes a response
via `ResponseWriter`. To access ctx: `yielder.user_data()` cast to
`UnsafePointer[CoroStreamCtx, MutAnyOrigin]`.

### `test_h3_coro_simple_get`

Body coroutine reads the request (no body), writes 200 + "hello" body. Pump until
response drained. Assert status 200 and body bytes on client side.

### `test_h3_coro_post_with_body`

Body coroutine calls `yield_to_caller()` after `on_request` (body not yet available),
resumes when DATA arrives, reads body bytes, writes 200 + echo body. Assert round-trip.

### `test_h3_coro_trailers`

Client sends HEADERS + DATA + HEADERS(trailers) + END_STREAM. Coroutine reads body,
then reads trailer frame from recv_body. Assert trailer header present.

### `test_h3_coro_goaway`

Server sends GOAWAY. Assert all suspended coroutines receive `StreamError.connection_closed()`
and unwind (observable via the error propagated through `recv_body` before the server is dropped).

### `test_h3_coro_rst_stream`

Client resets a stream mid-response. Assert coroutine receives `StreamError.rst_stream(...)`.

---

## 11. Memory safety invariants

These must hold throughout the implementation:

1. **Pop before free**: `_ = self._streams.pop(sid)` always precedes `_free_stream(ctx_ptr)`.
2. **No stale pointer resume**: after `_free_stream`, never access `ctx_ptr` again.
3. **`coro_addr` lifetime**: `coro_addr` is set once in `_on_request` and cleared (via free)
   in `_free_stream`. No other path writes it.
4. **take_pointee discipline**: after `ctx_ptr.take_pointee()`, the slot is uninit;
   must call `ctx_ptr.init_pointee_move(ctx^)` before any other access, or free the slot.
