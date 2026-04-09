# M2.5 — Unified HTTP API Surface

**Status:** M2.5a merged as `c93aaf9`; M2.5b merged as `3eb7b47` — both on main
**Date:** 2026-04-07 (revised 2026-04-09 post-M2.5b-merge)
**Author:** Claude (with Conobi)
**Predecessor milestone:** M2 (HTTP/1.1 + reverse proxy, merged 2026-04-07)
**Successor milestones:** HC-4, M5.5, M3, M5, M6 (all build on this trait surface)

**Delivery:** this spec is shipped as **two waves**:
- **M2.5a** — core trait surface (HC-4 unblocker) — ✅ shipped
- **M2.5b** — protocol-agnostic helpers (M6 unblocker, can run in parallel with HC-4) — ✅ shipped

See §12 for the file-level breakdown.

---

## Reading this spec post-M2.5a

Several signatures in §5 carry inline `# M2.5a:` notes describing forced
deviations from the original sketch. They fall into five buckets, all
driven by Mojo 0.26.2 ergonomics:

1. **Move-only collections** — `Session.run_until` takes `Deque[UInt64]`
   of handle IDs instead of `List[RequestHandle]` because stdlib
   `List`/`Deque` require Copyable elements and `RequestHandle` is move-only.
2. **One-way detach** — `RecvBody.detach()` is `deinit self` and
   `StreamHandler.on_request` takes `var body: RecvBody` so the detach
   pattern is reachable from inside the trait method (a `mut` parameter
   cannot be moved out).
3. **By-value error accessor** — `BodyFrame.error()` returns `StreamError`
   by value rather than by ref because `Optional.value()` returns a borrow
   into `_value` whose origin doesn't unify with the spec's `[self._error]`
   annotation. `StreamError` is Copyable so the cost is minimal.
4. **Captured-state ResponseWriter** — `ResponseWriter` stashes status and
   headers in Optional fields (`_captured_*`) and exposes `_take_*` accessors
   for the H1 adapter to drain after handler invocation, replacing the
   earlier draft's `_send_headers_id: UInt64` callback-registry hook. There
   is no runtime registry in M2.5a.
5. **Request trailers dropped** — `RequestBody` is bytes-or-stream-only;
   the H1 parser drops chunked request trailers and the cross-validation
   suite skips them. HC-4 will need to revisit this for HTTP/2's separate
   trailer HEADERS frame.

HC-4 implementers reading the surface should treat the inline `# M2.5a:`
notes as authoritative and the surrounding prose as historical context.

---

## Reading this spec post-M2.5b

§7 code sketches carry inline `# M2.5b:` notes describing forced deviations
from the original sketch. They fall into four buckets:

1. **`Origin(KeyElement)` replaces `(Copyable, Movable)`** —
   `EqualityComparable` doesn't exist in Mojo 0.26.2 (only `Equatable`),
   `Hashable` lives under `hashlib.hash`, and `KeyElement` from
   `std.collections.dict` is the composite alias bundling every constraint
   needed for `Dict` keys.
2. **`AltSvcCache` methods marked `raises`** — `Dict.__getitem__` and
   `Dict.pop` raise on missing key in Mojo 0.26.2, propagating upward
   through `lookup`, `clear`, and `clear_expired`.
3. **`try_write_event` free function replaces `EventStreamWriter` struct** —
   the sketch's `UnsafePointer[ResponseWriter, MutAnyOrigin]` contradicts
   its own "does NOT take ownership" doc and carries lifetime risk. SSE
   writers need no per-call state, so a stateless free function is simpler
   and safer.
4. **Byte-scanning throughout all parsers** — String `[i]` indexing and
   `[start:end]` slicing are unsupported in Mojo 0.26.2. Every parser uses
   `.as_bytes()` + `UInt8` constants + `chr(Int(b))` accumulation, matching
   the idiom in `src/h1/parser.mojo`.

Full deviation list: `plans/2026-04-07-m25b-helper-modules-retrospective.md`.

---

## 1. Goal

Define the protocol-agnostic trait surface, types, and shared utilities that all HTTP wire-format milestones (HC-4 → M5.5 → M5 → M6) implement against. The death-star case is a fast HTTP/3 server and a feature-complete unified HTTP client; M2.5 designs the API both will satisfy, even though only HTTP/1.1 is wired up to it in v1.

This is **interface work, not protocol work**.

### Design philosophy: HTTP/3 as the canonical shape

The trait surface is designed against HTTP/3 semantics. HTTP/2 and HTTP/1.1 are graceful projections of that shape onto older wire formats. Where features can be retrofit (trailers via H1 chunked encoding, priority hints via the `Priority` header, server-sent events over any reliable byte stream), they are exposed through the unified API. Where features genuinely don't fit (true stream multiplexing on H1, connection migration, datagrams on TCP), they are exposed through a `Capabilities` flag and isolated to opt-in extension traits.

Build order is inverted from API order: HC-4 → M5.5 (HTTP/2) ships before M3 → M5 (QUIC + HTTP/3) for validation and scope reasons. But the API is designed against H3's shape from M2.5 onwards so there is no retrofit pain when H3 lands.

---

## 2. Scope

### In scope (combined M2.5a + M2.5b)

- **Trait definitions** [M2.5a]
  - `StreamHandler` — server-side request lifecycle
  - `H3StreamExtension` — standalone opt-in trait for H3-specific features
  - `Session` — client-side connection abstraction
- **Sans-I/O primitives** [M2.5a]
  - `RecvBody` — inbound stream queue (γ hybrid: push from runtime, pull from handler)
  - `SendBody` — outbound stream queue
  - `ResponseWriter` — composes status/headers send + `SendBody`
  - `RequestHandle` — owning client-side handle
  - `H3Context` — H3-specific stream context (scaffolding in v1, filled in M5)
- **Capability flags**: `Capabilities` struct + factory methods per protocol [M2.5a]
- **Error types**: `StreamError`, `WriteResult` [M2.5a]
- **Configuration constants**: matched to hyper's defaults, in `src/http/config.mojo` [M2.5a]
- **MockSession + MockServer** — in-memory test substrate for trait conformance [M2.5a]
- **M2 refactor** [M2.5a]
  - `src/h1/server.mojo` and `src/h1/client.mojo` updated to implement `StreamHandler`/`Session`
  - `examples/reverse_proxy/main.mojo` refactored onto the new traits
- **Research spike**: `research/mojo-async-executor.md` (parallel, non-blocking) [M2.5a]
- **Cross-protocol helper modules** [M2.5b]
  - `src/http/priority.mojo` — RFC 9218 Priority header parser/serializer
  - `src/http/alt_svc.mojo` — RFC 7838 Alt-Svc parser + `AltSvcCache`
  - `src/http/sse.mojo` — text/event-stream parser + writer

### Out of scope (deferred)

- HTTP/2 and HTTP/3 protocol implementations (HC-4, M5.5, M5)
- Blocking adapter (`BlockingBody`) — thread-pool wrapper around the callback model
- Async adapter (`AsyncBody`) — Mojo coroutine integration (depends on Modular shipping pluggable executors; tracked in M2.6 if research spike succeeds)
- WebSockets (H1 upgrade, H2 extended CONNECT)
- HTTP/3 datagram methods beyond a capability flag
- WebTransport, MASQUE, HTTP/3 server push
- Connection pooling implementation (M6 owns this; M2.5 only defines the `Session` trait it'll dispatch through)
- SOCKS proxies, custom DNS resolution, Happy Eyeballs (RFC 8305)
- gzip/br/zstd content decoding (Tier 4 ergonomics; deferred to M6)
- Cookie jar (Tier 4 ergonomics; deferred to M6)

---

## 3. Architecture overview

```
                    ┌──────────────────────────────────┐
                    │   Application code (handler)     │
                    │  • implements StreamHandler      │
                    │  • optionally H3StreamExtension  │
                    └────────────┬─────────────────────┘
                                 │ trait dispatch (compile-time monomorphic)
                    ┌────────────▼─────────────────────┐
                    │   Server[H] / Session            │
                    │  • routes streams to handler     │
                    │  • drives Body queues + writers  │
                    │  • emits Capabilities per stream │
                    └────────────┬─────────────────────┘
                                 │ sans-I/O calls
                    ┌────────────▼─────────────────────┐
                    │   src/h1, (future src/h2, src/h3)│
                    │   protocol implementations       │
                    └────────────┬─────────────────────┘
                                 │ buffer in/out
                    ┌────────────▼─────────────────────┐
                    │   Application I/O loop           │
                    │   (boucle is one possible loop;  │
                    │    used in mojo-net's examples)  │
                    └──────────────────────────────────┘
```

Three separations of concern:

1. **Handler ↔ trait surface** — handlers see only `Request`, `RecvBody`, `ResponseWriter`, `Capabilities`. They never see boucle, never see protocol implementations, never touch buffers directly.
2. **Trait surface ↔ protocol** — protocol implementations push frames into `RecvBody`, drain `SendBody`, and call handler lifecycle methods at the right transitions. They never know which handler is running.
3. **Protocol ↔ I/O** — protocol code is sans-I/O. The application loop owns buffers and submits syscalls; the protocol layer is a state machine fed bytes in and producing bytes out.

This is the same architecture as `hyper` + `h2`/`h3` in Rust, validated by years of production use.

---

## 4. Module layout

```
src/http/
├── __init__.mojo        # Re-exports
├── method.mojo          # (existing)
├── status.mojo          # (existing)
├── version.mojo         # (existing)
├── headers.mojo         # (existing)
├── body.mojo            # (existing) — extend BodyFrame with End + Error variants  [M2.5a]
├── request.mojo         # (existing) — add clone() / try_clone()                   [M2.5a]
├── response.mojo        # (existing)
├── config.mojo          # NEW — default constants matching hyper                   [M2.5a]
├── handler.mojo         # NEW — StreamHandler, RecvBody, SendBody, ResponseWriter,
│                                Capabilities, StreamError, WriteResult             [M2.5a]
├── h3_extension.mojo    # NEW — H3StreamExtension standalone trait, H3Context     [M2.5a]
├── session.mojo         # NEW — Session trait, RequestHandle                       [M2.5a]
├── mock_session.mojo    # NEW — MockSession + MockServer for testing               [M2.5a]
├── priority.mojo        # NEW — RFC 9218 Priority parser/serializer                [M2.5b]
├── alt_svc.mojo         # NEW — RFC 7838 Alt-Svc + AltSvcCache                    [M2.5b]
└── sse.mojo             # NEW — text/event-stream parser + writer                  [M2.5b]
```

`MockSession` and `MockServer` deliberately live in `src/http/` (not under `tests/`) so downstream consumers (HC-4 tests, M5 tests, application code that wants to test handlers) can import them without depending on test infrastructure.

---

## 5. Core types

### 5.0 Mojo conventions used in this spec

Every owning struct in §5 follows this pattern (mirroring existing M2 code at `src/http/body.mojo`):

```mojo
struct Foo(Movable):
    # ...fields...

    def __init__(out self, ...):                      # primary constructor
        ...

    def __init__(out self, *, deinit take: Self):     # move constructor
        # field-by-field move from `take`

    fn __del__(deinit self):                          # destructor (note: fn, not def)
        # field-by-field cleanup if needed
```

Key points:
- All trait methods and ordinary methods use **`def`** (not `fn`), matching the M2 codebase. `fn` is reserved for the destructor (where `def __del__(var self)` would cause an infinite loop) and for inline-required code.
- Move constructor is `def __init__(out self, *, deinit take: Self)`. This is verified to work in Mojo 0.26.2 (see `src/http/body.mojo:43`).
- Destructor is `fn __del__(deinit self)`. The `fn` keyword and `deinit self` argument convention are both load-bearing.

When this spec writes `def foo(...) raises`, the implementation must use `def`, not `fn`.

### 5.1 `Capabilities` (runtime flags)

```mojo
# src/http/handler.mojo

# ALPN identifiers as integer constants — avoids per-stream String allocation.
comptime ALPN_H1 = 0
comptime ALPN_H2 = 1
comptime ALPN_H3 = 2

struct Capabilities(Copyable, Movable):
    """Per-stream protocol capability flags. Cheap to copy. Passed to handlers
    on every lifecycle callback so they can branch on protocol features."""

    var multiplexed: Bool       # Connection supports concurrent in-flight streams (H2, H3)
    var trailers: Bool          # Protocol can carry trailers natively (H2, H3; H1 chunked-only)
    var priority_hints: Bool    # RFC 9218 PRIORITY_UPDATE / Priority header supported
    var datagrams: Bool         # H3 datagrams (RFC 9297) available
    var alpn: Int               # one of ALPN_*

    @staticmethod
    def for_h1() -> Self
    @staticmethod
    def for_h2() -> Self
    @staticmethod
    def for_h3() -> Self

    def is_h1(self) -> Bool
    def is_h2(self) -> Bool
    def is_h3(self) -> Bool
    def alpn_string(self) -> String   # for diagnostics; not on hot path
```

**Cost analysis**: ~1 ns per branch, perfectly predicted (a single connection uses one protocol for its lifetime). Three orders of magnitude cheaper than the cheapest "real" work in the request path. Negligible.

### 5.2 `BodyFrame` extension

The existing tagged-union `BodyFrame` (Data | Trailers) gains an `End` variant and an `Error` variant:

```mojo
# src/http/body.mojo (extended)

comptime _TAG_DATA     = 0
comptime _TAG_TRAILERS = 1
comptime _TAG_END      = 2   # NEW — explicit end-of-stream marker
comptime _TAG_ERROR    = 3   # NEW — terminal error

struct BodyFrame(Copyable, Movable):
    var _tag: Int
    var _data: List[UInt8]
    var _headers: Headers
    var _error: Optional[StreamError]   # NEW

    # ...existing factories...

    @staticmethod
    def end() -> Self                   # NEW
    @staticmethod
    def error(err: StreamError) -> Self # NEW

    def is_data(self) -> Bool
    def is_trailers(self) -> Bool
    def is_end(self) -> Bool             # NEW
    def is_error(self) -> Bool           # NEW

    def data(ref self) -> ref [self._data] List[UInt8]
    def trailers(ref self) -> ref [self._headers] Headers
    def error(self) -> StreamError                         # NEW
    # M2.5a: by-value (not ref) — Optional.value() returns a borrow into
    # `_value` whose origin doesn't unify with `[self._error]`. StreamError
    # is Copyable so the copy is cheap. Revisit if profiling shows pressure.
```

**Frame ordering rule**: a body stream is a sequence of zero-or-more `Data` frames, optionally followed by a single `Trailers` frame, followed by exactly one terminal frame which is either `End` (clean) or `Error` (terminal error). Once the terminal frame is consumed via `try_read`, subsequent calls return `None` and `is_end()` on the body returns `True`.

### 5.3 `StreamError`

```mojo
# src/http/handler.mojo

# Stream error kinds. These are public — handlers may pattern-match on them.
comptime STREAM_ERR_PEER_CLOSED       = 0  # peer closed the stream/connection unexpectedly
comptime STREAM_ERR_RST_STREAM        = 1  # explicit RST_STREAM (H2/H3)
comptime STREAM_ERR_PARSER            = 2  # malformed frame / header / wire data
comptime STREAM_ERR_LOCAL_ABORT       = 3  # handler raised, runtime aborted the stream
comptime STREAM_ERR_CONNECTION_CLOSED = 4  # underlying connection closed mid-stream
comptime STREAM_ERR_PROTOCOL          = 5  # protocol-level error (e.g. flow control violation)

struct StreamError(Copyable, Movable):
    var kind: Int            # one of STREAM_ERR_*
    var code: UInt32         # protocol-specific error code (H2/H3 stream error code; 0 for H1)
    var message: String      # human-readable

    @staticmethod
    def peer_closed() -> Self
    @staticmethod
    def rst_stream(code: UInt32) -> Self
    @staticmethod
    def parser(message: String) -> Self
    @staticmethod
    def local_abort(message: String) -> Self
    @staticmethod
    def connection_closed() -> Self
    @staticmethod
    def protocol(code: UInt32, message: String) -> Self
```

**H1 error mapping**: H1 has no per-stream error codes, so `code` is always 0 for H1-side errors. The `kind` and `message` carry the meaningful information.

### 5.4 `WriteResult`

```mojo
# src/http/handler.mojo

comptime _WRITE_OK          = 0
comptime _WRITE_WOULD_BLOCK = 1   # high water mark hit; caller should pause and resume on drain
comptime _WRITE_CLOSED      = 2   # stream is reset or ended

struct WriteResult(Copyable, Movable):
    var tag: Int

    @staticmethod
    def ok() -> Self
    @staticmethod
    def would_block() -> Self
    @staticmethod
    def closed() -> Self

    def is_ok(self) -> Bool
    def is_would_block(self) -> Bool
    def is_closed(self) -> Bool
```

### 5.5 Body ownership model — the hybrid detach pattern

This is the single most consequential design decision in M2.5 and was identified during independent review as needing explicit treatment. **Read this section carefully before implementing any of §5.6 / §5.7 / §5.8.**

#### The problem

`RecvBody` and `SendBody` are sans-I/O queues that the runtime pushes/drains. They need to be accessible to application handlers across multiple lifecycle callbacks (`on_request`, `on_body_available`, `on_request_end`, etc). Three patterns are coherent:

1. **Always borrowed**: handler always gets `mut body: RecvBody`, runtime always owns. Simple, but the reverse-proxy and SSE patterns can't move the body elsewhere without manual frame pumping.
2. **Always owned**: handler takes `var body: RecvBody` on `on_request` and stores it on `self`. Runtime can no longer push to it after the handler takes it; needs a back-channel.
3. **Hybrid with explicit `detach()`**: default is borrowed; handler can take ownership when needed.

This spec uses **option 3**. The runtime owns the body in its per-stream state for the lifetime of the stream by default. Handlers receive `mut` borrows on lifecycle callbacks. **A handler can call `body.detach()` to move the body out of the runtime's per-stream state into its own ownership**, after which:

- The runtime stops calling lifecycle callbacks that pass a `body` argument for that stream (since it no longer owns one).
- The handler is fully responsible for draining frames, including handling end-of-stream.
- The runtime continues to push frames into the now-detached body (it has a stable address — the runtime keeps a pointer or a registered ID).

#### How it works concretely

```mojo
struct DetachedBody(Movable):
    """Owned RecvBody that has been moved out of the runtime's per-stream state.
    The handler is fully responsible for draining it. The runtime still pushes
    frames into the underlying queue using a registered ID."""
    var _inner: RecvBody

    def try_read(mut self) -> Optional[BodyFrame]
    def is_end(self) -> Bool
    # ... full RecvBody surface, plus:
    def take_inner(deinit self) -> RecvBody    # move out the inner queue
```

```mojo
trait StreamHandler(Movable, ImplicitlyDestructible):
    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,                            # M2.5a: see note below
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises
    """The body is consumed by the handler. The runtime materializes the full
    request body before invoking on_request (request-at-a-time in M2.5a's H1
    runtime adapter). Handlers that want to forward the body to a backend or
    keep it across handler boundaries call `body^.detach()` to obtain a
    DetachedBody and store it on self. Handlers that drain inline call
    body.try_read() in a loop and let the body drop at the end of the
    callback.

    M2.5a deviation from earlier draft: this parameter was originally
    `mut body: RecvBody` so the runtime could continue invoking
    on_body_available against the same body. Mojo 0.26.2 forbids consuming a
    `mut` parameter, and `body.detach()` is `deinit self` (one-way), so the
    detach pattern is unreachable from a `mut` body. HC-4 may revisit this
    once H2/H3 streaming inbound bodies need genuine cross-callback access —
    options include adding a separate `body.try_detach()` that operates on
    a `mut` ref by swapping internal state, or splitting on_request into
    `on_request_headers` (consumes nothing) + `on_request_body` (mut body)."""

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises
    """Called only if the handler did NOT detach the body during on_request.
    If the handler detached, the runtime no longer drives this callback for
    the detached stream — the handler reads frames from its DetachedBody at
    its own pace."""

    # ... other lifecycle methods unchanged ...
```

```mojo
struct RecvBody(Movable):
    # ... fields and methods from §5.6 ...

    def detach(deinit self) -> DetachedBody
    """Consume the body and return a DetachedBody owning the queue. After
    calling this, the runtime stops invoking on_body_available /
    on_request_end for this stream; the handler reads from the DetachedBody
    directly. Frames continue to arrive from the runtime via the underlying
    registered queue.

    M2.5a: `deinit self` (not `mut self`) to make the one-way semantics
    enforceable at the type level — once detached, the original RecvBody is
    inaccessible. This matches §5.5's "Cannot resurrect a detached body
    back into runtime ownership" rule and pairs with on_request taking
    `var body: RecvBody`."""
```

#### Handler patterns

**Simple inline handler** (no detach, processes inside callbacks):

```mojo
struct EchoHandler(StreamHandler):
    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        # Read whatever's already buffered, then return
        while True:
            var frame_opt = body.try_read()
            if not frame_opt:
                break
            var frame = frame_opt.value()
            if frame.is_data():
                _ = resp.try_send_body(BodyFrame.data(frame.data().copy()))
            elif frame.is_end():
                resp.end()
                break

    def on_body_available(mut self, mut body: RecvBody, mut resp: ResponseWriter) raises:
        while True:
            var frame_opt = body.try_read()
            if not frame_opt:
                break
            # ... same processing ...
```

**Reverse proxy** (detach inbound body, wrap as RequestBody.stream, attach to outbound request):

```mojo
struct ProxyHandler[Backend: Session](StreamHandler):
    var backend: Backend
    var inflight: Dict[StreamId, RequestHandle]

    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        var detached = body.detach()
        var outbound_req = self._rewrite_headers(req^)
        outbound_req.body = RequestBody.stream(detached^)   # see §5.12
        var handle = self.backend.submit(outbound_req^)
        self.inflight[stream_id_of(resp)] = handle^
        # Subsequent on_body_available NOT called for this stream — inbound body is owned by outbound RequestBody now
```

**SSE handler** (detach response side, write events incrementally):

```mojo
struct SseHandler(StreamHandler):
    def on_request(mut self, var req: Request, mut body: RecvBody, mut resp: ResponseWriter, caps: Capabilities) raises:
        var headers = Headers()
        headers.set("content-type", "text/event-stream")
        resp.send_status(StatusCode(200), headers^)
        # Process events as backpressure allows; relies on on_send_drained for resumption
        self._push_pending_events(resp)

    def on_send_drained(mut self, mut resp: ResponseWriter) raises:
        self._push_pending_events(resp)
```

(SSE doesn't need to detach the response — the `on_send_drained` callback gives it the same `resp` handle each time. Detach is only needed when the handler wants to escape the lifecycle-callback execution model entirely.)

#### Server-side and client-side symmetry

The detach pattern applies to both sides:

- **Server-side `RecvBody.detach() -> DetachedBody`** — used by reverse proxies and SSE-as-input handlers
- **Client-side `RequestHandle.take_body() -> RecvBody`** — already in the spec; same idea, different name. Client code calls `take_body` to detach the response body from the handle for streaming consumption.

These are the same pattern with two names because the call sites are different.

#### What this rules out

- **Cannot use a body across two separate `Session.run_until` calls without detaching first.** The body lives in the runtime's per-stream state, which is invalidated when `run_until` returns.
- **Cannot pass a borrowed `mut body` to code that outlives the lifecycle callback.** Detach first.
- **Cannot resurrect a detached body back into runtime ownership.** Detach is one-way.

### 5.6 `RecvBody`

```mojo
# src/http/handler.mojo

comptime _BODY_OPEN    = 0
comptime _BODY_END     = 1
comptime _BODY_ERRORED = 2

struct RecvBody(Movable):
    """Inbound body stream. The runtime pushes BodyFrames as they arrive from
    the wire; the handler pulls them via try_read(). Backpressure managed by
    watermarks: when bytes_buffered exceeds high_water, the runtime stops
    reading from the transport for this stream (H1: stops submit_recv on the
    connection socket; H2/H3: stops emitting WINDOW_UPDATE for the stream).
    When bytes_buffered drains back to low_water, reading resumes.

    For H1, per-stream and per-connection backpressure are the same thing
    (one stream = one connection); pausing a stream pauses the connection."""

    var _frames: Deque[BodyFrame]
    var _state: Int                 # one of _BODY_*
    var _bytes_buffered: UInt
    var _high_water: UInt
    var _low_water: UInt
    var _paused: Bool
    var _terminal_consumed: Bool    # M2.5a: drives is_end() — true after End/Error frame is popped
    # M2.5a omits the `_on_drain_id: UInt64` callback-registry hook the
    # earlier draft sketched. The runtime currently has no global registry;
    # the H1 adapter holds a typed pointer to the per-stream RecvBody and
    # drives backpressure by polling `is_paused()` after each push. HC-4
    # reintroduces this field if H2 needs it.

    # --- Public API (handler-facing) ---

    def try_read(mut self) -> Optional[BodyFrame]
    """Non-blocking read. Returns None if the queue is empty AND the body is
    still open. Returns Some(BodyFrame) for data, trailers, end-of-stream
    sentinel, or terminal error. After the End or Error frame is consumed,
    subsequent calls return None and is_end() returns True."""

    def is_end(self) -> Bool
    """True if the End or Error frame has been delivered AND consumed."""

    def is_errored(self) -> Bool
    def bytes_buffered(self) -> UInt
    def set_watermarks(mut self, *, high: UInt, low: UInt)

    def detach(deinit self) -> DetachedBody
    """Move the body out of the runtime's per-stream state into the caller's
    ownership. See §5.5 for the full ownership model. After detach, the
    runtime stops invoking on_body_available / on_request_end for the stream
    that owned this body. M2.5a: `deinit self` enforces the one-way rule at
    the type level."""

    # --- Runtime-internal API (called by I/O loop / framer) ---

    def _push(mut self, var frame: BodyFrame)
    """Append a frame to the queue. May trigger pause if bytes_buffered crosses
    high_water. Called only by protocol implementations. M2.5a: drops the
    push if the body has already terminated (state != _BODY_OPEN) — protects
    the "exactly one terminal frame" invariant against cross-layer ordering
    bugs."""

    def _set_end(mut self)
    """Mark end-of-stream by pushing an End frame and transitioning state.
    Called only by protocol implementations. Idempotent: a no-op if the body
    is already in any non-OPEN state (END wins on END; ERROR wins on
    END-after-ERROR)."""

    def _set_error(mut self, var err: StreamError)
    """Mark the stream as errored by pushing an Error frame. Idempotent: only
    the first error is recorded."""
```

**Watermark accounting rule**: `bytes_buffered` includes the data payload of `Data` variants and excludes `Trailers`, `End`, and `Error` variants. Trailers and terminal frames are small and always at the end; counting them against the byte budget could deadlock the stream.

### 5.7 `SendBody`

```mojo
struct SendBody(Movable):
    """Outbound body stream. The handler writes BodyFrames; the runtime drains
    them to the wire. Backpressure managed by high watermark: when
    bytes_buffered exceeds high_water, try_write returns WouldBlock until the
    runtime drains and bytes_buffered drops below low_water (then on_drain
    fires)."""

    var _frames: Deque[BodyFrame]
    var _state: Int
    var _bytes_buffered: UInt
    var _high_water: UInt
    var _low_water: UInt
    var _abort_code: UInt32
    # M2.5a omits the `_on_drain_id: UInt64` callback-registry hook the
    # earlier draft sketched. The H1 adapter polls SendBody._pop() after each
    # handler invocation; backpressure resumption is driven by `on_send_drained`
    # at the adapter layer rather than via a registered callback ID.

    # --- Public API (handler-facing) ---

    def try_write(mut self, var frame: BodyFrame) -> WriteResult
    """Append a frame to the send queue. Returns Ok if accepted under
    high_water, WouldBlock if appended *and* the buffered bytes exceed
    high_water (handler should pause further writes and wait for
    on_send_drained), Closed if the stream is reset or ended. The frame is
    consumed in all three cases — WouldBlock is not a rejection; it is an
    accept-and-pause hint to the caller."""

    def end(mut self) raises
    """Mark the body as complete by pushing an End frame. After this, no more
    frames can be written. Raises if the stream is reset or already ended."""

    def abort(mut self, code: UInt32) raises
    """Abort the stream with the given error code. Sends RST_STREAM (H2/H3) or
    closes the connection (H1). M2.5a: clears `_frames` and zeros
    `_bytes_buffered` so the runtime cannot drain a half-body before the
    RST/close. Raises if already aborted."""

    def bytes_buffered(self) -> UInt
    def set_watermarks(mut self, *, high: UInt, low: UInt)

    # --- Runtime-internal API ---

    def _pop(mut self) -> Optional[BodyFrame]
```

### 5.8 `ResponseWriter`

```mojo
struct ResponseWriter(Movable):
    """Server-side outbound writer. Composes status/headers send with a
    SendBody. The handler must call send_status before any try_send_body."""

    var _status_sent: Bool
    var _send_body: SendBody
    # M2.5a captured-state pattern. The earlier draft sketched a
    # `_send_headers_id: UInt64` callback registration so the protocol framer
    # could be invoked synchronously inside send_status. M2.5a has no runtime
    # registry, so send_status / send_informational stash the status + headers
    # in these Optional/list fields and the H1 adapter polls them after the
    # handler callback returns. HC-4 may reintroduce the callback-id model
    # when H2's framer needs immediate emission (e.g. mid-callback 100-Continue).
    var _captured_status: Optional[StatusCode]
    var _captured_headers: Optional[Headers]
    var _captured_informational: List[StatusCode]
    var _captured_informational_headers: List[Headers]

    # --- Public API ---

    def send_status(
        mut self,
        var status: StatusCode,
        var headers: Headers,
    ) raises
    """Send the response status line + headers. Must be called before any
    try_send_body. Raises if called twice."""

    def send_informational(
        mut self,
        var status: StatusCode,
        var headers: Headers,
    ) raises
    """Send a 1xx informational response (e.g. 103 Early Hints). May be
    called any number of times before send_status. Raises if status is
    not in the 1xx range or if send_status has already been called."""

    def try_send_body(mut self, var frame: BodyFrame) raises -> WriteResult
    def end(mut self) raises
    def abort(mut self, code: UInt32) raises
    def bytes_buffered(self) -> UInt

    # --- Runtime-internal API (called by the H1 adapter) ---
    # M2.5a: each `_take_*` drains the corresponding captured field. The H1
    # adapter calls these after every handler invocation to materialize a
    # Response from the captured state.
    def _has_status(self) -> Bool
    def _take_status(mut self) -> Optional[StatusCode]
    def _take_headers(mut self) -> Optional[Headers]
    def _take_informational(mut self) -> List[StatusCode]
    def _take_informational_headers(mut self) -> List[Headers]
    def _pop_body_frame(mut self) raises -> Optional[BodyFrame]
```

`ResponseWriter` is borrowed (`mut resp: ResponseWriter`) on every lifecycle callback, like `RecvBody`. There is currently no `detach` for `ResponseWriter` because no v1 use case needs it (SSE relies on `on_send_drained` to get a fresh borrow each time). A future detach mechanism is additive if needed.

### 5.9 `StreamHandler` trait

```mojo
trait StreamHandler(Movable, ImplicitlyDestructible):
    """Server-side request handler. The runtime calls these methods as the
    request lifecycle progresses. Handlers raise to abort the stream — the
    runtime catches and translates the exception into RST_STREAM (H2/H3) or
    connection close (H1) and calls on_reset with kind=LocalAbort.

    Lifecycle order (per stream):
        on_request                     # exactly once
        on_body_available*             # 0..N times, only if body NOT detached
        on_request_end                 # exactly once after the body ends, only if body NOT detached
        on_send_drained*               # 0..N times, after try_send_body returned WouldBlock
        on_reset                       # at most once, if the stream is reset

    If the handler detaches the body via body^.detach() during on_request,
    the on_body_available and on_request_end callbacks are NOT invoked for
    that stream — the handler is responsible for draining the DetachedBody
    itself.

    M2.5a addendum: in the M2.5a H1 runtime adapter the request body is
    fully materialized before on_request fires (request-at-a-time). The
    handler is therefore handed an owned body and can choose to drain it
    inline or detach it. on_body_available / on_request_end are wired
    structurally but never invoked by the H1 adapter today; HC-4 will be
    the first runtime to drive them."""

    def on_request(
        mut self,
        var req: Request,
        var body: RecvBody,                            # M2.5a: see §5.5
        mut resp: ResponseWriter,
        caps: Capabilities,
    ) raises

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises
    """Called when new body data arrives after on_request returned without
    fully draining the body, AND the handler did not detach the body. Default
    implementation: empty."""

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
    ) raises
    """Called once after the body's End frame has arrived, only if the body
    was not detached. The handler is expected to finish composing the
    response and call resp.end() (if it hasn't already)."""

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
    ) raises
    """Called when SendBody's bytes_buffered drops below the low watermark
    after a previous try_send_body returned WouldBlock. Default empty."""

    def on_reset(
        mut self,
        error: StreamError,
    )
    """Called when the stream is reset before the response is fully sent.
    Cannot raise; errors here are logged and ignored."""
```

### 5.10 `H3StreamExtension` trait — standalone (no inheritance)

**This is the standalone trait form** decided in revision-time review. `H3StreamExtension` does **not** inherit from `StreamHandler`. Handlers that want to serve both H3 and lower protocols implement both traits explicitly.

```mojo
# src/http/h3_extension.mojo

trait H3StreamExtension(Movable):
    """Standalone trait for HTTP/3 handlers that need access to H3-specific
    features (datagrams, push promises). HTTP/3 servers take handlers that
    conform to this trait. The full request lifecycle is duplicated here so
    that on_h3_request can take an H3Context argument that doesn't exist in
    StreamHandler.

    A handler that wants to serve BOTH H3 and lower protocols implements
    both StreamHandler and H3StreamExtension. The H3 server uses the H3 path;
    the H1/H2 servers use the StreamHandler path. The two implementations
    typically share private helper methods on the same struct."""

    def on_h3_request(
        mut self,
        var req: Request,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
        caps: Capabilities,
    ) raises

    def on_body_available(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises

    def on_request_end(
        mut self,
        mut body: RecvBody,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises

    def on_send_drained(
        mut self,
        mut resp: ResponseWriter,
        mut h3: H3Context,
    ) raises

    def on_reset(
        mut self,
        error: StreamError,
    )


struct H3Context(Movable):
    """H3-specific per-stream context. Provides access to features that
    have no analog in H1 or H2. In v1 this is scaffolding only — datagram
    methods return WriteResult.closed() until M5 wires them up."""

    var _stream_id: UInt64
    var _datagram_send_id: UInt64
    var _datagram_recv_queue: Deque[List[UInt8]]

    def stream_id(self) -> UInt64
    def try_send_datagram(mut self, payload: Span[UInt8]) -> WriteResult
    def try_recv_datagram(mut self) -> Optional[List[UInt8]]
```

**Server registration**: H3 servers (future, not in M2.5) take a generic `Http3Server[H: H3StreamExtension]`. H2 servers take `Http2Server[H: StreamHandler]`. H1 servers take `Http1Server[H: StreamHandler]`. Three concrete server types, three trait constraints, no overlap. Handlers implementing both traits are explicit dual implementations.

### 5.11 `Session` trait and `RequestHandle`

```mojo
trait Session(Movable, ImplicitlyDestructible):
    """Client-side connection session. Owns the underlying connection (single
    H1 socket, multiplexed H2/H3 connection, etc). Submits requests, drives
    the I/O loop until handles complete.

    Single-connection only. Connection pooling lives one layer up (M6's
    HttpClient). The Session trait is compile-time monomorphic — each
    protocol implementation (H1Session, H2Session, H3Session) is a distinct
    type. M6 composes them via a tagged enum or vtable indirection; that
    decision is deferred to M6 and does not affect this trait surface.

    Reentrancy:
      • Cross-session calls from inside a handler callback are SUPPORTED
        (this is the reverse-proxy pattern).
      • Same-session calls (calling submit on the SAME session from inside
        a handler callback that was driven by that session's run_until) are
        UNSUPPORTED in v1 — the behavior is unspecified and may deadlock.
        Plan accordingly."""

    def submit(mut self, var req: Request) raises -> RequestHandle
    """Queue a request for sending. Consumes the Request. Returns a handle
    that the caller drives via run_until / run_one. Callers retain
    ownership of the handle and pass its `id()` to run_until."""

    def run_until(mut self, mut handle_ids: Deque[UInt64]) raises
    """Drive the I/O loop until every handle named in `handle_ids` is
    complete or errored. The caller still owns the actual RequestHandle
    objects (which the session updates in place via internal back-references);
    `handle_ids` is just a wait-set.

    M2.5a deviation from earlier draft: this parameter was originally
    `mut handles: List[RequestHandle]`. Mojo 0.26.2's stdlib `List` and
    `Deque` require Copyable element types and `RequestHandle` is move-only
    (it owns Optional[RecvBody] / Optional[Response]). Passing IDs sidesteps
    the constraint without forcing RequestHandle to become Copyable. HC-4
    can revisit if a non-copying collection becomes available."""

    def run_one(mut self, mut handle: RequestHandle) raises
    """Convenience: drive until a single handle is complete."""

    def capabilities(self) -> Capabilities
    def alpn(self) -> Int                       # ALPN_*
    def close(deinit self) raises


comptime _HANDLE_PENDING          = 0
comptime _HANDLE_HEADERS_RECEIVED = 1
comptime _HANDLE_COMPLETE         = 2
comptime _HANDLE_ERRORED          = 3

struct RequestHandle(Movable):
    """Owning handle to an in-flight request. Created by Session.submit,
    consumed by Session.run_until + take_response. Owns the response and
    body data once they arrive."""

    var _id: UInt64
    var _state: Int
    var _response: Optional[Response]
    var _recv_body: Optional[RecvBody]
    var _error: Optional[StreamError]

    def is_complete(self) -> Bool
    def has_headers(self) -> Bool
    def is_errored(self) -> Bool
    def id(self) -> UInt64

    def try_take_response(mut self) -> Optional[Response]
    """Returns the response if headers have been received, leaving the body
    in the handle. Returns None otherwise."""

    def take_response(deinit self) raises -> Response
    """Consumes the handle and returns the Response. Raises if the handle is
    not yet complete or has errored. Use is_complete() to check first or
    drive via session.run_until([handle])."""

    def take_body(mut self) raises -> RecvBody
    """Detach the response body from the handle for streaming consumption.
    The client-side analog of RecvBody.detach() (§5.5). Must be called after
    has_headers() returns True. The handle remains valid for take_response
    thereafter, but take_response will fail if the body has been detached
    and not consumed (the response object expects to own the body). Standard
    usage is take_body XOR take_response, not both."""
```

### 5.12 `RequestBody` — buffered or streaming

To support the reverse-proxy and SSE patterns from §5.5, the `Request` type's body field is generalized to a tagged union that can carry either a buffered byte array (existing M2 case) or a `DetachedBody` (new in M2.5a):

```mojo
# src/http/request.mojo (extended)

comptime _REQ_BODY_BUFFERED = 0
comptime _REQ_BODY_STREAM   = 1

struct RequestBody(Movable):
    """Request body source. Either an in-memory byte buffer (the common case
    for small uploads, JSON requests, etc) or a DetachedBody acting as a
    streaming source (for body forwarding in proxies, large uploads, SSE-style
    chunked sends).

    The receiving Session implementation must handle both variants. The
    Buffered variant is sent in one go (subject to the flow control window);
    the Stream variant is drained frame-by-frame as the runtime makes
    progress."""

    var _tag: Int
    var _bytes: List[UInt8]
    var _stream: Optional[DetachedBody]

    @staticmethod
    def buffered(var bytes: List[UInt8]) -> Self
    @staticmethod
    def stream(var detached: DetachedBody) -> Self
    @staticmethod
    def empty() -> Self

    def is_buffered(self) -> Bool
    def is_stream(self) -> Bool
    def is_empty(self) -> Bool

    def bytes(ref self) -> ref [self._bytes] List[UInt8]
    def stream(mut self) -> ref [self._stream] Optional[DetachedBody]
    def take_stream(deinit self) -> DetachedBody
```

The existing `Request` body field is migrated from `List[UInt8]` to `RequestBody`. M2 code that constructs requests with byte-array bodies uses `RequestBody.buffered(bytes^)`. The reverse-proxy refactor (§8.3) uses `RequestBody.stream(body.detach())`.

**Session implementation responsibilities**: each concrete `Session` implementation (`H1Session`, future `H2Session`, etc) must handle both `RequestBody` variants. For `Buffered`, the existing M2 path applies. For `Stream`, the session drains frames from the `DetachedBody` as the outbound flow control window opens, pushing data into the wire-format encoder. End-of-stream and error handling propagate from the inbound `DetachedBody` to the outbound stream naturally.

**M2.5a request trailers note**: `RequestBody` deliberately has no slot for trailers. The H1 parser drops any chunked-request trailers it sees (request trailers in the wild are exceedingly rare), and `serialize_request` raises if asked to encode a streaming `RequestBody` since the sans-I/O serializer has no streaming path. The cross-validation suite skips trailer comparison for request vectors. HC-4 (HTTP/2) will need to revisit this — H2 streams trailers as a separate `HEADERS` frame after the body, so the trait surface will likely grow either a request-side trailer accessor on `RequestBody` or a separate trailers parameter on `Session.submit`.

### 5.13 `Request.clone()` / `try_clone()`

To support replay/retry use cases:

```mojo
# src/http/request.mojo (extended)

struct Request:
    # ...existing fields...
    var body: RequestBody    # was: List[UInt8]

    def clone(self) raises -> Self
    """Deep copy of the request. In v1, requests with Buffered bodies clone
    successfully (the byte array is deep-copied). Requests with Stream bodies
    raise StreamError.protocol(...) — DetachedBody is one-way and cannot be
    duplicated. Use try_clone for fallible variant."""

    def try_clone(self) -> Optional[Self]
    """Non-raising deep copy. Returns None if the body is a Stream variant,
    Some(clone) if Buffered or Empty."""
```

**Note on the M2 migration**: changing `Request.body` from `List[UInt8]` to `RequestBody` is a small breaking change to M2 code, but the surface area is contained (~10 call sites in M2's reverse proxy, h1 server/client). It's part of the M2.5a refactor.

---

## 6. Configuration constants

```mojo
# src/http/config.mojo
# Defaults intentionally match hyper exactly. NOT stable API — may change as
# we benchmark against real workloads. See:
#   https://github.com/hyperium/hyper/blob/master/src/proto/h2/server.rs

# Stream-level body queue watermarks
comptime DEFAULT_STREAM_WINDOW_HIGH      = 1024 * 1024   # 1 MiB
comptime DEFAULT_STREAM_WINDOW_LOW       = 256  * 1024   # 256 KiB (1/4 of high)

# H2 connection-level flow control window (no equivalent in H3)
comptime DEFAULT_CONN_WINDOW             = 1024 * 1024   # 1 MiB

# Per-frame size limits
comptime DEFAULT_MAX_FRAME_SIZE          = 16   * 1024   # 16 KiB
comptime DEFAULT_MAX_SEND_BUF_SIZE       = 400  * 1024   # ~400 KiB

# Header limits
comptime DEFAULT_MAX_HEADER_LIST_SIZE    = 16   * 1024   # 16 KiB

# Concurrency limits
comptime DEFAULT_MAX_CONCURRENT_STREAMS  = 200

# Timeouts and DoS limits
comptime DEFAULT_KEEP_ALIVE_TIMEOUT_SECS = 20
comptime DEFAULT_MAX_LOCAL_RESET_STREAMS = 1024
```

**Worst-case memory math**: 200 streams × 1 MiB = 200 MiB per connection. 10,000 connections × 200 MiB = 2 TiB. This is the *theoretical* worst case; realistic working set is 5-20% (streams rarely fill their windows simultaneously). Memory-constrained users override per session via a per-impl convenience method (`H1Session.with_stream_window(N)`, etc) — the override mechanism is not on the `Session` trait itself; it's a constructor option on each concrete implementation.

---

## 7. Helper modules — M2.5b only

These ship in **M2.5b** as a parallel-runnable wave after M2.5a. They are independent of the trait surface (they don't import from `handler.mojo` or `session.mojo` except via SSE's wrapper around `RecvBody`/`SendBody`).

### 7.1 `src/http/priority.mojo` — RFC 9218

Implements parsing and serialization of the `Priority` header.

```mojo
struct Priority(Copyable, Movable):
    var urgency: Int     # 0..7, default 3 (RFC 9218 §4.1)
    var incremental: Bool

    @staticmethod
    def default() -> Self    # urgency=3, incremental=False

    @staticmethod
    def parse_header(value: String) raises -> Self
    """Parses a Priority header value per RFC 9218 §4.
    Examples: "u=1", "u=5, i", "u=3, i=?0"."""
    # M2.5b: byte-scanning via .as_bytes() + UInt8 constants + chr(Int(b))
    # accumulation — String[i] and slicing are unsupported in Mojo 0.26.2.
    # comptime DEFAULT_URGENCY = 3 without `: Int` annotation (matches
    # existing ALPN_* pattern in handler.mojo).

    def serialize_header(self) -> String
    """Serializes to header value form. Omits default values."""
```

The H2/H3 PRIORITY_UPDATE frame integration happens in HC-4 / M5; M2.5 only ships the parser/serializer.

### 7.2 `src/http/alt_svc.mojo` — RFC 7838

```mojo
# M2.5b: Origin(KeyElement), not (Copyable, Movable) — KeyElement is the
# composite Dict-key trait in std.collections.dict; EqualityComparable
# doesn't exist (only Equatable) and Hashable lives under hashlib.hash.
struct Origin(KeyElement):
    var scheme: String   # "https" | "http"
    var host: String
    var port: UInt16

struct AltSvcEntry(Copyable, Movable):
    var protocol: String   # "h3", "h2", "h2c", "http/1.1"
    var host: String       # may be empty (same as origin)
    var port: UInt16
    var max_age_secs: UInt
    var persist: Bool

# M2.5b: free function parse_alt_svc(), not a @staticmethod on a struct.
def parse_alt_svc(value: String) raises -> List[AltSvcEntry]
# M2.5b: _split_top_level takes sep: UInt8 (not String). Three internal
# helpers (_strip_ws, _split_top_level, _parse_one_entry) use byte-scanning.

struct AltSvcCache:
    var _entries: Dict[Origin, List[AltSvcEntry]]
    # M2.5b: field is _received_at (UInt timestamp), not _expiry.
    var _received_at: Dict[Origin, UInt]

    def insert(mut self, var origin: Origin, entries: List[AltSvcEntry], received_at: UInt)
    # M2.5b: lookup, clear, clear_expired all marked `raises` because
    # Dict.__getitem__ and Dict.pop raise on missing key in Mojo 0.26.2.
    def lookup(self, origin: Origin, now: UInt) raises -> List[AltSvcEntry]
    # M2.5b: clear takes origin by borrow (not var) — callers keep using it.
    def clear(mut self, origin: Origin) raises
    def clear_expired(mut self, now: UInt) raises
```

### 7.3 `src/http/sse.mojo` — text/event-stream

```mojo
struct ServerSentEvent(Copyable, Movable):
    var event: Optional[String]
    var data: String
    var id: Optional[String]
    var retry: Optional[UInt]
    # M2.5b: Optional fields use direct-assign in copy ctor (Optional is
    # ImplicitlyCopyable in Mojo 0.26.2; .copied() exists but .copy() does not).

struct EventStreamReader(Movable):
    """Wraps a DetachedBody (note: DetachedBody, not RecvBody — SSE always
    detaches). Parses incoming bytes into events incrementally."""
    var _body: DetachedBody
    var _buffer: List[UInt8]
    # M2.5b: added _body_ended: Bool field to track stream termination.
    var _body_ended: Bool

    def __init__(out self, var body: DetachedBody)
    def try_next_event(mut self) raises -> Optional[ServerSentEvent]
    def is_end(self) -> Bool
    # M2.5b: when _body_ended is True and no blank-line boundary found,
    # buffer is cleared (WHATWG §9.2 discards incomplete events at stream
    # end). Without this, is_end() would return False forever on a body
    # that terminates mid-event — fixed in commit 8f43e38.

# M2.5b: EventStreamWriter struct REPLACED by try_write_event free function.
# The sketch's UnsafePointer[ResponseWriter, MutAnyOrigin] contradicts its
# own "does NOT take ownership" doc and carries lifetime risk in Mojo 0.26.2.
# SSE writers need no per-call state; the caller passes ResponseWriter by
# mutable reference on each call.
def try_write_event(
    mut resp: ResponseWriter,
    event: ServerSentEvent,
) raises -> WriteResult
```

---

## 8. M2 refactor — M2.5a only

The traits are validated by refactoring existing M2 code onto them. This is the M2.5a acceptance criterion.

### 8.1 `src/h1/server.mojo`

Becomes generic over `[H: StreamHandler]`. The existing `H1Connection` state machine is wrapped to invoke handler callbacks at the right transitions:

- Parser produces complete request → call `handler.on_request(req, body, resp, Capabilities.for_h1())`
- Body chunks arrive → push into `RecvBody._push`, call `handler.on_body_available` if previously empty AND body not detached
- Body ends → push End frame, call `handler.on_request_end` if not detached
- `resp.try_send_body` queues bytes → next iteration drains via `H1Connection.serialize_response`
- `resp.end` triggers final flush

Estimated change: ~200 lines.

### 8.2 `src/h1/client.mojo`

Implements `Session`. The existing request submission becomes `Session.submit`; the existing drive loop becomes `Session.run_until`.

Estimated change: ~150 lines.

### 8.3 `examples/reverse_proxy/main.mojo`

Refactored to use `StreamHandler` for the inbound side and `Session` for the outbound side. Uses `body.detach()` to forward inbound body to outbound request without manual frame pumping. The existing 976-line file should drop to ~600 lines because the buffer management plumbing moves into the trait substrate.

**Acceptance**: all existing M2 e2e tests must still pass against the refactored proxy.

---

## 9. Research spike (parallel) — M2.5a only

`research/mojo-async-executor.md` is a 2-3 day investigation, run in parallel with M2.5a implementation, **not blocking it**.

### Goals

1. Document the public Mojo coroutine API (`Coroutine`, `RaisingCoroutine`, `AnyCoroutine`) and confirm the `!co` MLIR dialect's existence.
2. Probe whether `__mlir_op."co.resume"` and friends are accessible from Mojo source.
3. If yes, build a minimal POC: an "async echo server" using a custom boucle executor that drives Mojo coroutines using io_uring completions as wakeup signals.
4. Report findings as `research/mojo-async-executor.md`.
5. If the spike succeeds, file a follow-up milestone proposal for **M2.6: AsyncBody adapter**. M2.5 remains callback-only regardless of outcome.

The spike is exploratory; positive findings inform future planning, they do not change M2.5's deliverables.

---

## 10. Test plan

### 10.1 Unit tests — M2.5a

| File | Coverage |
|---|---|
| `tests/http/test_capabilities.mojo` | Factory functions, equality, copy semantics, is_h1/h2/h3, alpn_string |
| `tests/http/test_body_frame.mojo` | New End + Error variants, predicates, accessors, frame ordering rule |
| `tests/http/test_recv_body.mojo` | push/pull, watermarks, pause/resume notification, error injection, end semantics, **detach()** |
| `tests/http/test_send_body.mojo` | write/drain, watermarks, WouldBlock semantics, end/abort, idempotency |
| `tests/http/test_response_writer.mojo` | send_status precedence, double-send rejection, informational handling, end semantics |
| `tests/http/test_mock_session.mojo` | Mock substrate roundtrip + assertion API |
| `tests/http/test_handler_lifecycle.mojo` | Drive a stub `StreamHandler` through `MockServer` for all five lifecycle methods |
| `tests/http/test_handler_detach.mojo` | Verify on_body_available NOT called after detach; DetachedBody pumps frames correctly |
| `tests/http/test_session_handle.mojo` | `RequestHandle` state machine, `take_response` ownership, `take_body` semantics |
| `tests/http/test_request_body.mojo` | `RequestBody` factories, predicates, take_stream semantics |
| `tests/http/test_request_clone.mojo` | `clone()` / `try_clone()` for Buffered (succeeds) and Stream (fails/None) bodies |

### 10.2 Integration tests — M2.5a

| File | Coverage |
|---|---|
| `tests/integration/test_h1_server_handler.mojo` | Refactored `H1Server` accepts a `StreamHandler` and serves a known request set |
| `tests/integration/test_h1_client_session.mojo` | Refactored `H1Client` implements `Session` and round-trips requests |
| `tests/integration/test_reverse_proxy.mojo` | Refactored proxy passes the existing M2 e2e suite + uses detach |

### 10.3 Unit tests — M2.5b

| File | Coverage |
|---|---|
| `tests/http/test_priority.mojo` | RFC 9218 vectors |
| `tests/http/test_alt_svc.mojo` | RFC 7838 vectors |
| `tests/http/test_sse.mojo` | text/event-stream parser conformance against the WHATWG test suite (subset) |

### 10.4 Stretch tests (if M2.5a completes early)

| File | Coverage |
|---|---|
| `tests/integration/test_sse_backpressure.mojo` | Server pushes events to a slow client; validates `try_send_body` → `WouldBlock` → `on_send_drained` round-trip |
| `tests/integration/test_large_upload.mojo` | Client streams a multi-MiB body; validates request-side backpressure |
| `tests/integration/test_handler_abort.mojo` | Handler raises mid-response; validates the runtime sends RST/close and calls `on_reset` |

These become required for HC-4 / M5.5.

### 10.5 What is NOT tested in M2.5

- `H3StreamExtension.on_h3_request` and the H3 lifecycle path. No H3 server exists in M2.5; the trait and `H3Context` are scaffolding for M5. Acceptance criterion §11.x covers only the five `StreamHandler` callbacks.
- Datagram methods on `H3Context` — they return `WriteResult.closed()` in v1.

---

## 11. Acceptance criteria

### 11.1 M2.5a (HC-4 unblocker)

M2.5a ships when **all** of the following are true:

1. `src/http/handler.mojo`, `src/http/h3_extension.mojo`, `src/http/session.mojo`, `src/http/config.mojo`, `src/http/mock_session.mojo` are implemented per §5–§6.
2. `src/http/body.mojo` is extended with End and Error variants per §5.2.
3. `src/http/request.mojo` is extended with `clone()` and `try_clone()` per §5.12.
4. All M2.5a unit tests in §10.1 pass.
5. All M2.5a integration tests in §10.2 pass.
6. `H1Server` implements `StreamHandler`-based dispatch per §8.1.
7. `H1Client` implements `Session` per §8.2.
8. The reverse proxy example is refactored onto the new traits per §8.3 and uses `body.detach()`.
9. **All existing M2 e2e tests pass against the refactored proxy.**
10. The mock substrate exercises all five `StreamHandler` lifecycle callbacks (not `on_h3_request`).
11. `research/mojo-async-executor.md` exists with findings, regardless of outcome.
12. `docs/project-context.md` updated to mark M2.5a complete.
13. No regressions in `bash conformance/scripts/run_tests.sh` (27/27).
14. No regressions in `bash scripts/run_tests.sh` (existing src tests).

### 11.2 M2.5b (M6 unblocker; can run in parallel with HC-4)

M2.5b ships when **all** of the following are true:

1. `src/http/priority.mojo`, `src/http/alt_svc.mojo`, `src/http/sse.mojo` are implemented per §7.
2. All M2.5b unit tests in §10.3 pass.
3. Priority and Alt-Svc parsers are conformant against their respective RFC examples.
4. SSE parser round-trips through the trait surface using `DetachedBody` and `EventStreamReader`.
5. `docs/project-context.md` updated to mark M2.5b complete.

---

## 12. Delivery: M2.5a / M2.5b split

### Why split

- **De-risks the trait shape.** If the trait surface is wrong (the §13 "uglier proxy" escape valve fires), only M2.5a is redone. The helper modules in M2.5b never depended on it.
- **HC-4 unblocks sooner.** HC-4 can start once M2.5a ships, ~25% faster than waiting for the full M2.5.
- **M2.5b runs in parallel.** Helper modules don't need HC-4 or M2.5a to be done — they're protocol-agnostic. They can be implemented in a separate worktree concurrently.
- **Smaller acceptance gates.** Each wave has its own clear "is this done" question.

### M2.5a contents (~3,250 LoC, the riskier wave)

**New files:**
- `src/http/handler.mojo` (~500 LoC including detach scaffolding)
- `src/http/h3_extension.mojo` (~150 LoC)
- `src/http/session.mojo` (~250 LoC)
- `src/http/config.mojo` (~50 LoC)
- `src/http/mock_session.mojo` (~400 LoC)

**Extended files:**
- `src/http/body.mojo` (+~50 LoC for End/Error variants)
- `src/http/request.mojo` (+~120 LoC for `RequestBody` tagged union, `clone()` / `try_clone()`, body field migration from `List[UInt8]` to `RequestBody`)

**Refactored files:**
- `src/h1/server.mojo` (~200 LoC of changes)
- `src/h1/client.mojo` (~150 LoC of changes)
- `examples/reverse_proxy/main.mojo` (~600 LoC, down from 976)

**Tests:**
- 9 unit test files in `tests/http/` (~1,000 LoC total)
- 3 integration test files in `tests/integration/` (~400 LoC total)

**Research:**
- `research/mojo-async-executor.md` (~300 LoC + POC code)

### M2.5b contents (~950 LoC, the safer wave)

**New files:**
- `src/http/priority.mojo` (~200 LoC)
- `src/http/alt_svc.mojo` (~250 LoC)
- `src/http/sse.mojo` (~300 LoC)

**Tests:**
- 3 unit test files in `tests/http/` (~200 LoC total)

### Sequencing

```
   Time →
   ├──── M2.5a ────┤
                    ├──── HC-4 starts here ──→
   ├─── M2.5b ────────┤  (parallel, separate worktree)
```

M2.5b can begin as soon as M2.5a's trait shape is solidified (after the reverse-proxy refactor proof, even before all M2.5a tests are written) — but it does not gate HC-4 in any way.

---

## 13. Estimated effort

| Wave | New code | Refactored code | Tests | Total |
|---|---|---|---|---|
| M2.5a | ~1,750 | ~950 | ~1,400 | ~4,100 |
| M2.5b | ~750 | 0 | ~200 | ~950 |
| **Total** | **~2,500** | **~950** | **~1,600** | **~5,050** |

Larger than M2 by ~25%. Most of M2.5b is well-bounded RFC parser work that's testable in isolation. The unique design risk is the trait surface in M2.5a; the refactor of M1/M2 onto the new traits is the proof.

---

## 14. Risks and areas requiring care

### 14.1 Risks

- **Trait dispatch in Mojo 0.26.2 is still maturing.** The standalone `H3StreamExtension` design avoids betting on trait inheritance with method override (which is fictional). Each protocol gets its own concrete server type with its own trait constraint.
- **`fn() escaping` callbacks may not be expressible cleanly in Mojo 0.26.2.** Fallback: integer-keyed callback registry (`_on_drain_id: UInt64` indexes into a runtime registry). The spec already uses this pattern as the documented approach.
- **Body detach implementation is the trickiest part of M2.5a.** The runtime must continue pushing frames into a detached body using a registered ID, and lifecycle callbacks must be suppressed for streams whose body has been detached. Implementer must verify both behaviors with tests.
- **Reverse proxy refactor must produce *cleaner* code** than today's hand-written version. If the refactored version is uglier, the trait shape is wrong and we go back to brainstorming. This is the design's main escape valve.
- **MockSession expressiveness** for modeling H1 + H2 + H3 in one type may not scale. Decision rule: when M5 (H3) wires up, if adding H3 support to MockSession would more than double the file size, split into `MockH1Session`, `MockH2Session`, `MockH3Session`. Re-evaluated at HC-4 / M5.5.
- **`H3Context` is scaffolding without an implementation.** Datagram methods return `WriteResult.closed()` in v1.
- **Hyper-matched 1 MiB defaults** mean a worst-case 200 MiB per connection. Documented in `src/http/config.mojo`.

### 14.2 Areas requiring care

- **Watermark accounting**: `bytes_buffered` counts only Data variants, not Trailers, End, or Error. Counting trailers/End/Error can deadlock the stream.
- **Error precedence**: if a `RecvBody` errors *and* receives an end frame in the same I/O loop tick, the error wins. Explicit ordering in `_set_end` / `_set_error`.
- **`take_response` semantics**: must consume the handle. Dropping a handle without `take_response` leaks the response and body until the destructor runs. Document clearly.
- **`take_body` XOR `take_response`**: standard usage is one or the other, not both. Document on `RequestHandle`.
- **Reentrancy**: cross-session reentry is supported (reverse proxy). Same-session reentry from inside a handler driven by `run_until` is UNSUPPORTED in v1.
- **Privacy of `_push` / `_pop` etc.**: Mojo 0.26.2 has no crate-level privacy. The underscore convention plus documentation is the v1 enforcement. Sealed-trait pattern explored if Mojo's trait system supports it.
- **DetachedBody must not be resurrected back into runtime ownership.** Detach is one-way.

---

## 15. Decision log

| Decision | Choice | Reason |
|---|---|---|
| Death-star scope | Tiers 1-4 + Alt-Svc + SSE; datagrams = capability flag only | User specified |
| Handler execution model | Callback primitive (γ hybrid); blocking/async adapters deferred | Mojo's async runtime is experimental and not pluggable to custom I/O sources |
| Body model | γ (push from runtime, pull from handler via per-stream queue) | Pure pull (β) requires coroutine integration we don't have; pure push (α) makes SSE awkward |
| Capability negotiation | Model C (unified trait + opt-in H3 extension + runtime flags) | Model A is dishonest; Model B creates origin-soup and breaks M6's runtime ALPN dispatch |
| Body API methods | Execution-model-neutral: `try_read`, `is_end`, `write`, `end`. No `read()`/`async fn read()` in v1 | Permits future blocking and async adapters as additive wrapper types |
| Body ownership across callbacks | Hybrid with explicit `detach()` | Simple inline handlers stay simple; reverse-proxy and SSE patterns get a clean escape hatch via one-way detach |
| H3StreamExtension shape | **Standalone trait (no inheritance)** | Trait inheritance with method override is fictional in Mojo; standalone traits with full lifecycle methods avoid the fiction |
| Session polymorphism | **Compile-time monomorphic; M6 composes via tagged enum or vtable (deferred)** | Mojo 0.26.2 has no trait objects; the trait surface itself doesn't need to commit, M6 picks the composition mechanism |
| Client API shape | Option d (handle-based substrate + convenience wrappers in M6) | Supports single-request, batch, and streaming patterns; future-proof for async migration |
| Request ownership | Owning (`var req: Request` in `Session.submit`) | Identical performance, strictly safer, avoids origin propagation, aligns with industry consensus |
| Backpressure model | Soft watermarks, automatic pause/resume, single-channel error reporting | Standard pattern; auto-management keeps handlers simple |
| Default constants | Match hyper exactly | Battle-tested, apples-to-apples benchmarking |
| HTTP/3 as canonical shape | Yes (death-star is H3 fast server) | API designed against H3 semantics; H1/H2 are projections |
| Build order | HC-4 (H2) → M5.5 → M3 → M5 (H3) | H2 has stronger oracles; H2 has smaller scope |
| Async research spike | Parallel to M2.5a, not blocking | An unanswered question shouldn't gate a milestone |
| Mock substrate location | `src/http/`, not `tests/` | Downstream consumers need them |
| Trait method declaration | **`def`, not `fn`** | Matches existing M2 code at `src/http/body.mojo:43` |
| Move ctor / destructor convention | **`def __init__(out self, *, deinit take: Self)` + `fn __del__(deinit self)`** | Verified against M2 code |
| BodyFrame end-of-stream marker | **Explicit `End` variant (4th tag)** | Avoids ambiguity between "no data yet" and "stream ended" |
| `Session.run_until` semantics | **Mutates handles in place via list indexing** | Caller retains ownership of the list; clean call site |
| `Capabilities.alpn` representation | **Integer constant (`Int`), not `String`** | Avoids per-stream String allocation |
| Delivery | **Split into M2.5a (core, HC-4 unblocker) + M2.5b (helpers, parallel)** | De-risks trait shape; HC-4 unblocks ~25% sooner; M2.5b runs in parallel |

---

## 16. Future extensions designed for

The trait surface is deliberately designed to admit these as additive changes, not breaking ones:

- **Blocking adapter (M2.6 candidate)**: a `BlockingBody` wrapper that exposes `read() -> Optional[BodyFrame]` and a `BlockingSession` wrapper that runs the I/O loop on a separate OS thread. Application code uses sync calls; under the hood the adapter bridges to the callback substrate.
- **Async adapter (M2.6 or M2.7 candidate)**: an `AsyncBody` wrapper exposing `async fn read() -> Optional[BodyFrame]` and an `AsyncSession` wrapper integrating with Mojo's coroutine runtime. Depends on Modular shipping pluggable executors OR on the research spike succeeding with a custom executor in boucle.
- **Connection pooling (M6)**: `HttpClient` wraps a pool of `Session` implementations keyed by `(scheme, host, port)`, with idle eviction, max-connections-per-host limits, and Alt-Svc-driven protocol upgrades. Composition mechanism (tagged enum vs vtable) chosen at M6 implementation time.
- **High-level convenience API (M6)**: `HttpClient.get(url)`, `HttpClient.post(url, body)`, retries, redirects, cookies, content decoding, middleware. All built on top of the Session/RequestHandle substrate.
- **WebTransport / HTTP/3 datagrams (post-M5)**: `H3Context` already has the method signatures; M5 wires up the actual datagram path.
- **Server push (post-M5)**: extends `H3Context` with `push_promise` methods. Currently absent because server push is effectively dead in practice.

---

## 17. Open questions (deferred to planning or implementation time)

1. **Sealed trait enforcement for runtime-internal methods.** Can Mojo 0.26.2 express "this method is callable from a specific set of modules"? If yes, use it for `_push`/`_pop`/etc. If no, document and rely on convention.
2. **Callback registry vs `fn() escaping`** for `_on_drain` callbacks. Verify which approach Mojo 0.26.2 supports cleanly.
3. **`MockSession` mode flags vs split types.** Defer to M5 timeframe. v1 only needs H1 mode.
4. **Configuration override mechanism.** `H1Session.with_stream_window(N)`-style builder vs an explicit `Config` struct passed to constructors. Decide during M2.5a planning.
5. **`take_body` after `take_response`?** Standard usage is XOR. Implementation should raise on the second call. Confirm during planning.
6. **DetachedBody implementation strategy.** How does the runtime keep pushing into a detached body? Two options: (a) the runtime stores a stable pointer to the body's internal queue and writes through it; (b) the runtime stores a registered ID and looks up the queue in a registry per push. Decide during planning based on Mojo ergonomics. Note: option (a) tensions with `DetachedBody(Movable)` because moving the body invalidates the pointer; option (b) is move-safe. If the chosen approach is (a), `DetachedBody` becomes `Movable but not after detach is registered` which is hard to express in Mojo — registry approach (b) is likely the right answer.

7. **`H3StreamExtension` detach semantics.** Does `body.detach()` work the same way for H3 handlers (suppressing `on_body_available` / `on_request_end`)? Probably yes — `H3Context` is per-stream and orthogonal to body ownership — but document explicitly during M5 planning.

8. **`def close(deinit self)` syntax verification.** Mojo 0.26.2 allows `deinit self` on regular methods (not just `__del__`)? Verify with Mojo MCP during M2.5a planning. If not, fall back to `__del__` for cleanup.

9. **`EventStreamWriter` pointer field.** Currently spec'd as `UnsafePointer[ResponseWriter, MutAnyOrigin]`. The mojo-tquic project convention is `UInt64` for pointer fields. `EventStreamWriter` is `Movable` (not `TrivialRegisterPassable`) so the typed pointer may be fine, but verify during M2.5b planning.

---

## End of spec
