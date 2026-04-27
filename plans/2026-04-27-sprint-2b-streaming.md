# Sprint 2B — H2 Rename + Tiered Streaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename `src/h2/h2_coro_server.mojo` → `src/h2/h2_sync_server.mojo` (Sprint 1 removed all coros from this file; the name is now misleading), then add the opt-in **streaming-handler tier** to H3 first (canonical-shape validation per `docs/project-context.md` line 54) and H2 second (applies the H3-validated API contract). Streaming connections pay 64 KiB/stream; sync connections continue to pay <1024 B/stream (R8). Codify R1' grep gate so future work cannot silently re-introduce `boucle.stackful` outside the streaming server files.

**Architecture:** Two streaming servers (`src/h2/h2_streaming_server.mojo` + `src/h3/h3_streaming_server.mojo`) live BESIDE the sync servers. Each streaming server holds a `boucle.stackful.CoroutinePool` and a per-stream `StreamingCtx` (~64 KiB each, holding the suspending stack + body-frame ring + response-write buffer). The streaming-handler signature is **identical across H2 and H3**: `fn(ctx_ptr: UnsafePointer[StreamingCtx, MutAnyOrigin], mut yld: CoroYielder) raises -> None`. User-facing helpers (`body.next_chunk(mut yld)`, `resp.write_chunk(mut yld, bytes)`, `resp.finish(mut yld)`, `ctx.cancelled() -> Bool`) are the only API surface that differs from the sync tier. Wire-format specifics live in the codec layer beneath, unchanged.

**Tech Stack:** Mojo 0.26.2+ (`comptime assert`); `boucle.stackful.{CoroutinePool, CoroHandle, CoroYielder, CoroBody}`; `src/h2/connection.H2Connection` + `src/h3/connection.H3Connection`; `src/io/{io_trait,io_uring}.mojo` (Sprint 1, unchanged).

**Prerequisite:** Plan 2A is complete and committed on `feat/h2-state-machine-path-a`. The Plan 2A retro working note (`plans/2026-04-27-sprint-2a-retro-notes.md`) is read at Task 0.1 to consume the Phase-1 H1 outcome + the `H3Connection.send_data` audit verdict.

**Out of scope (deferred):**
- H1 streaming companion (`h1_streaming_server.mojo`) — Sprint 2.5.
- Streaming-tier perf lift target — the deliverable is *shape*, not throughput.
- Mojo upstream `co_await` (Path C) — parallel track, not a Sprint 2 deliverable.

---

## File structure

### Created

| File | Purpose |
|---|---|
| `src/h3/h3_streaming_server.mojo` | H3 server using `boucle.stackful.CoroutinePool`. Streaming handler signature `fn(ctx_ptr, mut yld: CoroYielder) raises -> None`. R8' assert: `size_of[H3StreamingCtx]() < 96 * 1024`. |
| `src/h2/h2_streaming_server.mojo` | H2 mirror of `h3_streaming_server.mojo`. Resurrects Sprint-1-deleted `H2BodyYieldFn` / `resume_stream` / suspending body helpers from `git show main:src/h2/h2_coro_server.mojo` — re-audited against current types, NOT pasted. R8' assert: `size_of[H2StreamingCtx]() < 96 * 1024`. |
| `src/streaming/__init__.mojo` | Re-exports `StreamingCtx` (alias for the two protocol-specific ctx structs via a phantom-typed parameter) + `StreamingHandlerFn` type alias. **Created only if** Day-13 audit shows the user-facing signature genuinely is identical between H2 and H3 (it should be, per spec D4); if not, keep the per-protocol aliases inside their server modules. |
| `bench/streaming_handler.mojo` | LLM-stream pattern: emits N tokens at K-µs intervals via `resp.write_chunk(mut yld, ...)` + `yld.suspend()`. Used by both `bench/h2_streaming_server.mojo` and `bench/h3_streaming_server.mojo`. |
| `bench/h2_streaming_server.mojo` | Bench harness wiring `streaming_handler.mojo` through `H2StreamingServer`. |
| `bench/h3_streaming_server.mojo` | Bench harness wiring `streaming_handler.mojo` through `H3StreamingServer`. |
| `tests/test_h3_streaming_server.mojo` | H3 streaming tests. Picks up the MOVE-classified tests stashed in Plan 2A Task 2.2 (`tests/_h3_streaming_pending.mojo`); rewrites them against the new streaming server; deletes the stash file. |
| `tests/test_h2_streaming_server.mojo` | H2 streaming tests. Resurrects `test_body_yield` + `test_resume_stream` from `git show main:tests/test_h2_coro_server.mojo` against the new streaming server. |

### Renamed

| From | To |
|---|---|
| `src/h2/h2_coro_server.mojo` | `src/h2/h2_sync_server.mojo` (file content unchanged; struct rename `H2CoroServer` → `H2SyncServer` is **deferred** to a later sprint to minimise blast radius — many call sites would change). The rename is `git mv` only. |
| `tests/test_h2_coro_server.mojo` | `tests/test_h2_sync_server.mojo` |

### Modified

| File | Change |
|---|---|
| `src/h2/__init__.mojo` | Update import path for `H2CoroServer`; add `H2StreamingServer` re-export. |
| `src/h3/__init__.mojo` | Add `H3StreamingServer` re-export. |
| `src/h2/connection.mojo` | **Conditional on Day-11 audit:** add `H2Connection.send_data(...) -> SendResult` returning `Sent(n: Int) | WouldBlock | StreamClosed` if not present. |
| `src/h3/connection.mojo` | **Conditional on Day-9 audit:** add `H3Connection.send_data(...) -> SendResult` returning the same enum if not present. |
| `bench/h2_server.mojo` | Update import after rename. |
| `bench/h3_server.mojo` | (No change — already uses `H3CoroServer` from Plan 2A's renamed module.) |
| `scripts/run_tests.sh` | Add `tests/test_h2_streaming_server.mojo` + `tests/test_h3_streaming_server.mojo`; remove `tests/test_h2_coro_server.mojo` (renamed to `test_h2_sync_server.mojo`); remove the stub for `tests/_h3_streaming_pending.mojo` (deleted in Task 2.4); add the **R1' grep gate** as a separate test step. |

### Deleted

| File | Reason |
|---|---|
| `tests/_h3_streaming_pending.mojo` | Plan 2A's stash file, now consumed into `tests/test_h3_streaming_server.mojo`. |

---

## Phase 0 — Audits and rename (~1 day)

### Task 0.1: Read Plan 2A retro working note

**Files:**
- Read: `plans/2026-04-27-sprint-2a-retro-notes.md`

- [ ] **Step 1: Extract relevant findings**
Plan 2A Task 3.2 produced this note. Extract three pieces:
- The `H3Connection.send_data` audit verdict (R-2A-2 in Plan 2A) — does it expose `WouldBlock` or not? Drives Day-9 prerequisite audit (Task 1.1) priority.
- Final R8 size of `src/h3/h3_sync_server.mojo::CoroStreamCtx` — informs Task 1.6's R8' budget posture for `H3StreamingCtx`.
- Phase-1 pool decision — informs whether `H1StreamingCtxPool` would mirror or differ.

Write the three extractions into the Task 0.1 commit message as input to subsequent tasks.

### Task 0.2: Rename `h2_coro_server.mojo` → `h2_sync_server.mojo` (mechanical)

**Files:**
- Rename: `src/h2/h2_coro_server.mojo` → `src/h2/h2_sync_server.mojo`
- Rename: `tests/test_h2_coro_server.mojo` → `tests/test_h2_sync_server.mojo`
- Modify: `src/h2/__init__.mojo`, `bench/h2_server.mojo`, `scripts/run_tests.sh` (and any other callsites)

- [ ] **Step 1: `git mv` the source file**
Run: `git mv src/h2/h2_coro_server.mojo src/h2/h2_sync_server.mojo`

- [ ] **Step 2: `git mv` the test file**
Run: `git mv tests/test_h2_coro_server.mojo tests/test_h2_sync_server.mojo`

- [ ] **Step 3: Find every callsite that imports the old path**
Run: `grep -rn 'h2_coro_server' .worktrees/feat-h2-state-machine-path-a/src/ .worktrees/feat-h2-state-machine-path-a/bench/ .worktrees/feat-h2-state-machine-path-a/tests/ .worktrees/feat-h2-state-machine-path-a/scripts/`
Expected: a handful of matches in `src/h2/__init__.mojo`, `bench/h2_server.mojo`, `scripts/run_tests.sh`, and possibly cross-test imports.

- [ ] **Step 4: Replace each match with the new path**
For each match, replace `h2_coro_server` → `h2_sync_server` and `test_h2_coro_server` → `test_h2_sync_server`. The struct name `H2CoroServer` is preserved (NOT renamed to `H2SyncServer`) — that's a separate change with a much larger blast radius, deferred to a polish pass.

Verify zero remaining references:
Run: `grep -rn 'h2_coro_server' .worktrees/feat-h2-state-machine-path-a/`
Expected: zero matches.

- [ ] **Step 5: Build + run full test suite**
Run: `bash scripts/run_tests.sh`
Expected: all tests pass (count unchanged from end of Plan 2A).

Run: `bash conformance/scripts/run_tests.sh`
Expected: 35/35.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill.

---

## Phase 1 — H3 streaming server (canonical-shape validation, ~2 days)

### Task 1.1: Day-9 prerequisite audit — `H3Connection.send_data` `WouldBlock` surface

**Files:**
- Read: `src/h3/connection.mojo` (specifically the `send_data` family)

- [ ] **Step 1: Inspect the surface**
Read `src/h3/connection.mojo` and find the function(s) that send DATA frames on a stream. Verify whether the function:
- a) Returns `Int` (bytes accepted) and silently drops or buffers on FC window full — **insufficient**, blocks the streaming-handler from observing backpressure.
- b) Raises on FC window full — **insufficient**, exception cost is too high to drive an event loop.
- c) Returns a sentinel like `SendResult { Sent(Int), WouldBlock, StreamClosed }` — **sufficient**, this is the streaming-handler API requirement.

Plan 2A retro working note (Task 0.1 above) may already record this verdict.

- [ ] **Step 2: If (c), proceed to Task 1.2**

- [ ] **Step 3: If (a) or (b), add the SendResult sentinel**
This is a small precursor commit BEFORE writing the streaming server. Add the variant struct + adapt `send_data`:

```
# src/h3/connection.mojo (add near other public types)

struct H3SendResult(Movable):
    """Result of a non-blocking H3 DATA send. Flow-control aware."""

    var kind: UInt8  # 0 = Sent, 1 = WouldBlock, 2 = StreamClosed
    var bytes_sent: Int  # only meaningful when kind == 0

    def __init__(out self, *, kind: UInt8, bytes_sent: Int = 0):
        self.kind = kind
        self.bytes_sent = bytes_sent

    def __init__(out self, *, deinit take: Self):
        self.kind = take.kind
        self.bytes_sent = take.bytes_sent

    @staticmethod
    fn sent(n: Int) -> H3SendResult:
        return H3SendResult(kind=0, bytes_sent=n)

    @staticmethod
    fn would_block() -> H3SendResult:
        return H3SendResult(kind=1)

    @staticmethod
    fn stream_closed() -> H3SendResult:
        return H3SendResult(kind=2)
```

Adapt the existing `send_data` body (or add a new `send_data_nonblocking` variant alongside the existing one to avoid breaking H3HandlerServer / H3CoroServer (sync)) so it returns `H3SendResult`. Choose the approach that minimises blast radius: a new method is safer if the existing one has many call sites.

- [ ] **Step 4: Commit (only if step 3 ran)**
Use the `commit-smart` skill. Message describes this as a precursor to the streaming server.

### Task 1.2: Skeleton — create `src/h3/h3_streaming_server.mojo` with imports

**Files:**
- Create: `src/h3/h3_streaming_server.mojo`

- [ ] **Step 1: Write file header + imports**
```
# src/h3/h3_streaming_server.mojo
#
# HTTP/3 server-side adapter for STREAMING handlers. Each stream gets a
# 64 KiB stackful coroutine (boucle.stackful) so the handler can suspend
# across upstream I/O boundaries (LLM token emission, SSE, gRPC server-
# streaming, reverse proxy, file upload). Companion to
# `src/h3/h3_sync_server.mojo` — that's the default tier; this is opt-in.
#
# R8' compile-time budget: size_of[H3StreamingCtx]() < 96 KiB.
# R1' grep gate: this file IS allowed to import boucle.stackful.
#
# See plans/2026-04-27-sprint-2b-streaming.md.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

from boucle.stackful import (
    CoroutinePool,
    CoroHandle,
    CoroYielder,
    CoroBody,
)

from src.quic.connection import QuicConnection
from src.h3.connection import H3Connection, H3Event, H3SendResult
from src.h3.error import H3_REQUEST_CANCELLED
from src.h3.qpack import QpackHeaderField
from src.http.handler import (
    Capabilities,
    RecvBody,
    ResponseWriter,
    StreamError,
)
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.method import Method
from src.http.request import Request
from src.http.status import StatusCode
from src.http.version import Version
```

### Task 1.3: Define `H3StreamingHandlerFn` type alias

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Append**
```
# H3StreamingHandlerFn — handler invoked once per stream. Receives the
# per-stream ctx pointer + a CoroYielder. The handler may suspend
# (yld.suspend()) any number of times during the lifetime of the stream;
# each suspend returns control to the H3 event loop, which resumes the
# handler when more body data arrives or the writer-side window opens.

comptime H3StreamingHandlerFn = fn (
    UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut CoroYielder,
) raises -> None
```

(`H3StreamingCtx` is forward-referenced; defined in Task 1.4.)

### Task 1.4: Define `H3StreamingCtx` struct

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Append the struct**
The streaming ctx holds everything the H3 sync ctx holds, plus a few streaming-specific fields. Mirror `src/h3/h3_sync_server.mojo::CoroStreamCtx` (Plan 2A Task 2.5) and add:
- `body_frame_ring: List[BodyFrame]` — incoming body frames, drained by `body.next_chunk(mut yld)`. Capped at `body_ring_capacity` (default 8 frames).
- `writer_pending_chunk: Optional[List[UInt8]]` — last write-chunk that hit `WouldBlock`, retried on resume.
- `cancelled: Bool` — set true by adapter when STOP_SENDING / RST_STREAM / connection drop arrives; polled by handler via `ctx.cancelled()`.
- `coro_addr: UInt64` — address of heap-allocated `CoroHandle` (0 = none); identical to the pre-Sprint-1 H2 coro shape.

```
struct H3StreamingCtx(Movable):
    """Per-stream context for STREAMING H3 serving. Heap-allocated and
    pinned; the boucle.stackful coro stack lives on the heap inside the
    CoroHandle pointed to by `coro_addr`. Total cost: ~64 KiB stack +
    ~few hundred B of struct bookkeeping = <96 KiB (R8')."""

    var request:                Request
    var recv_body:              RecvBody
    var resp_writer:            ResponseWriter
    var caps:                   Capabilities
    var stream_id:              UInt64
    var extra_data:             UnsafePointer[NoneType, MutExternalOrigin]
    var coro_addr:              UInt64
    var request_ended:          Bool
    var response_ended:         Bool
    var headers_sent:           Bool
    var body_frame_ring:        List[BodyFrame]
    var writer_pending_chunk:   Optional[List[UInt8]]
    var cancelled:              Bool

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
        self.body_frame_ring = List[BodyFrame]()
        self.writer_pending_chunk = Optional[List[UInt8]](None)
        self.cancelled = False

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
        self.body_frame_ring = take.body_frame_ring^
        self.writer_pending_chunk = take.writer_pending_chunk^
        self.cancelled = take.cancelled

    def coro_ptr(self) -> UnsafePointer[CoroHandle, MutAnyOrigin]:
        return UnsafePointer[CoroHandle, MutAnyOrigin](
            unsafe_from_address=Int(self.coro_addr)
        )
```

### Task 1.5: Define streaming-handler API helpers — `next_chunk`, `write_chunk`, `finish`, `cancelled`

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Append the helpers as free functions taking `ctx_ptr` + `yld`**
The handler signature is `fn(ctx_ptr, mut yld) raises -> None`. Helpers are not methods on `H3StreamingCtx` — they're free functions in this module that take the ctx pointer + yielder. This keeps the user-facing call shape identical: `next_chunk(ctx, mut yld)`, `write_chunk(ctx, mut yld, bytes)`, `finish(ctx, mut yld)`, `cancelled(ctx)`. (Mojo 0.26 method dispatch on raw pointers is awkward; free functions sidestep it.)

```
def next_chunk(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises -> Optional[BodyFrame]:
    """Yield the next body chunk; suspend if none ready. Returns None on EOF.
    Polls cancellation between suspends."""
    while not ctx_ptr[].request_ended and len(ctx_ptr[].body_frame_ring) == 0:
        if ctx_ptr[].cancelled:
            raise StreamError(H3_REQUEST_CANCELLED)
        yld.suspend()
    if len(ctx_ptr[].body_frame_ring) > 0:
        var frame = ctx_ptr[].body_frame_ring.pop()
        return Optional[BodyFrame](frame^)
    return Optional[BodyFrame](None)


def write_chunk(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
    var bytes: List[UInt8],
) raises:
    """Send a body chunk. Suspends if writer-side window is full
    (H3SendResult.WouldBlock); resumes on writer-window-open event."""
    if ctx_ptr[].cancelled:
        raise StreamError(H3_REQUEST_CANCELLED)
    if not ctx_ptr[].headers_sent:
        # Lazy-send headers on first write_chunk.
        # The H3 server's _drain_responses takes care of actual transmit
        # by reading ctx.resp_writer; here we mark intent.
        ctx_ptr[].headers_sent = True
    ctx_ptr[].writer_pending_chunk = Optional[List[UInt8]](bytes^)
    # Suspend; the adapter will retry the send on each resume until
    # writer_pending_chunk is None, then resume the coro.
    while ctx_ptr[].writer_pending_chunk:
        if ctx_ptr[].cancelled:
            raise StreamError(H3_REQUEST_CANCELLED)
        yld.suspend()


def finish(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    """Close the response body. After this, the handler should return."""
    ctx_ptr[].response_ended = True
    yld.suspend()  # let the adapter run its drain pass


fn cancelled(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin]
) -> Bool:
    return ctx_ptr[].cancelled
```

### Task 1.6: R8' compile-time assert

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Append the assert helper**
```
# Per-stream memory budget for streaming ctx (R8' in the sprint roadmap).
#
# 64 KiB stack (boucle.stackful default) + ~32 KiB for the struct itself
# (body_frame_ring, writer_pending_chunk, request, recv_body, etc.) =
# < 96 KiB total per stream.

fn _check_streaming_ctx_size():
    comptime assert size_of[H3StreamingCtx]() < 96 * 1024, (
        "H3StreamingCtx exceeded R8' budget (96 KiB) — investigate"
        " before raising the cap"
    )
```

The helper is called from each `H3StreamingServer` constructor (Task 1.7).

### Task 1.7: Define `H3StreamingServer` struct + constructors + `__del__`

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Append the server struct**
Mirror Plan 2A's `H3CoroServer` (sync) struct shape but add a `_pool: CoroutinePool` field for the per-stream coro stacks. The `_streams` Dict still maps `stream_id` to a `_StreamingPtr` wrapper. The `_ctx_pool` field can use a smaller default (`capacity=4`) given the much larger per-ctx cost.

```
struct H3StreamingServer(Movable):
    """H3 server adapter for STREAMING handlers. Each stream gets a
    boucle.stackful coroutine; the handler may suspend across upstream
    I/O boundaries via `next_chunk(yld)` / `write_chunk(yld, ...)` /
    `finish(yld)` helpers."""

    var _quic: QuicConnection
    var _h3: H3Connection
    var _handler_fn: H3StreamingHandlerFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _StreamingPtr]
    var _ctx_pool: H3StreamingCtxPool
    var _coro_pool: CoroutinePool

    def __init__(
        out self,
        *,
        handler_fn: H3StreamingHandlerFn,
        extra_data: UnsafePointer[NoneType, MutExternalOrigin] = UnsafePointer[
            NoneType, MutExternalOrigin
        ](),
    ) raises:
        _check_streaming_ctx_size()
        # ... QUIC + H3 setup (mirror Plan 2A Task 2.9)
        self._handler_fn = handler_fn
        self._extra_data = extra_data
        self._outbuf = List[UInt8]()
        self._streams = Dict[Int, _StreamingPtr]()
        self._ctx_pool = H3StreamingCtxPool(capacity=4)
        self._coro_pool = CoroutinePool(capacity=4)
        self._flush_outbound()

    # ... (deinit take, __del__) — mirror Plan 2A pattern + free coro_addr
    # for every stream in __del__ before freeing the ctx itself.
```

Add a parallel `_StreamingPtr` Dict-element wrapper + `_free_streaming_stream` helper + `H3StreamingCtxPool` mirroring the sync versions but typed for `H3StreamingCtx`. (Yes, this is the second copy — R5/R9 forbid premature abstraction; the third copy in H2 gets folded into a shared module IFF the user-facing signature is genuinely identical at Day 13.)

### Task 1.8: Implement `feed_datagram_from_buffer` with streaming dispatch

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Mirror Plan 2A's H3 sync transport bridging**
Read `src/h3/h3_sync_server.mojo::feed_datagram_from_buffer` (the Plan 2A Task 2.10 result) — most of the body is identical. The differences:
- On `H3_EVT_REQUEST_HEADERS_RECEIVED`: instead of a sync ctx-pointer call (`self._handler_fn(ctx_ptr)`), allocate a `CoroHandle` from `self._coro_pool`, store its address in `ctx.coro_addr`, and schedule the first resume.
- On `H3_EVT_DATA_RECEIVED`: append the BodyFrame to `ctx.body_frame_ring` and resume the stored coro (if it was suspended in `next_chunk`).
- On `H3_EVT_STREAM_RESET` / `STOP_SENDING` / `H3_EVT_GOAWAY_RECEIVED` for the stream: set `ctx.cancelled = True` and resume the stored coro (so the suspended handler can observe cancellation and unwind).
- On writer-window-open (when `H3SendResult.WouldBlock` previously fired and now there's room): drain `ctx.writer_pending_chunk` via `self._h3.send_data(...)`; if accepted, set `writer_pending_chunk = None` and resume the coro.

The coro lifecycle mirrors the pre-Sprint-1 H2 coro server's pattern (which is what Plan 2A's audit-of-stashed-tests Task 2.1 handed off knowledge of). To resurrect the exact pattern, run `git show main:src/h2/h2_coro_server.mojo > /tmp/main_h2_coro.mojo` and read the `_resume_stream` / `coro_pool.acquire` / `CoroHandle` setup from that snapshot. Adapt to H3 events.

### Task 1.9: `_drain_responses` adapted for streaming write-chunks

**Files:**
- Modify: `src/h3/h3_streaming_server.mojo` (append)

- [ ] **Step 1: Drain pending chunks**
For each stream with `writer_pending_chunk: Some(bytes)`: call `self._h3.send_data(stream_id, bytes)`. If `H3SendResult.Sent`: clear the pending field. If `WouldBlock`: leave the field set; the adapter retries on the next event-loop pass. If `StreamClosed`: set `ctx.cancelled = True` and clear the field.

For each stream with `response_ended: True` and no pending chunk: send the final FIN-equivalent (call `self._h3.send_data(stream_id, [], end_stream=True)` or whatever M5b's API exposes), free the stream.

### Task 1.10: Build the H3 streaming server

**Files:**
- Build: `src/h3/h3_streaming_server.mojo`

- [ ] **Step 1: Build smoke**
Run: `mojo build src/h3/h3_streaming_server.mojo`
Expected: build succeeds, `_check_streaming_ctx_size` does not trip.

If R8' fires: heaviest field is usually `body_frame_ring: List[BodyFrame]` (each BodyFrame may hold a List[UInt8] of arbitrary size). Consider capping `body_frame_ring` to `InlineArray[BodyFrame, 8]` to bound the size — if that's still over budget, propose R8' revision per the spec's R6 mitigation.

### Task 1.11: Pick up MOVE-classified tests from `tests/_h3_streaming_pending.mojo`

**Files:**
- Read: `tests/_h3_streaming_pending.mojo`
- Create: `tests/test_h3_streaming_server.mojo`
- Delete: `tests/_h3_streaming_pending.mojo`

- [ ] **Step 1: Read the stash file**
Plan 2A Task 2.2 saved each MOVE-classified test verbatim with the `_streaming_` infix in the function name.

- [ ] **Step 2: Rewrite each into `tests/test_h3_streaming_server.mojo`**
For each stashed test, port the test body to use the new streaming-handler signature (`fn(ctx_ptr, mut yld) raises -> None`) and the new helpers (`next_chunk(ctx, yld)`, `write_chunk(ctx, yld, bytes)`, `finish(ctx, yld)`).

Mirror Plan 2A Task 2.14's pattern but the ports here use `CoroYielder` rather than the sync direct call.

- [ ] **Step 3: Add at least one new test exercising cancellation via STOP_SENDING**
The streaming tier MUST observe cancellation; the sync tier doesn't need to. Add `test_h3_streaming_cancel_via_stop_sending` that drives a stream, has the handler suspend in `next_chunk`, sends STOP_SENDING from the peer, asserts the handler observes `ctx.cancelled() == True` and unwinds via `StreamError`.

- [ ] **Step 4: Register + run**
Add `tests/test_h3_streaming_server.mojo` to `scripts/run_tests.sh`. Remove the entry for `tests/_h3_streaming_pending.mojo` (which never got registered — Plan 2A intentionally left it out).
Run: `mojo run tests/test_h3_streaming_server.mojo`
Expected: PASS.

- [ ] **Step 5: Delete the stash file**
Run: `git rm tests/_h3_streaming_pending.mojo`

- [ ] **Step 6: Commit**
Use the `commit-smart` skill.

### Task 1.12: H3 streaming bench server + LLM-stream demo handler

**Files:**
- Create: `bench/streaming_handler.mojo`
- Create: `bench/h3_streaming_server.mojo`

- [ ] **Step 1: Write the LLM-stream demo handler**
```
# bench/streaming_handler.mojo
#
# LLM-stream demo: emits N pseudo-tokens at K-µs intervals.
# Used by both bench/h2_streaming_server.mojo and bench/h3_streaming_server.mojo
# to demonstrate end-to-end streaming on both protocols with a single handler.

from std.memory import UnsafePointer

# Streaming-handler signatures are PROTOCOL-SPECIFIC at the type level
# (the ctx pointer type differs) but STRUCTURALLY IDENTICAL at the body level.
# We provide two thin entry points; the body is shared.

from src.h2.h2_streaming_server import H2StreamingCtx
from src.h2.h2_streaming_server import (
    next_chunk as h2_next_chunk,
    write_chunk as h2_write_chunk,
    finish as h2_finish,
)
from src.h3.h3_streaming_server import H3StreamingCtx
from src.h3.h3_streaming_server import (
    next_chunk as h3_next_chunk,
    write_chunk as h3_write_chunk,
    finish as h3_finish,
)
from boucle.stackful import CoroYielder


comptime LLM_TOKEN_COUNT = 64
comptime LLM_TOKEN_BYTES = "data: token-emitted\n\n"


def llm_stream_h3_handler(
    ctx_ptr: UnsafePointer[H3StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    for _ in range(LLM_TOKEN_COUNT):
        var bytes = List[UInt8]()
        for b in LLM_TOKEN_BYTES.as_bytes():
            bytes.append(b)
        h3_write_chunk(ctx_ptr, yld, bytes^)
    h3_finish(ctx_ptr, yld)


def llm_stream_h2_handler(
    ctx_ptr: UnsafePointer[H2StreamingCtx, MutAnyOrigin],
    mut yld: CoroYielder,
) raises:
    for _ in range(LLM_TOKEN_COUNT):
        var bytes = List[UInt8]()
        for b in LLM_TOKEN_BYTES.as_bytes():
            bytes.append(b)
        h2_write_chunk(ctx_ptr, yld, bytes^)
    h2_finish(ctx_ptr, yld)
```

- [ ] **Step 2: Write the H3 streaming bench server**
```
# bench/h3_streaming_server.mojo
#
# Bench harness for H3 streaming. Mirrors bench/h3_server.mojo but uses
# H3StreamingServer and the LLM-stream demo handler.

from src.io.io_uring import IoUring
from src.h3.h3_streaming_server import H3StreamingServer
from bench.streaming_handler import llm_stream_h3_handler
# ... (mirror bench/h3_server.mojo's QUIC + UDP setup; swap H3CoroServer
# for H3StreamingServer and bench_h3_body_fn for llm_stream_h3_handler).
```

(Concrete bench code is bulkier; mirror `bench/h3_server.mojo`'s structure verbatim and substitute the streaming server type + handler fn.)

- [ ] **Step 3: Build + smoke**
Run: `mojo build bench/h3_streaming_server.mojo -o bench/h3_streaming_server`
Run: `./bench/h3_streaming_server &` (background)
Run: `h2load --h3 -c 1 -m 1 -n 1 https://127.0.0.1:8443/stream`
Expected: response body contains `LLM_TOKEN_COUNT × LLM_TOKEN_BYTES.byte_length()` bytes.

- [ ] **Step 4: Stop the server + commit**
`kill %1`. Use the `commit-smart` skill.

---

## Phase 2 — H2 streaming server (~2 days, applies the H3-validated pattern)

### Task 2.1: Day-11 prerequisite audit — `H2Connection.send_data` `WouldBlock` surface

**Files:**
- Read: `src/h2/connection.mojo`

- [ ] **Step 1: Inspect the surface**
Same audit as Task 1.1, but for H2. Verdict drives whether this task includes a precursor commit adding `H2SendResult` (mirror `H3SendResult`).

- [ ] **Step 2: If precursor commit needed, add it**
Mirror Task 1.1 step 3 with H2 substitutions; commit separately.

### Task 2.2: Resurrect Sprint-1-deleted H2 streaming helpers from git

**Files:**
- Read: `git show main:src/h2/h2_coro_server.mojo` (the pre-Sprint-1 file with stackful helpers)
- Create: `src/h2/h2_streaming_server.mojo`

- [ ] **Step 1: Extract the deleted helpers as a reference**
Run: `git show main:src/h2/h2_coro_server.mojo > /tmp/main_h2_coro.mojo`
Read /tmp/main_h2_coro.mojo and identify:
- `H2BodyYieldFn` type alias.
- The CoroHandle allocation block in `feed`.
- `resume_stream` external-resume API.
- Any helper functions that take `CoroYielder`.

These are the source-of-truth structures, but they CANNOT be pasted — they were written against the pre-Sprint-1 H2Connection API which has since shifted.

- [ ] **Step 2: Mirror `src/h3/h3_streaming_server.mojo` (Tasks 1.2-1.10) with H2 substitutions**
The streaming tier's user-facing API is identical across H2 and H3 (per spec D4); only the wire-format-specific code differs. Walk through `src/h3/h3_streaming_server.mojo` line by line and produce `src/h2/h2_streaming_server.mojo` with these substitutions:
- `H3Connection` → `H2Connection`
- `QuicConnection` → (none — H2 wraps `H2Connection` directly, no QUIC layer)
- `H3Event` → `H2Event`, `H3_EVT_*` → `H2_EVT_*`
- `H3SendResult` → `H2SendResult`
- `stream_id: UInt64` → `stream_id: UInt32`
- `H3StreamingCtx` → `H2StreamingCtx`
- `H3StreamingHandlerFn` → `H2StreamingHandlerFn`
- `H3StreamingServer` → `H2StreamingServer`
- `H3StreamingCtxPool` → `H2StreamingCtxPool`
- The pre-Sprint-1 deleted helpers from /tmp/main_h2_coro.mojo are the **shape reference** — confirm each piece of the H3 mirror matches what the deleted H2 version did, but use the H3 mirror as the canonical structure (it's been validated by Phase 1's tests).

- [ ] **Step 3: Build smoke**
Run: `mojo build src/h2/h2_streaming_server.mojo`
Expected: succeeds, R8' assert clean.

### Task 2.3: H2 streaming tests — resurrect `test_body_yield` + `test_resume_stream`

**Files:**
- Read: `git show main:tests/test_h2_coro_server.mojo`
- Create: `tests/test_h2_streaming_server.mojo`

- [ ] **Step 1: Extract the deleted tests**
Run: `git show main:tests/test_h2_coro_server.mojo > /tmp/main_test_h2.mojo`
Find `test_body_yield` and `test_resume_stream`. These are the suspension-dependent tests Sprint 1 deleted.

- [ ] **Step 2: Port them against the new streaming server**
Mirror Task 1.11's port pattern: rewrite each test to use the new helpers (`next_chunk`, `write_chunk`, `finish`) instead of the old direct `CoroYielder.suspend()` / `resume_stream(stream_id)` calls.

- [ ] **Step 3: Add `test_h2_streaming_cancel_via_rst_stream`**
Mirror Task 1.11 step 3 with H2 RST_STREAM substitution.

- [ ] **Step 4: Register + run**
Add to `scripts/run_tests.sh`. Run: `mojo run tests/test_h2_streaming_server.mojo`
Expected: PASS.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill.

### Task 2.4: H2 streaming bench server

**Files:**
- Create: `bench/h2_streaming_server.mojo`

- [ ] **Step 1: Mirror `bench/h3_streaming_server.mojo` with H2 substitutions**
`H3StreamingServer` → `H2StreamingServer`; `llm_stream_h3_handler` → `llm_stream_h2_handler`. Use `bench/h2_server.mojo` as the structural reference for the H2 + TLS + io_uring setup.

- [ ] **Step 2: Build + smoke**
Run: `mojo build bench/h2_streaming_server.mojo -o bench/h2_streaming_server`
Run: `./bench/h2_streaming_server &`; `h2load -c 1 -m 1 -n 1 https://127.0.0.1:8443/stream`
Expected: streaming response.

- [ ] **Step 3: Stop server + commit**
`kill %1`. Use the `commit-smart` skill.

---

## Phase 3 — R1' grep gate codification + integration (~1 day)

### Task 3.1: Add R1' grep gate to `scripts/run_tests.sh`

**Files:**
- Modify: `scripts/run_tests.sh`

- [ ] **Step 1: Add a check step**
Insert near the top (before any `mojo run` calls — fail fast):
```
# R1' grep gate — boucle.stackful is allowed only in *_streaming_server.mojo
# files inside src/, plus src/tls/lib.mojo (FFI bridge slot, currently
# unused). Tests at repo-root tests/ are not scoped here. See
# plans/2026-04-27-sprint-2b-streaming.md.

R1_VIOLATIONS=$(grep -rEn 'boucle\.stackful' src/ \
  | grep -vE '^src/(h2/h2_streaming_server|h3/h3_streaming_server)\.mojo:' \
  | grep -vE '^src/tls/lib\.mojo:' \
  || true)
if [ -n "$R1_VIOLATIONS" ]; then
    echo "R1' violation: boucle.stackful imported outside allowed files:"
    echo "$R1_VIOLATIONS"
    exit 1
fi
echo "R1' grep gate: PASS"
```

- [ ] **Step 2: Run the script**
Run: `bash scripts/run_tests.sh`
Expected: `R1' grep gate: PASS` printed; full src test suite passes.

- [ ] **Step 3: Commit**
Use the `commit-smart` skill.

### Task 3.2: HttpArena `validate.sh` covering all five servers

**Files:**
- Run-only: `bench/validate.sh` (or `scripts/validate.sh` per Plan 2A Task 3.1)

- [ ] **Step 1: Run validation**
Run: the same script Plan 2A Task 3.1 located.
Expected: H1, H2, H3 all green. Streaming servers don't run via this script (it doesn't know to call streaming endpoints); their smoke checks are in Tasks 1.12 step 3 + 2.4 step 2.

### Task 3.3: 120s × 3-run benchmark capture (sync regressions + streaming smoke)

**Files:**
- Append: `bench/profile/baselines/{h2,h3}-throughput.csv`, `bench/profile/baselines/streaming-smoke.csv`

- [ ] **Step 1: Re-run H2 sync bench**
Same cells used in Sprint 1 + Plan 2A. Confirm no regressions vs Sprint 1 baselines (rename should not move numbers; if it does, investigate).

- [ ] **Step 2: Re-run H3 sync bench**
Same long-conn cell from Plan 2A Task 2.17. Confirm Plan 2A's lift is preserved.

- [ ] **Step 3: Capture streaming smoke numbers**
For both H2 + H3 streaming bench servers, run a low-concurrency stream (`-c 1 -m 1 -n 1000`) and record latency p50/p95 + tokens-per-sec. **NO regression target on streaming** (the deliverable is shape, not throughput); this row is for forward tracking only.

Append rows tagged `sprint-2-streaming-smoke` to `bench/profile/baselines/streaming-smoke.csv`.

- [ ] **Step 4: Commit**
Use the `commit-smart` skill.

### Task 3.4: Sprint 2 retrospective (covers both 2A + 2B)

**Files:**
- Create: `plans/2026-04-27-sprint-2-retrospective.md`

- [ ] **Step 1: Consume Plan 2A working note**
Read `plans/2026-04-27-sprint-2a-retro-notes.md` (Plan 2A Task 3.2's output) and integrate the Phase-1 H1 outcome + Phase-2 H3 sync findings.

- [ ] **Step 2: Add Plan 2B sections**
- Phase 0 rename outcome (clean, contentious, surprises?).
- Phase 1 H3 streaming server: actual days vs estimated 2; whether the `H3SendResult` precursor commit was needed; final R8' size for `H3StreamingCtx`.
- Phase 2 H2 streaming: ditto for H2.
- Phase 3 R1' gate first violation (if any).
- Three-config bench numbers for sync (no regression check) + streaming smoke (forward-tracking).
- Open questions for Sprint 2.5 / Sprint 3:
  - Does the streaming-handler signature truly belong in a shared module (as `src/streaming/__init__.mojo` was conditionally proposed)?
  - H1 streaming companion design: how much can be reused from H2 streaming?
  - Sprint 3 InlineArray work on H3 sync ctx — is the +15-25% lift target preserved?

- [ ] **Step 3: Commit**
Use the `commit-smart` skill.

### Task 3.5: Push branch + open PR

**Files:**
- (Git operations only.)

- [ ] **Step 1: Push final state**
Run: `git push origin feat/h2-state-machine-path-a`

- [ ] **Step 2: Open PR**
Run: `gh pr create --title "feat: Sprint 2 — Path A across H1/H2/H3 + tiered streaming on H2 + H3" --body "$(cat <<'EOF'
## Summary
- Extends Sprint 1's Path A from H2 to H1 (bench wiring + per-conn pool if hot) and H3 (full coro→sync rewrite mirroring H2)
- Adds opt-in streaming-handler tier on H3 (canonical-shape) + H2, signature identical across protocols
- Codifies R1' grep gate so future work cannot silently re-introduce boucle.stackful

## Test plan
- [ ] HttpArena validate.sh green for H1/H2/H3
- [ ] R1' grep gate passes (zero matches outside src/{h2,h3}/*_streaming_server.mojo + src/tls/lib.mojo)
- [ ] R8 + R8' compile-time asserts pass
- [ ] Sync regressions: zero vs Sprint 1 baselines
- [ ] H3 sync long-conn lift: +15-25% vs M5c coro baseline
- [ ] Streaming smoke: end-to-end LLM-stream pattern works on both H2 and H3
EOF
)"`

If the user has not authorised PR creation, surface the request instead.

---

## Spec → Task coverage check

| Spec requirement | Task(s) |
|---|---|
| §3 Rename `h2_coro_server.mojo` → `h2_sync_server.mojo` | 0.2 |
| §4 H3 streaming server | 1.2-1.10 |
| §4 Day-9 prerequisite audit (H3 WouldBlock surface) | 1.1 |
| §4 H3 streaming tests | 1.11 |
| §4 R8' for H3 streaming ctx | 1.6, 1.10 |
| §5 H2 streaming server | 2.1-2.2 |
| §5 Day-11 prerequisite audit (H2 WouldBlock surface) | 2.1 |
| §5 H2 streaming tests (resurrected) | 2.3 |
| §5 R8' for H2 streaming ctx | 2.2 (R8' assert mirrored from H3) |
| §6 streaming bench fixtures + servers | 1.12, 2.4 |
| §6 `bench/streaming_handler.mojo` | 1.12 |
| §7 R1' grep gate codification | 3.1 |
| Acceptance §1 (5 servers build clean) | 1.10, 2.2.3 (build smoke), Plan 2A's contributions covered by their builds |
| Acceptance §2 (HttpArena validate.sh) | 3.2 |
| Acceptance §3 (no regressions + streaming smoke) | 3.3 |
| Acceptance §4 (streaming demonstration) | 1.12 step 3, 2.4 step 2 |
| Acceptance §5 (R1' grep gate zero matches) | 3.1 |
| Acceptance §6 (R8 + R8' asserts) | 1.6, 1.10, 2.2 |
| Acceptance §7 (test count growth) | 1.11, 2.3 |
| Acceptance §8 (conformance still 35/35) | 0.2 step 5, 3.2 |
| Acceptance §9 (retrospective) | 3.4 |

---

## Risks specific to Plan 2B

### R-2B-1. The "streaming-handler signature is identical" claim breaks on H2 vs H3

Spec D4 asserts the signature is identical. Phase 1 (H3) might surface a per-protocol divergence — e.g. H3's STOP_SENDING semantics may need a different cancellation API than H2's RST_STREAM, or H2 priority signalling may need to flow into the handler differently than H3 priority capsules.

**Mitigation:** if Phase 1 ends with a divergence, the spec's "identical" claim is invalidated. Document the divergence in the Plan 2B retro and propose either: (a) split the signatures into H2-specific + H3-specific (giving up "write once, run on either"), or (b) introduce a generic `mut StreamingCtx` trait wrapper that both ctx structs conform to (more Mojo-effort but preserves the user-facing promise). Decision is the user's, not the implementer's.

### R-2B-2. `git show main:src/h2/h2_coro_server.mojo` resurrection has bit-rotted

Sprint 1 deleted the H2 streaming helpers; the deletion is on `feat/h2-state-machine-path-a` HEAD. The pre-deletion file lives on `main`. If `main` has moved since (e.g. via an unrelated commit touching `H2Connection` API), the resurrected helpers won't compile against the current `H2Connection` shape.

**Mitigation:** Task 2.2 step 1 explicitly extracts to `/tmp/main_h2_coro.mojo` for reading-only; Task 2.2 step 2 uses the H3 mirror (which is fresh against current types) as the canonical structure. The deleted helpers are reference-only.

### R-2B-3. R1' grep gate has a false-positive in `src/tls/lib.mojo` from Wave 2

`src/tls/lib.mojo` contains the QUIC handshake FFI (Wave 2 per project-context line 39). Wave 2 itself does not import `boucle.stackful`, but if a future FFI bridge does, the gate would silently allow it. The current allow-list explicitly names `src/tls/lib.mojo` even though it doesn't use stackful today.

**Mitigation:** add a comment in `scripts/run_tests.sh` documenting that `src/tls/lib.mojo` is a reserved slot for FFI bridges; if a Wave 3+ FFI bridge needs `boucle.stackful`, that's the explicit allowlisted file (or split it into `src/tls/{lib,ffi_bridge}.mojo` and update the gate).

### R-2B-4. Boucle's `CoroutinePool` API has shifted since the Sprint-1 deletion

Boucle is at `~/Projets/perso/boucle/`. Sprint 1 deleted the H2 stackful path on April 27; if boucle has been updated since (mojo-net's Mojo upgrade pulled in a new boucle), the `CoroutinePool` constructor may have gained or removed parameters.

**Mitigation:** Task 1.7 step 1 builds a smoke test that exercises `CoroutinePool(capacity=4)`; if boucle's API has shifted, the build fails with a clear error and the implementer adjusts the constructor call. No silent breakage.

### R-2B-5. Bench drivers (`h2load`) don't exercise the suspending path

`h2load -m 1 -n 1` issues one stream end-to-end without exercising suspend/resume across writer-window-open events (the request typically completes in microseconds, faster than any FC window full event).

**Mitigation:** the streaming bench demo (`bench/streaming_handler.mojo` LLM-stream with N=64 tokens) is a **shape demonstrator**, not a perf benchmark. Acceptance §4 only requires "demonstrates end-to-end streaming" — observable via tcpdump / wireshark on the loopback; the test in Task 1.11 step 3 (cancellation via STOP_SENDING) is the actual semantic check.

---

## Plan 2B end state

After Task 3.5:
- Branch `feat/h2-state-machine-path-a` reaches Sprint 2 final state: ~30-40 commits since Sprint 1 start.
- Five servers shipped (H1 sync — Plan 2A; H2 sync renamed; H2 streaming new; H3 sync new; H3 streaming new).
- `bench/streaming_handler.mojo` demonstrates LLM-stream pattern over both H2 and H3.
- R1' grep gate codified in `scripts/run_tests.sh`.
- R8 + R8' compile-time asserts in place across both sync and streaming ctx structs.
- HttpArena `validate.sh` green; full test suite passes; conformance 35/35.
- Sprint 2 retrospective committed; PR open against `main` for review.
- Sprint 3 (InlineArray + SIMD on H3 sync) is unblocked.
