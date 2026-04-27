# Sprint 2A — H1/H3 Sync Mirror Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Sprint 1's Path A sync handler shape from H2 to H1 (bench wiring + per-conn allocation pool if hot) and H3 (full coro→sync rewrite, mirroring `src/h2/h2_coro_server.mojo` line-for-line over QUIC).

**Architecture:** `IoUring[H]` (Sprint 1) is the uniform I/O capability across H1/H2/H3 bench servers. H1's `H1HandlerServer` is already sync-shaped — only its bench harness needs `IoUring` wiring + an optional `H1StreamCtxPool` mirroring Sprint 1's `CoroStreamCtxPool`. H3's `H3CoroServer` (M5c) currently uses `boucle.stackful.CoroHandle` per stream; we rewrite it as `H3CoroServer` (file-name preserved this sprint, internal shape rewritten) using a sync ctx-pointer body fn — `H3BodyFn = fn(UnsafePointer[CoroStreamCtx, MutAnyOrigin]) raises -> None` — and add `CoroStreamCtxPool(capacity=16)` for cache locality. Path A shape is now uniform across H2 (Sprint 1) and H3 (this plan).

**Tech Stack:** Mojo 0.26.2 or later (active toolchain `0.26.3.0.dev2026042005`); `boucle.completion.CompletionLoop`; `src/io/{io_trait,io_uring}.mojo` (Sprint 1); `src/quic/connection.QuicConnection`; `src/h3/connection.H3Connection`; `src/http/{request,handler,body,headers,method,status,version}.mojo`.

**Out of scope (covered by Plan 2B):**
- Renaming `h2_coro_server.mojo` → `h2_sync_server.mojo` (Day 8 of the Sprint 2 plan; deferred to 2B because it's a churning rename that disturbs imports across this plan's 7-day execution).
- H2 + H3 streaming server companions (`*_streaming_server.mojo`).
- `bench/streaming_handler.mojo` + companion benches.
- R1' grep gate in `scripts/run_tests.sh`.
- Sprint 2 retrospective (covers both 2A + 2B; written after 2B lands).

---

## File structure

### Created

| File | Purpose |
|---|---|
| `src/h3/h3_sync_server.mojo` | H3 server adapter using sync ctx-pointer body fn. Mirrors `src/h2/h2_coro_server.mojo` over QUIC. **Replaces** the current `src/h3/h3_coro_server.mojo` shape (existing file is rewritten in place; the rename to `h3_sync_server.mojo` is part of the rewrite to keep the file boundary clean). |
| `src/h1/stream_ctx_pool.mojo` | `H1StreamCtxPool` — free-list of typed-uninitialised heap blocks for the H1 per-request ctx. Created **only if** Day-1 audit shows allocator pressure exceeds quantified thresholds. |
| `tests/test_h3_sync_server.mojo` | Sync-shape H3 tests, mirroring `tests/test_h2_coro_server.mojo`. Replaces `tests/test_h3_coro_server.mojo`. Day-3 audit of the existing 5 tests classifies each as DELETE / MOVE-to-streaming-test (kept for Plan 2B) / REWRITE-as-sync. |
| `tests/test_h1_stream_ctx_pool.mojo` | Pool smoke tests if Phase 1 adds the H1 pool. |

### Modified

| File | Change |
|---|---|
| `bench/h1_server.mojo` | Switch the bench harness from raw `CompletionLoop` to `IoUring[H]` for symmetry with H2/H3. Wire `H1StreamCtxPool` into `H1HandlerServer` if Phase 1 adds it. |
| `bench/h3_server.mojo` | Switch `H3CoroServer[BenchHandler]` → `H3SyncServer[BenchHandler]`. Update `bench_h3_body_fn` reference (sync body fn). |
| `bench/handler.mojo` | Rewrite `bench_h3_body_fn` from `CoroBody`-shaped to sync ctx-pointer-shaped (mirror existing `bench_h2_body_fn`). |
| `src/h3/__init__.mojo` | Re-export `H3SyncServer` instead of `H3CoroServer`. |
| `docs/project-context.md` | Phase-0 corrections (Sprint 1 row, line 33 relaxation, line 121 Mojo pin). |

### Deleted

| File | Reason |
|---|---|
| `src/h3/h3_coro_server.mojo` | Superseded by `src/h3/h3_sync_server.mojo`. The old file's logic is fully replaced by the rewrite, not kept as a streaming variant — Plan 2B builds the streaming companion as a NEW file (`h3_streaming_server.mojo`) using the resurrected helpers from git history (which lived in the **H2** coro server before Sprint 1 deleted them; H3 never had streaming-helper code in the first place). |
| `tests/test_h3_coro_server.mojo` | Replaced by `tests/test_h3_sync_server.mojo` per Day-3 audit. |

---

## Phase 0 — Pre-Sprint-2 prerequisites (~30 min, doc-only)

### Task 0.1: Update Mojo version pin in project-context

**Files:**
- Modify: `docs/project-context.md:121`

- [ ] **Step 1: Edit line 121**
Change `- **Mojo:** 0.26.2 (...)` to `- **Mojo:** 0.26.2 or later (currently 0.26.3 nightly, ` `0.26.3.0.dev2026042005`, April 20 2026 — Sprint 1 already uses 0.26.2-syntax `comptime assert`)`.

- [ ] **Step 2: Verify**
Run: `grep -n '\*\*Mojo:\*\*' docs/project-context.md`
Expected: line 121 shows the new pin.

### Task 0.2: Relax line 33 to record the `src/io/` exception

**Files:**
- Modify: `docs/project-context.md:33`

- [ ] **Step 1: Replace line 33**
Replace:
```
- **Sans-I/O at every protocol layer.** Application code composes the protocol layer with an I/O loop (boucle in examples). No I/O imports inside `src/`. Exception: `boucle.stackful` (CoroHandle, CoroYielder) is allowed in `src/` because it is a control-flow mechanism with no I/O dependency. Only boucle's I/O primitives (`boucle.net.*`, `CompletionLoop`, `CompletionHandler`) are restricted to examples.
```
With:
```
- **Sans-I/O at every protocol layer (`src/h1/`, `src/h2/`, `src/h3/`, `src/quic/`, `src/http/`).** Application code composes the protocol layer with an I/O loop. The `src/io/` capability layer is the explicit exception — it owns the `Io` trait + `IoUring[H]` impl and is the only place inside `src/` that imports `boucle.completion` (`CompletionLoop`, `CompletionHandler`, `BufRing`) and `boucle.handle` (`RawHandle`). Sprint 1 introduced this layer to centralise the io_uring binding behind a stable trait surface. `boucle.stackful` (CoroHandle, CoroYielder) is allowed in `src/` because it is a control-flow mechanism with no I/O dependency, and is constrained by R1' (only `*_streaming_server.mojo` files inside `src/` plus `src/tls/lib.mojo`).
```

- [ ] **Step 2: Verify**
Run: `grep -n 'src/io/' docs/project-context.md | head -3`
Expected: line 33 mentions `src/io/` capability layer.

### Task 0.3: Add Sprint 1 row to Active specs and plans table

**Files:**
- Modify: `docs/project-context.md` (Active specs and plans table)

- [ ] **Step 1: Insert Sprint 1 row**
Insert a new row in the Active specs and plans table immediately above the existing `pending` Sprint 2 spec row (which was added at brainstorming time):
```
| done | `plans/2026-04-27-h2-perf-roadmap-sprint-sequence.md` (Sprint 1 segment) → `plans/2026-04-27-sprint-1-retrospective.md` | **Sprint 1 — Path A on H2 + Io trait + IoUring + CoroStreamCtxPool.** 11 commits on `feat/h2-state-machine-path-a` (last `0ea3720`). Replaced `boucle.stackful.CoroHandle`-per-stream with sync `H2BodyFn = fn(UnsafePointer[CoroStreamCtx, MutAnyOrigin]) raises -> None`. New `src/io/io_trait.mojo` + `src/io/io_uring.mojo`. New `CoroStreamCtxPool(capacity=16)` recovers cache locality. R8 compile-time assert: `size_of[CoroStreamCtx]() < 1024 B` (lands at ~608 B). Three-config pinning bench: `/baseline2` GM +47 % RPS, `/json/50` GM +7 % RPS (cache-locality regression −7.8 %→−1.1 % shared-pin after pool). `tests/test_h2_coro_server.mojo` rewritten to 4 sync-shape tests; suspension-dependent tests deleted (resurrected for Plan 2B's H2 streaming server). |
```

- [ ] **Step 2: Verify**
Run: `grep -c 'Sprint 1 —' docs/project-context.md`
Expected: ≥ 1.

### Task 0.4: Commit Phase 0

- [ ] **Step 1: Stage + commit**
Use the `commit-smart` skill. Message format: `type: what changed` — no scope, no plan/spec references. The change is doc-only and small; expect a single commit covering all three edits.

---

## Phase 1 — H1 sync wiring + per-conn allocation audit (~1.5 days)

### Task 1.1: Read current H1 bench harness shape

**Files:**
- Read: `bench/h1_server.mojo` (whole file, 637 lines)

- [ ] **Step 1: Inventory the bench harness**
Read the file end-to-end and document in a working note (no commit) which lines:
- Construct `CompletionLoop` directly (the migration target — these are the lines that become `IoUring[H]`).
- Wire `H1HandlerServer[BenchHandler]` into the loop (the boundary where the pool, if added, plugs in).
- Allocate per-request state (the candidates for the `H1StreamCtxPool` if Day-1 profile shows pressure).

Output: a 5-bullet summary of the migration touch points to embed in the Task 1.2 commit message.

### Task 1.2: Switch H1 bench from `CompletionLoop` to `IoUring[H]`

**Files:**
- Modify: `bench/h1_server.mojo` (the `CompletionLoop` construction site identified in Task 1.1)

- [ ] **Step 1: Add the `IoUring` import**
Add `from src.io.io_uring import IoUring` to the imports block.

- [ ] **Step 2: Replace `CompletionLoop[H1UringHandler](...)` with `IoUring[H1UringHandler](...)`**
The `IoUring` constructor takes the same args as `CompletionLoop` (handler + `sq_entries`); the migration is a 1-line struct-name change at the construction site. Refer to `src/io/io_uring.mojo:50-53` for the constructor signature.

- [ ] **Step 3: Replace `loop._handler.<field>` callsites with `io.loop._handler.<field>`**
`IoUring` deliberately exposes `loop` as a public field (`src/io/io_uring.mojo:39-42`), so the migration is mechanical — every existing `loop._handler.<x>` becomes `io.loop._handler.<x>`. Mirror the pattern Sprint 1 used in `bench/h2_server.mojo` post-migration.

- [ ] **Step 4: Build + run smoke**
Run: `mojo build bench/h1_server.mojo -o bench/h1_server`
Expected: build succeeds with no errors.

Run: `./bench/h1_server &` (background) then `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/baseline2`
Expected: `200`.
Stop with `kill %1`.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill.

### Task 1.3: Profile H1 allocator pressure under bench load

**Files:**
- Read-only: `bench/h1_server.mojo`, `src/h1/handler_server.mojo`

- [ ] **Step 1: Run the bench under perf**
Build + start the server in one terminal:
```
mojo build bench/h1_server.mojo -o bench/h1_server
taskset -c 0,1,2,3 ./bench/h1_server &
```

In another terminal, generate load:
```
taskset -c 4,5,6,7 wrk -d 30s -c 256 -t 4 http://127.0.0.1:8080/baseline2 &
WRK_PID=$!
```

While `wrk` runs, collect a perf profile (run as root or with appropriate caps):
```
sudo perf record -F 200 -g --pid=$(pgrep -f h1_server) -- sleep 20
sudo perf report --stdio --percent-limit 0.5 --no-children > /tmp/h1_profile.txt
```

Wait for `wrk` to finish: `wait $WRK_PID`.

Stop the server.

- [ ] **Step 2: Score the profile against the threshold**
The H1 pool is added if **any** of these triggers:
1. `_heap_alloc` (or `malloc`/`calloc`) collectively account for ≥ 5% of total CPU in `/tmp/h1_profile.txt`.
2. Average per-request `_heap_alloc` count ≥ 1 (estimate via `perf stat -e probe:_heap_alloc -- sleep 20` if probe registration is feasible; else fall back to malloc-CPU% above).
3. Cold-start `/json/50` regression ≥ 5% in any pin config vs Sprint 1 baseline (compare the 3-pinning-config table from `bench/profile/baselines/h1-throughput.csv` — record exists; if not, treat as N/A and use trigger 1 alone).

Output: a Markdown bullet list "trigger N: HIT/MISS — [evidence]" embedded in the Task 1.3 commit message.

- [ ] **Step 3: Commit**
Use the `commit-smart` skill. Message includes the trigger scorecard.

### Task 1.4: Decision branch — pool or skip

**Files:**
- (No file changes; this is a routing decision recorded in the commit message of Task 1.5 or Task 1.10.)

- [ ] **Step 1: Apply the rule**
- If **any** trigger from Task 1.3 step 2 hit: proceed to Task 1.5 (write the pool).
- If **all** triggers missed: **skip Tasks 1.5–1.9**; jump to Task 1.10 (Phase 1 retro).

### Task 1.5: Write failing test for `H1StreamCtxPool` round-trip

**Files:**
- Create: `tests/test_h1_stream_ctx_pool.mojo`

- [ ] **Step 1: Write failing test**
Mirror Sprint 1's `CoroStreamCtxPool` test pattern — round-trip an acquire/release pair and assert idle_count behavior. Reference: `src/h2/h2_coro_server.mojo:216-259` for the pool surface.

```
# tests/test_h1_stream_ctx_pool.mojo
from std.testing import assert_equal, assert_true
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.h1.stream_ctx_pool import H1StreamCtx, H1StreamCtxPool


def test_pool_acquire_release_round_trip() raises:
    var pool = H1StreamCtxPool(capacity=16)
    assert_equal(pool.idle_count(), 0)
    var p1 = pool.acquire()
    var p2 = pool.acquire()
    assert_equal(pool.idle_count(), 0)
    pool.release(p1)
    pool.release(p2)
    assert_equal(pool.idle_count(), 2)
    var p3 = pool.acquire()
    assert_equal(pool.idle_count(), 1)
    pool.release(p3)


def test_pool_capacity_overflow_frees_excess() raises:
    var pool = H1StreamCtxPool(capacity=2)
    var p1 = pool.acquire()
    var p2 = pool.acquire()
    var p3 = pool.acquire()
    pool.release(p1)
    pool.release(p2)
    pool.release(p3)  # over capacity → pool frees this directly
    assert_equal(pool.idle_count(), 2)


def main() raises:
    test_pool_acquire_release_round_trip()
    test_pool_capacity_overflow_frees_excess()
    print("ok")
```

- [ ] **Step 2: Verify it fails**
Run: `mojo run tests/test_h1_stream_ctx_pool.mojo`
Expected: FAIL — `unable to locate module 'src.h1.stream_ctx_pool'`

### Task 1.6: Implement `H1StreamCtx` + `H1StreamCtxPool`

**Files:**
- Create: `src/h1/stream_ctx_pool.mojo`

- [ ] **Step 1: Identify the H1 per-request ctx**
Read `src/h1/handler_server.mojo` and identify the per-request struct currently allocated on the heap (likely `H1RequestCtx` or similar). Record its name + size. The `H1StreamCtx` typedef in the new module is an **alias** for that existing struct, not a new struct — the pool stores typed-uninitialised pointers to the existing ctx type.

- [ ] **Step 2: Write the module**
Mirror `src/h2/h2_coro_server.mojo:216-259` with substitutions: `CoroStreamCtx` → the H1 ctx struct identified in Step 1; `CoroStreamCtxPool` → `H1StreamCtxPool`. Same constructor (`capacity: Int = 16`), same `acquire()`/`release()`/`idle_count()` surface, same `__del__` that walks `_free` and calls `.free()`.

```
# src/h1/stream_ctx_pool.mojo
from std.memory import UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.h1.handler_server import <CTX-NAME-FROM-STEP-1> as H1StreamCtx


struct H1StreamCtxPool(Movable):
    """Free-list of typed `H1StreamCtx`-sized heap blocks. Caller owns
    initialisation/destruction of the pointee; the pool only manages the
    underlying memory. Mirrors `src.h2.h2_coro_server.CoroStreamCtxPool`."""

    var _free: List[UInt64]
    var _capacity: Int

    def __init__(out self, *, capacity: Int = 16):
        self._free = List[UInt64]()
        self._capacity = capacity

    def __init__(out self, *, deinit take: Self):
        self._free = take._free^
        self._capacity = take._capacity

    fn __del__(deinit self):
        for i in range(len(self._free)):
            var p = UnsafePointer[H1StreamCtx, MutAnyOrigin](
                unsafe_from_address=Int(self._free[i])
            )
            p.free()

    fn acquire(mut self) raises -> UnsafePointer[H1StreamCtx, MutAnyOrigin]:
        if len(self._free) > 0:
            var addr = self._free.pop()
            return UnsafePointer[H1StreamCtx, MutAnyOrigin](
                unsafe_from_address=Int(addr)
            )
        return _heap_alloc[H1StreamCtx](1).as_any_origin()

    fn release(
        mut self, ptr: UnsafePointer[H1StreamCtx, MutAnyOrigin]
    ):
        if len(self._free) < self._capacity:
            self._free.append(UInt64(Int(ptr)))
        else:
            ptr.free()

    fn idle_count(self) -> Int:
        return len(self._free)
```

- [ ] **Step 2: Verify the test passes**
Run: `mojo run tests/test_h1_stream_ctx_pool.mojo`
Expected: PASS — output `ok`.

- [ ] **Step 3: Commit**
Use the `commit-smart` skill.

### Task 1.7: Wire `H1StreamCtxPool` into `H1HandlerServer`

**Files:**
- Modify: `src/h1/handler_server.mojo` (per-request ctx allocation + free path)

- [ ] **Step 1: Locate the heap-alloc + free sites**
In `src/h1/handler_server.mojo`, find:
- The site where the per-request ctx is allocated (an `_heap_alloc[H1StreamCtx](1)` or equivalent).
- The site(s) where the ctx is freed (likely a `destroy_pointee()` + `free()` pair, possibly in a `_free_stream`-style helper).

- [ ] **Step 2: Add the pool field**
Add `var _ctx_pool: H1StreamCtxPool` to the server struct. Initialise in each constructor with `self._ctx_pool = H1StreamCtxPool(capacity=16)`. Update `deinit take: Self` move-init to include `self._ctx_pool = take._ctx_pool^`.

- [ ] **Step 3: Replace alloc and free**
Replace the alloc site with `var ctx_ptr = self._ctx_pool.acquire()` and the free site's `ctx_ptr.free()` with `self._ctx_pool.release(ctx_ptr)` (the `destroy_pointee()` call stays — the pool only manages raw memory).

- [ ] **Step 4: Build + run existing H1 test suite**
Run: `bash scripts/run_tests.sh test_h1_*`
Expected: all H1 tests still pass.

- [ ] **Step 5: Commit**
Use the `commit-smart` skill.

### Task 1.8: Re-run H1 bench and capture pool lift

**Files:**
- Append: `bench/profile/baselines/h1-throughput.csv` (or create if not present)

- [ ] **Step 1: Run the same bench command Task 1.3 used**
```
mojo build bench/h1_server.mojo -o bench/h1_server
taskset -c 0,1,2,3 ./bench/h1_server &
sleep 1
taskset -c 4,5,6,7 wrk -d 120s -c 256 -t 4 http://127.0.0.1:8080/baseline2 \
  | tee /tmp/h1_pool_run1.txt
```
Repeat twice more (`run2`, `run3`) for a 3-run median.

Stop the server.

- [ ] **Step 2: Append median to baselines CSV**
Compute the median RPS across the three runs and append a row tagged `sprint-2a-pool-on` to `bench/profile/baselines/h1-throughput.csv`. If the file does not exist, create it with header:
```
date,branch,commit,config,endpoint,rps_run1,rps_run2,rps_run3,rps_median,notes
```

- [ ] **Step 3: Commit**
Use the `commit-smart` skill.

### Task 1.9: Phase 1 retro note

**Files:**
- Append a one-paragraph entry to a working note (the eventual Sprint 2 retrospective draft); not committed yet.

- [ ] **Step 1: Record outcome**
Capture in a working note: trigger scorecard from Task 1.3, decision (pool added Y/N), measured H1 lift (or "N/A — pool not warranted"). The Sprint 2 retrospective (after Plan 2B) will reference this note.

---

## Phase 2 — H3 sync mirror (~5 days, the largest single piece)

### Task 2.1: Day-3 audit — enumerate `tests/test_h3_coro_server.mojo` cases and classify

**Files:**
- Read: `tests/test_h3_coro_server.mojo` (484 lines, 5 test fns)

- [ ] **Step 1: Read the 5 tests end-to-end**
The 5 tests (line numbers from `grep -n` at spec time):
- `test_h3_coro_simple_get` (line 228)
- `test_h3_coro_post_with_body` (line 283)
- `test_h3_coro_trailers` (line 338)
- `test_h3_coro_rst_stream` (line 390)
- `test_h3_coro_goaway` (line 439)

For each, classify into one of three buckets:
1. **DELETE** — purely suspension-dependent; the test exercises `CoroYielder.suspend()` semantics with no observable behavior worth keeping for a sync handler.
2. **MOVE** — exercises suspend/resume; keep the test verbatim as input to Plan 2B's `tests/test_h3_streaming_server.mojo`. Rename the function with the `_streaming_` infix and stash it in a new file `tests/_h3_streaming_pending.mojo` (underscore prefix marks it as not-yet-wired; Plan 2B picks it up).
3. **REWRITE** — exercises non-suspension behavior (state transitions, error paths, RST_STREAM, GOAWAY, multi-stream). Rewrite into `tests/test_h3_sync_server.mojo` with the new sync-handler signature.

- [ ] **Step 2: Record the classification**
Write the 5-row classification table into the Task 2.1 commit message:
```
| Test | Verdict | Reason |
|---|---|---|
| test_h3_coro_simple_get  | <verdict> | <reason> |
| test_h3_coro_post_with_body | <verdict> | <reason> |
| test_h3_coro_trailers    | <verdict> | <reason> |
| test_h3_coro_rst_stream  | <verdict> | <reason> |
| test_h3_coro_goaway      | <verdict> | <reason> |
```

Heuristic to apply: if the test calls `yld.suspend()` or `yld.yield_to_caller()` directly, MOVE. If it asserts on suspension order, MOVE. Otherwise REWRITE. DELETE only if the test is genuinely meaningless without suspension.

- [ ] **Step 3: Commit**
Use the `commit-smart` skill. Message includes the table above.

### Task 2.2: Stash MOVE-classified tests

**Files:**
- Create: `tests/_h3_streaming_pending.mojo` (only if Task 2.1 produced any MOVE verdicts)

- [ ] **Step 1: Move the marked tests**
For each test classified MOVE in Task 2.1, copy it verbatim into `tests/_h3_streaming_pending.mojo` with the `_streaming_` infix in the function name (e.g. `test_h3_coro_post_with_body` → `test_h3_streaming_post_with_body`). Add a header comment:
```
# tests/_h3_streaming_pending.mojo
#
# H3 streaming-handler tests stashed during Sprint 2A's coro→sync rewrite.
# Plan 2B picks these up when implementing src/h3/h3_streaming_server.mojo.
# This file is not registered in scripts/run_tests.sh until 2B lands.
#
# DO NOT delete; DO NOT modify shape — these tests must execute against the
# resurrected suspending API verbatim, the same way Sprint 1's deleted
# tests/test_h2_coro_server.mojo (now on main) will be resurrected for
# tests/test_h2_streaming_server.mojo.
```

- [ ] **Step 2: Verify file is not in the test runner**
Run: `grep -n 'h3_streaming_pending' scripts/run_tests.sh`
Expected: zero matches.

- [ ] **Step 3: Commit**
Use the `commit-smart` skill.

### Task 2.3: Skeleton — create `src/h3/h3_sync_server.mojo` with imports + module docstring

**Files:**
- Create: `src/h3/h3_sync_server.mojo`

- [ ] **Step 1: Write the file header + imports**
Mirror `src/h2/h2_coro_server.mojo:1-50` with H3 substitutions:
```
# src/h3/h3_sync_server.mojo
#
# HTTP/3 server-side adapter — sans-IO codec wrapper. Feed inbound QUIC
# datagrams via `feed_datagram_from_buffer()`; drain outbound datagrams via
# `drain()`. Translates H3Connection events into a per-stream hand-written
# state machine, NOT stackful coroutines (Sprint 2A Path A — mirrors
# Sprint 1's H2CoroServer over QUIC).
#
# The "Coro" in `CoroStreamCtx` is preserved to mirror the H2 sister-file's
# naming (Sprint 1 chose to leave it that way to minimise churn). A future
# rename pass can unify both names — out of scope here.
#
# See plans/2026-04-27-sprint-2a-h1h3-sync.md.

from std.collections import Dict, Optional
from std.memory import Span, UnsafePointer
from std.memory.unsafe_pointer import alloc as _heap_alloc
from std.sys.info import size_of

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
from src.http.body import BodyFrame
from src.http.headers import Headers
from src.http.method import Method
from src.http.request import Request
from src.http.status import StatusCode
from src.http.version import Version
```

Note the deliberate **absence** of `from boucle.stackful import ...`. R1' grep gate in Plan 2B will assert this.

- [ ] **Step 2: Build smoke**
Run: `mojo build src/h3/h3_sync_server.mojo` (will fail because no struct/fn defined yet, but the imports must resolve).
Expected: failure with a "no entry point" or "expected struct/fn declaration" error, NOT an "unable to locate module" error.

### Task 2.4: Define `H3BodyFn` type alias

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Append the alias**
Mirror `src/h2/h2_coro_server.mojo:69-71`:
```
# H3BodyFn — synchronous handler invoked once per request.
#
# The handler receives a pointer to the per-stream context, reads
# `ctx.request` (or for streaming POST bodies, polls `ctx.recv_body`),
# and writes the response into `ctx.resp_writer`. It runs to completion
# in one call — no `yield_to_caller`. Streaming-handler use cases are
# served by `src/h3/h3_streaming_server.mojo` (Plan 2B).

comptime H3BodyFn = fn (
    UnsafePointer[CoroStreamCtx, MutAnyOrigin]
) raises -> None
```

(`CoroStreamCtx` is forward-referenced; defined in Task 2.5.)

### Task 2.5: Define `CoroStreamCtx` struct (no `coro_addr`, sync shape)

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Append the struct**
Mirror `src/h2/h2_coro_server.mojo:79-130` with two H3-specific changes:
1. `stream_id: UInt32` → `stream_id: UInt64` (QUIC uses 62-bit stream IDs).
2. Remove `unacked_bytes: Int` field (QUIC-level FC handled by `QuicConnection`; H2's stream-window-byte tracking is irrelevant on H3).

```
struct CoroStreamCtx(Movable):
    """Per-stream context for sync H3 serving. Heap-allocated so the
    adapter and the body fn can reach it via pointer. Holds the request,
    body receiver, response writer, capabilities, and stream lifecycle
    bookkeeping.

    No `coro_addr` field (Sprint 2A Path A — handler runs synchronously).
    No `unacked_bytes` (QUIC handles flow control internally)."""

    var request:        Request
    var recv_body:      RecvBody
    var resp_writer:    ResponseWriter
    var caps:           Capabilities
    var stream_id:      UInt64
    var extra_data:     UnsafePointer[NoneType, MutExternalOrigin]
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
        self.request_ended = take.request_ended
        self.response_ended = take.response_ended
        self.headers_sent = take.headers_sent
```

### Task 2.6: Add `_check_stream_ctx_size` R8 assert helper

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Append the helper**
Mirror `src/h2/h2_coro_server.mojo:152-156`:
```
fn _check_stream_ctx_size():
    comptime assert size_of[CoroStreamCtx]() < 1024, (
        "H3 CoroStreamCtx exceeded R8 budget (1024 B) — investigate"
        " before raising the cap"
    )
```

- [ ] **Step 2: Build smoke**
Run: `mojo build src/h3/h3_sync_server.mojo`
Expected: build still fails (no `H3SyncServer` constructor yet) but `comptime assert` does not trigger — the helper is not called yet. If the assert fires at this stage, H3 ctx is already over budget; halt and audit field choices before continuing.

### Task 2.7: Add `_CoroStreamPtr` Dict-storage wrapper + `_free_stream` helper + `CoroStreamCtxPool`

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Append `_CoroStreamPtr`**
Mirror `src/h2/h2_coro_server.mojo:165-182` verbatim — same struct, same methods, same Dict-element conformance. The pointer wraps `CoroStreamCtx` so `Dict[Int, _CoroStreamPtr]` satisfies `CollectionElement`.

- [ ] **Step 2: Append `_free_stream`**
Mirror `src/h2/h2_coro_server.mojo:190-193` verbatim:
```
def _free_stream(ctx_ptr: UnsafePointer[CoroStreamCtx, MutAnyOrigin]):
    """Hard-destroy the CoroStreamCtx allocation."""
    ctx_ptr.destroy_pointee()
    ctx_ptr.free()
```

- [ ] **Step 3: Append `CoroStreamCtxPool`**
Mirror `src/h2/h2_coro_server.mojo:216-259` verbatim — the struct is type-parameterised over the pointee type internally (well, in our case we have two separate copies, one per protocol — that's fine, R5/R9 forbid premature abstraction). All four methods (`__init__`, `deinit take`, `__del__`, `acquire`, `release`, `idle_count`) carry over unchanged. The `UnsafePointer[CoroStreamCtx, MutAnyOrigin]` references resolve to **this file's** `CoroStreamCtx` (the H3 one).

### Task 2.8: Define `H3CoroServer` (file-name preserves "Coro", surface is sync)

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Open the struct**
Mirror `src/h2/h2_coro_server.mojo:267-280`. Differences:
- `_conn: H2Connection` → `_quic: QuicConnection` + `_h3: H3Connection`. H3 wraps QuicConnection directly (per `docs/project-context.md` line 55: *"H3CoroServer wraps QuicConnection directly (same as H3HandlerServer), not H3Connection"*) but also holds an `H3Connection` for the H3-specific event stream.
- `_body_fn: H2BodyFn` → `_body_fn: H3BodyFn`.
- Other fields (`_extra_data`, `_outbuf`, `_streams`, `_ctx_pool`) carry over identically.

```
struct H3CoroServer(Movable):
    """Drive per-stream state from an HTTP/3 H3Connection over a
    QuicConnection. Sans-IO: caller feeds inbound QUIC datagrams via
    `feed_datagram_from_buffer()` and drains outbound datagrams via
    `drain()`. Each stream's user handler runs synchronously when the
    request arrives (Sprint 2A Path A — no stackful coroutines)."""

    var _quic: QuicConnection
    var _h3: H3Connection
    var _body_fn: H3BodyFn
    var _extra_data: UnsafePointer[NoneType, MutExternalOrigin]
    var _outbuf: List[UInt8]
    var _streams: Dict[Int, _CoroStreamPtr]
    var _ctx_pool: CoroStreamCtxPool
```

### Task 2.9: Constructors + `__del__`

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append within the struct)

- [ ] **Step 1: Add constructors**
Mirror `src/h2/h2_coro_server.mojo:283-323`. Use the constructor signatures the existing `src/h3/h3_coro_server.mojo:133+` lines wired up — read those lines first to get the exact `QuicConnection` + `H3Connection` setup, then port them into the sync server.

The body of each constructor calls `_check_stream_ctx_size()` first, then constructs the QUIC + H3 layers, sets `self._body_fn`, `self._extra_data`, allocates `self._outbuf`/`self._streams`/`self._ctx_pool = CoroStreamCtxPool(capacity=16)`, and finally calls `self._flush_outbound()`.

- [ ] **Step 2: Add the `deinit take` move-init**
Mirror `src/h2/h2_coro_server.mojo:325-331` with all H3 fields.

- [ ] **Step 3: Add `__del__`**
Mirror `src/h2/h2_coro_server.mojo:333-343` — walk `self._streams.keys()`, free each ctx via `_free_stream`. Identical pattern.

### Task 2.10: Transport bridging API — `feed_datagram_from_buffer` + `drain`

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Read the existing H3 datagram path**
Read `src/h3/h3_coro_server.mojo:200-300` (or until the `feed_datagram_from_buffer` body ends) to capture the QUIC-datagram + H3-event handling pattern. The QUIC-side wiring stays identical between the coro and sync versions — only the per-stream dispatch (the part that allocated `CoroHandle`) changes.

- [ ] **Step 2: Port `feed_datagram_from_buffer`**
Copy the body verbatim, then locate the inner block that handles `H3_EVT_REQUEST_HEADERS_RECEIVED` (or the equivalent H3 event constant) — that is the site where the old version allocated `CoroHandle` and called `coro.resume()`. Replace it with the H2-style sync dispatch:
1. Construct `Request` from H3 headers via `request_from_h3_headers` (or whatever helper M5b shipped — read `src/h3/connection.mojo` for the helper name; if it doesn't exist, the H3 sync server inlines the same headers-to-Request adapter that `H3HandlerServer` uses).
2. Acquire a typed-uninitialised pointer from `self._ctx_pool.acquire()`.
3. `init_pointee_move` the new `CoroStreamCtx` into it.
4. Insert `_CoroStreamPtr(addr=UInt64(Int(ctx_ptr)))` into `self._streams`.
5. Call `self._body_fn(ctx_ptr)` — this is the SYNC dispatch (no coroutine).
6. Drain outbound (`_drain_responses` equivalent — see Task 2.11).
7. If `ctx.response_ended`, free the stream via `_free_stream` + `self._ctx_pool.release(ctx_ptr)` + `self._streams.pop(stream_id)`.

Mirror `src/h2/h2_coro_server.mojo:347-` for the structural pattern.

- [ ] **Step 3: Port `drain`**
Returns the accumulated outbound datagrams from `self._outbuf`, drains it, returns the bytes. Identical to H2's `drain` (mirror `src/h2/h2_coro_server.mojo`'s `drain` method — search for it and copy).

### Task 2.11: Internal helpers — `_dispatch_events`, `_drain_responses`, `_flush_outbound`

**Files:**
- Modify: `src/h3/h3_sync_server.mojo` (append)

- [ ] **Step 1: Port the three helpers from the H2 sync server**
- `_dispatch_events(events: List[H3Event])` — switches on H3 event tags (HEADERS, DATA, TRAILERS, STREAM_ENDED, STREAM_RESET, GOAWAY, CONNECTION_TERMINATED) and invokes the same per-stream handlers as the H2 sister file (mirror `src/h2/h2_coro_server.mojo`'s `_dispatch_events` switch arms; substitute H3 event constants from `src/h3/connection.mojo`).
- `_drain_responses` — for each stream in `self._streams`, if `ctx.response_ended` is True, send the response via `self._h3.send_headers(...) + send_data(...)` (use M5b's API; read `src/h3/connection.mojo` for exact signatures), then call `self._flush_outbound()`, then free the stream.
- `_flush_outbound` — moves QUIC datagrams from `self._quic.datagrams_to_send()` into `self._outbuf`. Mirror the existing H3 coro server's flush pattern verbatim.

### Task 2.12: Build the H3 sync server

**Files:**
- Build: `src/h3/h3_sync_server.mojo`

- [ ] **Step 1: Build smoke**
Run: `mojo build src/h3/h3_sync_server.mojo`
Expected: build succeeds with no errors. The R8 `comptime assert` fires at compile time; if it triggers ("`H3 CoroStreamCtx exceeded R8 budget`"), audit field choices in Task 2.5 before continuing.

- [ ] **Step 2: Commit Tasks 2.3-2.12 as one logical unit**
The skeleton + struct + helpers + server are a single coherent rewrite. Commit them together with a single message describing the H3 coro→sync mirror.
Use the `commit-smart` skill.

### Task 2.13: Update `src/h3/__init__.mojo` to re-export `H3CoroServer` from the new file

**Files:**
- Modify: `src/h3/__init__.mojo`

- [ ] **Step 1: Replace the export**
Find `from src.h3.h3_coro_server import H3CoroServer` (or equivalent line) and change `h3_coro_server` → `h3_sync_server`. The struct name `H3CoroServer` is preserved (per the spec D6: rename of H2 deferred to Plan 2B for the same reason this file's name is preserved here — minimise churn during the largest single piece of work in the sprint).

- [ ] **Step 2: Verify with grep**
Run: `grep -rn 'from src.h3.h3_coro_server' .worktrees/feat-h2-state-machine-path-a/src/ .worktrees/feat-h2-state-machine-path-a/bench/ .worktrees/feat-h2-state-machine-path-a/tests/`
Expected: only matches in the OLD file `src/h3/h3_coro_server.mojo` itself (which Task 2.18 deletes); zero matches elsewhere.

### Task 2.14: Rewrite `tests/test_h3_coro_server.mojo` → `tests/test_h3_sync_server.mojo` per Day-3 audit

**Files:**
- Create: `tests/test_h3_sync_server.mojo`
- Delete: `tests/test_h3_coro_server.mojo` (in Task 2.18 alongside the source-file delete)

- [ ] **Step 1: Build the new test file**
For each test classified REWRITE in Task 2.1, rewrite into `tests/test_h3_sync_server.mojo` with the new sync handler signature (`fn(UnsafePointer[CoroStreamCtx, MutAnyOrigin]) raises -> None`). Mirror Sprint 1's pattern in `tests/test_h2_coro_server.mojo` — read that file for the test-fixture shape (mock body fn, fixture builders, assertion helpers).

For each test classified DELETE: do not include.

For each test classified MOVE: it has already been stashed in `tests/_h3_streaming_pending.mojo` (Task 2.2) — do not include here.

- [ ] **Step 2: Run the new test file**
Run: `mojo run tests/test_h3_sync_server.mojo`
Expected: PASS — output `ok`.

- [ ] **Step 3: Register the test in the runner**
Read `scripts/run_tests.sh` and add `tests/test_h3_sync_server.mojo` to the test list. Remove `tests/test_h3_coro_server.mojo` from the list (the file itself is deleted in Task 2.18).

- [ ] **Step 4: Run the full suite**
Run: `bash scripts/run_tests.sh`
Expected: full src test suite still passes (count grows by however many REWRITE-classified tests landed).

- [ ] **Step 5: Commit**
Use the `commit-smart` skill.

### Task 2.15: Rewrite `bench/handler.mojo::bench_h3_body_fn` from `CoroBody` shape to sync ctx-pointer shape

**Files:**
- Modify: `bench/handler.mojo`

- [ ] **Step 1: Locate the existing function**
Run: `grep -n 'bench_h3_body_fn\|bench_h2_body_fn' bench/handler.mojo`
Read the existing `bench_h2_body_fn` (the post-Sprint-1 sync version) and the existing `bench_h3_body_fn` (the pre-rewrite coro version).

- [ ] **Step 2: Rewrite `bench_h3_body_fn`**
Mirror `bench_h2_body_fn`'s body verbatim. The H2 ctx type is `src.h2.h2_coro_server.CoroStreamCtx`; the H3 ctx type is `src.h3.h3_sync_server.CoroStreamCtx` (same name, different module). The two functions are structurally identical except for the ctx type alias.

If the H2 version reads `ctx.request.path` to dispatch to a static lookup, the H3 version does the same. If the H2 version writes `ctx.resp_writer.write_status(StatusCode.OK).write_headers(...).write_body(...)`, the H3 version does the same.

- [ ] **Step 3: Build smoke**
Run: `mojo build bench/handler.mojo`
Expected: build succeeds.

### Task 2.16: Update `bench/h3_server.mojo` to use `H3CoroServer` from the new module

**Files:**
- Modify: `bench/h3_server.mojo`

- [ ] **Step 1: Update the import**
Change `from src.h3.h3_coro_server import H3CoroServer` → `from src.h3.h3_sync_server import H3CoroServer`.

- [ ] **Step 2: Verify the body fn type alias**
The bench server registers `bench_h3_body_fn` as the `H3BodyFn` for `H3CoroServer`. Both sides now agree on the sync ctx-pointer signature — no further change needed.

- [ ] **Step 3: Build + run**
Run: `mojo build bench/h3_server.mojo -o bench/h3_server`
Expected: build succeeds.

Run smoke: `./bench/h3_server &` (background); `h2load --h3 -c 1 -m 1 -n 1 https://localhost:8443/baseline2`; expected `200 OK`. Stop server.

- [ ] **Step 4: Commit Tasks 2.13-2.16**
A single logical commit covering the H3 sync wiring across `__init__`, tests, `handler.mojo`, and `h3_server.mojo`.
Use the `commit-smart` skill.

### Task 2.17: Run H3 long-lived-connection bench, capture +15-25% RPS lift

**Files:**
- Append: `bench/profile/baselines/h3-throughput.csv`

- [ ] **Step 1: Run the long-conn cell**
Per spec acceptance §3, the H3 lift is measured on a **long-lived-connection** cell, NOT cold-start short-conn (which is bottlenecked by accept-loop FFI per project-context line 117 and which a handler-shape change cannot move).

```
mojo build bench/h3_server.mojo -o bench/h3_server
taskset -c 0,1,2,3 ./bench/h3_server &
sleep 1
taskset -c 4,5,6,7 h2load --h3 -c 1 -m 1000 -n 100000 \
  https://127.0.0.1:8443/baseline2 \
  | tee /tmp/h3_sync_run1.txt
```
Repeat for run2 and run3.

- [ ] **Step 2: Compare to pre-rewrite baseline**
Before the rewrite landed, the H3 baseline on the same cell (single connection, 1000 streams in flight) is whatever the latest `bench/profile/baselines/h3-throughput.csv` row tagged `m5c-coro` records. If that row does not exist, capture it now: `git stash` the rewrite (effectively `git checkout main -- src/h3/h3_coro_server.mojo bench/h3_server.mojo bench/handler.mojo` into a temp worktree); rerun the bench cell; restore the rewrite.

- [ ] **Step 3: Compute lift + append to CSV**
RPS lift % = (sync_median - coro_median) / coro_median × 100. Append row tagged `sprint-2a-h3-sync` with the median RPS and the % lift. Acceptance: lift in [+15%, +25%]; if outside that range, flag in commit message — under-lift suggests Sprint 1's H2 bottleneck is not present on H3 (likely because QUIC's per-stream state already dominates), over-lift suggests something else changed and bears investigation.

- [ ] **Step 4: Commit**
Use the `commit-smart` skill.

### Task 2.18: Delete the old `h3_coro_server.mojo` source + test files

**Files:**
- Delete: `src/h3/h3_coro_server.mojo`
- Delete: `tests/test_h3_coro_server.mojo`

- [ ] **Step 1: Verify zero remaining references**
Run: `grep -rn 'h3_coro_server' .worktrees/feat-h2-state-machine-path-a/src/ .worktrees/feat-h2-state-machine-path-a/bench/ .worktrees/feat-h2-state-machine-path-a/tests/ .worktrees/feat-h2-state-machine-path-a/scripts/`
Expected: zero matches outside the two files about to be deleted.

- [ ] **Step 2: Delete**
Run: `git rm src/h3/h3_coro_server.mojo tests/test_h3_coro_server.mojo`

- [ ] **Step 3: Run full src test suite**
Run: `bash scripts/run_tests.sh`
Expected: all src tests pass (count steady or grown by REWRITE-classified tests).

- [ ] **Step 4: Run full conformance suite**
Run: `bash conformance/scripts/run_tests.sh`
Expected: 35/35 (per project-context line 125-127).

- [ ] **Step 5: Run reverse-proxy e2e**
Run: `bash scripts/test_reverse_proxy.sh`
Expected: green.

- [ ] **Step 6: Commit**
Use the `commit-smart` skill.

---

## Phase 3 — Plan 2A integration

### Task 3.1: HttpArena `validate.sh` for H1/H2/H3

**Files:**
- Run-only: `bench/validate.sh` (or `scripts/validate.sh` — locate via grep)

- [ ] **Step 1: Locate the HttpArena validation script**
Run: `find . -name 'validate.sh' -path '*/bench/*' 2>/dev/null; find . -name 'validate.sh' -path '*/scripts/*' 2>/dev/null`
Expected: exactly one path (or two if there's both bench- and script-level; pick the one referenced by recent bench commits in the spec).

- [ ] **Step 2: Run validation**
Run: `bash <path-from-step-1>` (the script handles all three protocols).
Expected: H1, H2, H3 all green.

- [ ] **Step 3: If H3 fails**
Acceptance §2 requires all three protocols pass. If H3 alone fails post-rewrite, investigate the failing case before proceeding. Common rewrite-introduced failures: missing event-tag arm in `_dispatch_events` (Task 2.11), uninitialised field in `CoroStreamCtx` constructor (Task 2.5), `_streams` Dict insert/free mismatch (Task 2.10). Use git diff against `main` for the pre-rewrite H3 path as a reference.

### Task 3.2: Plan 2A retro working note

**Files:**
- Create: `plans/2026-04-27-sprint-2a-retro-notes.md` (a working note, NOT the Sprint 2 retro)

- [ ] **Step 1: Capture outcomes**
Write a 1-page note covering:
- Phase 1 outcome: trigger scorecard, pool added Y/N, measured H1 lift.
- Phase 2 outcome: actual H3 sync mirror days vs estimated 5; any unexpected QUIC-layer surprises during port; final R8 ctx size for H3.
- Day-3 audit classification table (verdict per test).
- Bench numbers: H1 baseline vs pool-on (if added), H3 long-conn lift %.
- Open issues to flag for Plan 2B's planning: e.g. if H3 sync mirror surfaced an `H3Connection.send_data` shape that doesn't expose a `WouldBlock` sentinel (that would push Plan 2B Day 9's prerequisite audit higher-priority), or if pool capacity 16 was wrong for H1 and 4 or 32 worked better, etc.

This is a working note — kept locally for Plan 2B's planning to consume; the Sprint 2 retrospective covers both 2A + 2B and is written after 2B lands.

- [ ] **Step 2: Commit**
Use the `commit-smart` skill.

### Task 3.3: Push the branch (do NOT open a PR; pre-2B)

**Files:**
- (Git operation only; no file changes.)

- [ ] **Step 1: Push**
Run: `git push -u origin feat/h2-state-machine-path-a`
Expected: branch updated on origin. **Do NOT open a PR** — Plan 2B continues on the same branch and the PR opens after 2B's retrospective lands.

If the user has not authorised pushing to origin, skip this step and surface the request.

---

## Spec → Task coverage check

| Spec requirement | Task(s) |
|---|---|
| Pre-Sprint-2 prerequisite #1 (Sprint 1 row) | 0.3 |
| Pre-Sprint-2 prerequisite #2 (`src/io/` exception) | 0.2 |
| Pre-Sprint-2 prerequisite #3 (Mojo pin) | 0.1 |
| §1 H1 sync wiring + audit + pool-if-hot | 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8 |
| §2 H3 sync mirror | 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12 |
| §2 Day-3 H3 test enumeration audit | 2.1, 2.2, 2.14 |
| §2 H3 sync bench wiring + lift capture | 2.15, 2.16, 2.17 |
| §2 R8 H3 sync ctx assert | 2.6, 2.12 |
| §2 Old H3 coro file delete | 2.18 |
| Acceptance §1 (5 servers build clean) | 1.2 (h1), 2.16 (h3); h2_sync renaming is Plan 2B; streaming files are Plan 2B |
| Acceptance §2 (HttpArena validate.sh) | 3.1 |
| Acceptance §3 (no regressions + H3 +15-25%) | 1.8 (h1 lift), 2.17 (h3 lift) |
| Acceptance §6 (R8 + R8' asserts) | 2.6 (R8 H3 sync); R8' is Plan 2B |
| Acceptance §7 (test count grows by 8-10) | 1.5 (pool tests if added), 2.14 (H3 sync rewrites) |
| Acceptance §8 (conformance still 35/35) | 2.18 step 4 |

**Out-of-scope-for-Plan-2A spec items (Plan 2B):**
- Acceptance §1 streaming + h2_sync files
- Acceptance §4 streaming demonstration
- Acceptance §5 R1' grep gate
- Acceptance §6 R8' streaming-ctx asserts
- Acceptance §7 streaming tests
- Acceptance §9 retrospective (single retro covers both plans, written after 2B)
- D6 H2 rename (Plan 2B Day 8)
- §4 H3 streaming server
- §5 H2 streaming server
- §6 streaming bench fixtures + servers
- §7 R1' grep gate codification

---

## Risks specific to Plan 2A

### R-2A-1. H3 ctx exceeds R8 1024 B budget at compile time

H3 ctx is structurally similar to H2's CoroStreamCtx (~608 B in Sprint 1) but `stream_id` widens from `UInt32` to `UInt64` (+4 B) and other QUIC-specific fields may creep in. The `comptime assert` in Task 2.6 fires at compile time if the budget is exceeded.

**Mitigation:** if Task 2.12 trips the R8 assert, the heaviest non-essential field is usually `caps: Capabilities` (which clones; consider pointer-to-shared-caps if it's the culprit). If the H3 ctx structurally cannot fit under 1024 B, propose an R8 budget revision to <2048 B per the spec's R4 mitigation; record in the Sprint 2 retro.

### R-2A-2. `H3Connection.send_data` does not expose a `WouldBlock` sentinel

The spec's Plan-2B-Day-9 prerequisite audit reads this surface and adds the sentinel if missing. Plan 2A's H3 sync server doesn't NEED `WouldBlock` (sync responses are written end-to-end inside the body fn; backpressure is handled by QUIC's stream FC dropping the send), but if Task 2.10's port reveals that `send_data` always blocks-or-aborts with no in-between, that is itself a Plan 2A finding worth recording so 2B starts informed.

**Mitigation:** during Task 2.10, audit `H3Connection.send_data` and record its behavior in the Plan 2A retro working note (Task 3.2). Pre-warns Plan 2B's planning.

### R-2A-3. M5b's `H3HandlerServer` already has the helpers `H3CoroServer` will need

`docs/project-context.md` line 146 says: *"H3HandlerServer (heap-allocated per-stream contexts, response draining)"* shipped in M5b. The H3 sync server's response-draining code (Task 2.11 `_drain_responses`) might be duplicating logic that `H3HandlerServer` already encapsulates.

**Mitigation:** at the start of Task 2.11, read `src/h3/h3_handler_server.mojo` and identify any helper that `H3CoroServer` (sync) can call directly rather than re-port. Aim for the H3 sync adapter to be a thin shim over `H3HandlerServer` if the surface allows it; if it does not, port the helpers verbatim and flag the duplication for a Sprint 4 polish pass.

### R-2A-4. Phase 1 audit is inconclusive (allocator pressure between thresholds)

Triggers in Task 1.3 are quantified, but borderline cases (e.g. malloc-CPU% = 4.7% — fails the ≥5% trigger but feels meaningful) need a tiebreaker.

**Mitigation:** if the audit lands in [4%, 5%) malloc-CPU OR [0.7, 1.0) `_heap_alloc`/req, default to **adding the pool** (cost is small — ~80 lines of code; benefit if the cold-start regression manifests later is large). Record the borderline call in the commit message.

### R-2A-5. Task 2.10's port surfaces an event tag the H2 sister file doesn't have

H3 has events H2 doesn't: H3-specific GOAWAY semantics (request-stream-IDs vs H2's stream-IDs), `H3_DATAGRAM_RECEIVED` (deprecated path), unidirectional-stream lifecycle events. Mirroring H2's `_dispatch_events` won't cover these.

**Mitigation:** when porting Task 2.11's `_dispatch_events`, read the existing `src/h3/h3_coro_server.mojo`'s switch arms first (it has all the H3 event tags wired up). The H3 SYNC server's switch arms are: copy the existing H3 coro switch arms verbatim, replacing only the per-stream dispatch (the part that allocated `CoroHandle` and called `coro.resume()`) with the sync ctx-pointer call site identified in Task 2.10 step 2.

---

## Plan 2A end state

After Task 3.3:
- Branch `feat/h2-state-machine-path-a` has Sprint 1 (11 commits) + Phase 0 (1 commit) + Phase 1 (3-7 commits depending on pool decision) + Phase 2 (4-6 commits) + Phase 3 (3 commits) ≈ 22-28 commits total.
- All five servers from the spec's "5 servers" acceptance criterion that exist in 2A's scope (h1, h2_sync renamed-to-be in 2B, h3_sync) build clean.
- HttpArena `validate.sh` green for H1/H2/H3.
- Three-config bench captures recorded in `bench/profile/baselines/{h1,h3}-throughput.csv`.
- R8 H3 ctx compile-time assert in place.
- Plan 2B's planning has a working-note input (`plans/2026-04-27-sprint-2a-retro-notes.md`) covering the Phase-1 outcome + the Task 2.10 audit of `H3Connection.send_data` shape.

Plan 2B then continues on the same branch.
