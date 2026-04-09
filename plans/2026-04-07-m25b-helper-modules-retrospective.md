# M2.5b — Helper Modules Retrospective

**Branch:** `m25b-helper-modules` (worktree `.worktrees/m25b-helper-modules`)
**HEAD:** `8f43e38`
**Commits landed:** 11 (10 TDD task commits + 1 post-review fix)
**Tests:** 33/33 src + 27/27 conformance + reverse-proxy e2e — all green
**LoC delta:** ~1217 lines across 6 new files (plan target was ~950; overshoot due to Mojo 0.26.2's verbose byte-scanning idiom)

## What was built

All 11 tasks from the plan landed as-sketched, with Mojo 0.26.2 syntactic adaptations at every parser site. Three fully independent additive helper modules under `src/http/`:

1. **`src/http/priority.mojo`** (120 LoC) — RFC 9218 Priority header. `Priority` struct (urgency + incremental) with `default()` / `parse_header()` / `serialize_header()` round-trip verified.
2. **`src/http/alt_svc.mojo`** (366 LoC) — RFC 7838. `Origin(KeyElement)` key struct, `AltSvcEntry`, `parse_alt_svc()` free function, `AltSvcCache` with insert/lookup/clear/clear_expired.
3. **`src/http/sse.mojo`** (327 LoC) — WHATWG event-stream subset. `ServerSentEvent`, `EventStreamReader` (incremental parser wrapping `DetachedBody`), `try_write_event` stateless free function. Writer → reader round-trip verified through the real `ResponseWriter` / `DetachedBody` M2.5a types.

Plus three new test files (94/127/183 LoC) and two re-export lines in `src/http/__init__.mojo`.

## Deviations from spec

**Documented upfront in the plan (carried through unchanged):**

1. **Flat test layout.** `tests/test_*.mojo` instead of `tests/http/test_*.mojo` — matches every other file under `tests/`.
2. **`try_write_event` is a stateless free function** instead of the spec's `EventStreamWriter` struct wrapping an `UnsafePointer[ResponseWriter]`. The spec sketch contradicted its own "does NOT take ownership" line and carried lifetime risk.

**Discovered during implementation (Mojo 0.26.2 forced):**

3. **`comptime` constants without type annotations.** `comptime DEFAULT_URGENCY = 3` (no `: Int`). Matches the existing `comptime ALPN_*` pattern in `src/http/handler.mojo`.
4. **Byte-scanning throughout all parsers.** String `[i]` indexing and `[start:end]` slicing are unsupported in Mojo 0.26.2. Every parser (`parse_header` for Priority, `parse_alt_svc` and its helpers, `_parse_event_bytes` for SSE) uses `.as_bytes()` + `UInt8` constants + `chr(Int(b))` accumulation, matching the existing idiom in `src/h1/parser.mojo:_bytes_to_string`. This roughly triples the line count of each parser compared to a string-slice-based version — accounts for most of the ~270 LoC overshoot vs the plan target.
5. **`struct Origin(KeyElement)`** instead of the plan's `(Copyable, Movable, Hashable, EqualityComparable)`. MCP investigation revealed `Hashable` lives under `hashlib.hash`, `EqualityComparable` does not exist (only `Equatable`), and `KeyElement` (from `std.collections.dict`) is a composite alias bundling every constraint needed for `Dict` keys. MCP `validate` confirmed `Dict[Origin, Int]()` works.
6. **`AltSvcCache.lookup` / `clear` / `clear_expired` marked `raises`.** `Dict.__getitem__` and `Dict.pop` both raise on missing key in Mojo 0.26.2, which propagates upward. The plan declared them non-raising.
7. **`AltSvcCache.clear(origin: Origin)` takes borrow, not `var`.** Plan used `var origin` (consuming); changed to borrow so callers can keep using `origin` in subsequent lookups. Internal copies made via `Origin(other=origin)`.
8. **`_split_top_level(s, sep: UInt8)`** — single-byte separator, not `sep: String`. Simpler and matches the actual call sites (`,` and `;`).
9. **`Optional[T]` direct-assign in copy constructors.** `Optional[T]` in Mojo 0.26.2 has `.copied()`, not `.copy()`, and is `ImplicitlyCopyable` so direct assignment already performs a copy. Pattern: `self.event = other.event` (for Optional) but `self.data = other.data.copy()` (for String).
10. **`for kv in Dict.items(): kv.key / kv.value`** — field access, not subscript. The per-task reviewer suggested `kv[]` style but that failed to compile.
11. **`to_drop[j]^` rewritten as `Origin(other=to_drop[j])`.** Transferring out of a `List` by index is not allowed ("expression does not designate a value with an origin").

**Post-review fix (commit `8f43e38`, not in the original plan):**

12. **`EventStreamReader` partial-event discard on stream end.** The final cross-cutting review flagged a livelock: if a body ends mid-event (no trailing blank line), `is_end()` returned `False` forever because the buffer was non-empty but `try_next_event()` couldn't find a boundary. Fix: when `_body_ended` is true and no boundary is found, clear the buffer (WHATWG §9.2 discards incomplete events at dispatch time). New regression test `test_reader_partial_event_at_end_discarded`.

## Pain points

- **Byte-scanning boilerplate is repetitive.** Each parser re-implements the same "range start → range end → build string via `chr(Int(b))`" pattern. By the end of Phase 2 the subagent had implemented variants of this loop ~15 times. A shared `src/http/_bytes_util.mojo` with `bytes_to_string(buf, start, end)` and `bytes_equal_str(buf, start, end, literal)` helpers would cut 50-80 lines per parser and make the intent clearer. Deferred to M2.5c / HC-4 cleanup.
- **Two-stage subagent reviews on mechanical tasks are heavy.** Tasks like "add struct with 4 fields + constructor" are too small for the per-task spec + quality review loop to meaningfully catch issues — every review found only minor stylistic notes. The real value was in Task 6 (`parse_alt_svc`) and Task 9 (`EventStreamReader`), which actually had subtle bugs surfaceable by review. Consider bundling trivial tasks within a phase in future plans.
- **Worktree fixture inheritance gap.** `conformance/vectors/hpack-stories/` is a nested git repo (has its own `.git`), so it doesn't track into the worktree. `lib/librustls_mojo.so` is untracked. Both had to be manually symlinked from main before tests could run. A worktree-setup script would make this reproducible.
- **Mid-run `cd` drift.** When running the conformance suite from main (to verify the test data issue was pre-existing), the shell working directory left the worktree. Subsequent `bash scripts/run_tests.sh` calls ran against main (30/30, no helpers) and looked broken until I noticed the `pwd`. Prefer absolute paths or explicit `cd` chains when comparing worktree vs main.
- **Reviewer false positive: "use direct assignment instead of `.copy()` for String."** Two independent quality reviewers suggested dropping explicit `.copy()` on String fields, but the project-context explicitly documents that Mojo 0.26.2 requires explicit `.copy()` for move-only-via-list edge cases, and the existing codebase (e.g. `src/http/body.mojo`) uses this idiom consistently. Orchestrator-level judgment overrode the reviewer advice. This is expected — reviewers lack the full codebase context — but it's a reminder that subagent reviews are advisory, not authoritative.

## Interrogations during implementation

- **Should `parse_header` call `atol` inside try/except to wrap errors?** Quality reviewer (Task 2) flagged that `atol("abc")` raises without a parser-specific message. I chose to let it propagate — the test suite covers the "correct" path and the raised error is still a valid Mojo `Error`. A future hardening pass can add descriptive wrapping.
- **`AltSvcCache` double-copy on `insert`.** The implementation stores `Origin(other=origin)` in `_entries` and moves `origin^` into `_received_at`. Functionally correct because both dicts agree on the key (same hash, same eq), but the asymmetry is easy to misread. I considered "symmetrize to two copies" vs "keep as-is" — kept as-is because any symmetry rewrite would need another extra copy, and the current form is only confusing if you don't know Mojo's move semantics.
- **`_find_event_boundary` re-scan on split frames.** When `try_next_event` is called repeatedly while bytes arrive a few at a time, each call re-scans the entire buffer from offset 0 looking for the boundary. This is O(n²) in the worst case. I kept the simple form because the typical SSE payload is small and M6 / HC-4 may add its own buffer-management layer. Flagged in the retrospective for future perf work.
- **`_try_parse_uint` on very large retry values.** No overflow guard. `"99999999999999999999"` wraps silently. Not exercised by any test. WHATWG says "parse as ASCII decimal" without bounds, so this is spec-conformant but a practical concern. Deferred.

## Open questions

- **Merge strategy for `m25b-helper-modules`.** Project convention (per `c93aaf9`) is `--no-ff` merges to preserve the phase boundary in git log. Should M2.5b land the same way?
- **Should the Mojo 0.26.2 deviations be reconciled back into the spec** (as the post-M2.5a `# M2.5a:` inline notes did)? The spec §7 sketches still show `struct Origin(Copyable, Movable)` and `EventStreamWriter { var _resp: UnsafePointer[...] }`, which are misleading for anyone reading the spec post-M2.5b. Deferred to the user's call during merge.
- **`src/http/_bytes_util.mojo` extraction.** Now that three parsers share the same byte-scanning idiom, is it worth factoring it out before HC-4 starts, or should HC-4 do it when it writes the HPACK decoder (which will hit the same pattern)? My preference: let HC-4 decide, because it has more data on the calling shapes.
- **SSE writer performance.** `try_write_event` builds a `String` via byte-by-byte `chr(Int(b))` then converts back to `List[UInt8]` for the `BodyFrame.data` payload. Two quality reviewers flagged this — `O(n)` intermediate copies per event. For the target M6 use case (client-side SSE consumer, mostly reading not writing), this is acceptable; for a server pushing 1000 events/sec it isn't. Deferred until a real server-side SSE use case lands.
- **`AltSvcCache.lookup` invariant between `_entries` and `_received_at`.** The two dicts must stay in sync; `insert` and `clear` maintain this, but nothing prevents a future edit from desynchronizing them. A paired existence check or a single `Dict[Origin, (List[AltSvcEntry], UInt)]` would make the invariant structural. Deferred — current tests all pass and the struct is private to this module.

## Recommendations for next spec

- **HC-4 should front-load the `src/http/_bytes_util.mojo` extraction** if it ends up touching HPACK decoding. The four places in M2.5b that reinvent byte-to-string are: `priority.mojo:parse_header`, `alt_svc.mojo:_strip_ws`/`_split_top_level`/`_parse_one_entry`, `sse.mojo:_bytes_to_string`. Centralizing these gives HC-4 a consistent interface for byte-level work.
- **For plans with many small tasks (10+), consider phase-level subagent dispatch** instead of per-task. M2.5b's 11 tasks took ~30 subagent dispatches (11 implementers + 11 spec + 11 quality + 1 final). For the mechanical tasks (1, 3, 5, 8), the per-task review cycle added review-level tokens without catching issues. Tasks 6, 9, and the final cross-cutting review were where the two-stage review paid off.
- **Worktree bootstrap automation.** A `scripts/setup_worktree.sh` that symlinks `lib/` and `conformance/vectors/hpack-stories/` would save 2-3 minutes of confused test runs at the start of every worktree-based implementation session.
- **Reconcile the M2.5 spec §7 sketches with the landed types** post-merge, mirroring what the M2.5a post-merge reconciliation did with the `# M2.5a:` inline notes. HC-4 and M6 will read §7 for the `Priority` / `Alt-Svc` / `SSE` shapes; the sketches currently show trait lists (`Copyable, Movable`) and type signatures (`UnsafePointer[ResponseWriter]`) that don't match the real implementation.
- **Open the `AsyncBody / M2.6` question early in HC-4 planning.** HC-4 is the first milestone post-Mojo-0.26.2 research spike; if Mojo 0.27 ships before HC-4 lands, the async executor re-spike should happen in parallel to avoid blocking.
