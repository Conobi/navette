# Research Plan — `_drain_stream` Deep-Dive

**Created:** 2026-05-01
**Predecessor:** Q1 (shipped at main `70ba90c`) named `quic_post_recv_us` at ~19.4M μs / 30s as long-conn dominant. The bracket covers `_quic.timeout` + poll-loop including `_drain_stream` inside `feed_datagram_from_buffer` (`src/h3/connection.mojo:259-317`).
**Goal of next spec:** Diagnostic sub-leg pass that decomposes the post-recv bracket into 4-5 named sub-phases so the *follow-on* optimization spec has a measurement-grounded target.
**Why research first:** Predictions from code inspection have a 0/2 track record on this codebase (Subagent B's prediction overturned by Q1; sub-leg pass's `write_hs` prediction overturned). Mirror reference QUIC stacks before guessing what to time.

## Topic Table

| # | Topic | Status | Depends on | Priority | Rationale |
|---|---|---|---|---|---|
| 1 | TQUIC + quiche stream-data accumulation + frame-parse paths | not-started | — | high | Defines the sub-leg taxonomy. We want our 4-5 timers to map onto the same logical stages reference stacks use (FFI recv / buf accumulate / frame parse / QPACK decode / event delivery) so cost-share is comparable across stacks during the follow-on optimization. |
| 2 | Mojo `Dict[K, struct].copy` + `List[UInt8]` batch-API surface (Mojo 0.26.2) | not-started | — | medium | Confirms whether the defensive `.copy()` calls and byte-by-byte loops in `_drain_stream` / `_parse_frames_from_buf` are real work or compiler-elided. Also enumerates available alternatives (`extend(Span)`, `del lst[:n]`, span-over-list) for the follow-on optimization spec. Not strictly gating the diagnostic spec but feeds the cycle. |

## Dependency Graph

```
Topic 1 (TQUIC/quiche taxonomy)  ─┐
                                    ├──→ brainstorming continues
Topic 2 (Mojo Dict + List APIs) ─┘
```

Both topics are independent and run in parallel. Brainstorming resumes when both are complete.

## Topic 1 — TQUIC + quiche stream-data accumulation + frame-parse paths

**Output:** `research/2026-05-01-tquic-quiche-stream-read-paths.md`

**Questions to answer:**
1. In TQUIC's H3 layer, what is the equivalent of mojo-net's `_drain_stream`? Trace from QUIC stream-readable event → H3 frame parse → request handler dispatch.
2. What data structure holds the per-stream accumulating buffer? (Ring? VecDeque? Cursor over Bytes?)
3. How is "consume N bytes from front" implemented? (Slice + reassign? `advance`-style cursor? Linked Bytes chunks?)
4. Is QPACK decode invoked per-HEADERS-frame, or batched across multiple frames?
5. Same questions for quiche (Cloudflare's QUIC stack, well-documented).
6. What named time-measurement points do TQUIC / quiche maintainers cite in their performance docs? (Look for benchmark tooling, profiler outputs, or commit messages.)
7. Are there per-stream FFI calls per readable event, or is recv batched?

**Method:** Read TQUIC source at `~/Projets/perso/tquic` (already cloned per `feedback_mirror_tquic.md`); fetch quiche from GitHub if not cached; web-search for any "how we benchmark" / "profiling H3" maintainer posts.

**Out of scope:** lsquic, quinn (informative but not the named primary references); ngtcp2 (C); aioquic (Python — already dismissed as non-representative for perf).

## Topic 2 — Mojo `Dict[K, struct].copy` + `List[UInt8]` batch-API surface

**Output:** `research/2026-05-01-mojo-list-dict-batch-apis.md`

**Questions to answer:**
1. In Mojo 0.26.2, does `List[UInt8].extend(Span[UInt8])` exist? If yes, signature + cost. If no, what's the canonical batch-append idiom?
2. Does `del lst[:n]` (slice-delete) work for `List[UInt8]`? If yes, is it O(n) or O(remaining)?
3. Can `Span(my_list)` be constructed without copying the list? What's the lifetime of the span vs the list it views?
4. When we write `var sbuf = self._stream_bufs[key].copy()`, is this a deep struct copy? Does it allocate? What's the cost relative to a `mut`-borrow if one were available?
5. Are there `mut`-borrow accessors on Mojo `Dict` (e.g. `dict.get_ref(key)`) in 0.26.2 that bypass `.copy()`?
6. What's the canonical "head cursor instead of front-shift" pattern in Mojo? (struct with `buf: List[UInt8]` + `head: Int` field; `len_remaining = len(buf) - head`).

**Method:** Mojo MCP `lookup` for `List`, `Dict`, `Span`; `search` for `extend`, `__delitem__`, `get_ref`; `validate` quick snippets for unknown idioms; `changelog` for 0.26.2 release notes on List/Dict.

**Out of scope:** SIMD primitives, InlineArray, comptime metaprogramming (Sprint 3 territory); FFI buffer management.

---

When both topics close green, brainstorming resumes with concrete sub-leg taxonomy + idiom-grounded follow-on plan.
