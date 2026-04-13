# mojo-net — Project Context

**Last updated:** 2026-04-13
**Current phase:** done

## Why this exists

Pure-Mojo networking stack. The death-star deliverables are:
1. A fast HTTP/3 server
2. A feature-complete unified HTTP client (works over H1/H2/H3 with one API)

Single native dependency: rustls via a thin C FFI shim (`librustls-mojo`).

## Scope

- **Wire formats:** QUIC, HTTP/3, HTTP/2, HTTP/1.1
- **Servers:** H3 (primary goal), H2, H1
- **Clients:** Unified client with protocol selection via ALPN
- **TLS:** via librustls-mojo (rustls 0.23)
- **I/O:** sans-I/O at every protocol layer; `boucle` (separate library) used only in examples
- **Conformance:** test-vector + oracle cross-validation methodology (HC-1..HC-5, QC-1..QC-2)

## Non-goals

- Server push (deprecated in H2, dead in practice in H3)
- macOS/Windows I/O backends in v1 (Linux only via boucle)
- HTTP/0.9, SPDY, gQUIC
- Connection migration in v1 of M3 (deferred enhancement)
- WebSocket support in v1 (revisit after M6)

## Key architectural decisions

- **Sans-I/O at every protocol layer.** Application code composes the protocol layer with an I/O loop (boucle in examples). No I/O imports inside `src/`. Exception: `boucle.stackful` (CoroHandle, CoroYielder) is allowed in `src/` because it is a control-flow mechanism with no I/O dependency. Only boucle's I/O primitives (`boucle.net.*`, `CompletionLoop`, `CompletionHandler`) are restricted to examples.
- **Strict-by-default parsing** with opt-in leniency via per-rule flags (24 flags in HTTP/1.1 ParserStrictness).
- **Conformance-driven development.** Each milestone has its own conformance suite with test vectors and oracle cross-validation before production code is written.
- **Test oracles:** h11 + httptools (HTTP/1.1), hyperframe (H2 frames), Python `hpack` (HPACK), hyper-h2 (HC-4 future), aioquic + quiche (H3/QUIC future).
- **Vector format:** JSON, consistent across all protocols.
- **Conformance vs production split:** `conformance/lib/` holds reference implementations used as test oracles; `src/` holds production code that is cross-validated against them.
- **librustls-mojo Wave model:** Wave 1 = TCP-TLS + AEAD primitives (done); Wave 2 = QUIC handshake lifecycle (deferred to M3).
- **HTTP/3 is the canonical shape.** API design leads with H3 semantics; H2 and H1 are graceful projections of that shape onto older wire formats. Build order is H2 first (HC-4 → M5.5) for validation reasons, but the public API is designed against H3 semantics from M2.5 onwards.
- **Handler execution model is callback-based** (γ hybrid: per-stream queue with `try_read` / `on_body_available`). Sync and async adapters deferred — Mojo's coroutine runtime is experimental and not pluggable to custom I/O sources today (verified via Modular docs + GitHub issues 2026-04-07).
- **Body ownership across handler callbacks: hybrid with explicit `detach()`.** Default is borrowed from runtime; handlers call `body.detach() -> DetachedBody` to take ownership for forwarding (reverse proxy) or wrapping (SSE). One-way; no resurrection.
- **Capability negotiation: runtime flags + standalone `H3StreamExtension` trait.** Not type-state generics (would create origin propagation through M6). Not trait inheritance with method override (fictional in Mojo). Standalone H3 trait avoids both pitfalls.
- **Session trait is compile-time monomorphic.** M6's connection pool composes via tagged enum or vtable indirection — decision deferred to M6 implementation time. The trait surface itself does not commit.
- **Client request ownership: owning, not borrowing.** `Session.submit(var req: Request)` consumes the request; `RequestHandle` owns derived state; no origin parameters propagating through `List[RequestHandle]`.
- **Default constants match hyper exactly.** 1 MiB stream window, 16 KiB max frame, 200 max concurrent streams, 20s keepalive. Subject to change after benchmarking; not stable API.
- **Mojo 0.26.2 conventions used in spec/code:** `def` for trait methods and ordinary methods; `fn __del__(deinit self)` for destructors; `def __init__(out self, *, deinit take: Self)` for move constructors; `comptime` constants instead of `@parameter`; integer constants for ALPN identifiers (no per-stream `String`).

## Active specs and plans

| Status | Spec | Notes |
|---|---|---|
| shipped | `specs/2026-04-07-m25-unified-http-api.md` → `plans/2026-04-07-m25a-unified-http-api.md` | M2.5a (HC-4 unblocker) — merged to main as `c93aaf9` and pushed to origin 2026-04-07. 30/30 src + 27/27 conformance + reverse-proxy e2e all green. Spec reconciled post-merge with inline `# M2.5a:` notes describing the five Mojo-0.26.2 forced deviations. |
| shipped | `specs/2026-04-07-m25-unified-http-api.md` → `plans/2026-04-07-m25b-helper-modules.md` | M2.5b (M6 unblocker) — merged to main as `3eb7b47` on 2026-04-09. 11 TDD commits + 1 post-review fix (`8f43e38`). 33/33 src + 27/27 conformance + reverse-proxy e2e all green. ~1217 LoC across 6 new files. Retrospective: `plans/2026-04-07-m25b-helper-modules-retrospective.md`. |
| done | `specs/2026-04-09-hc4-h2-connection-layer.md` → `plans/2026-04-09-hc4-phase0-trait-change.md` | HC-4 Phase 0 (prep commit: mut body + try_detach). 4 commits (`50b890e..f07a0f6`). 34/34 src + 27/27 conformance + e2e green. Final cross-cutting review: CLEAN. |
| done | `specs/2026-04-09-hc4-h2-connection-layer.md` → `plans/2026-04-09-hc4a-connection-core.md` | HC-4a connection core. 15 TDD commits (`64338e3..9955b95`). 24 unit + 3 cross-validation tests. 29/29 conformance + 34/34 src + e2e green. Retrospective: `plans/2026-04-09-hc4a-connection-core-retrospective.md`. Pushed to origin/main on 2026-04-10. |
| done | `specs/2026-04-09-hc4-h2-connection-layer.md` → `plans/2026-04-10-hc4b-stream-data-path.md` | HC-4b stream data path. 13 TDD tasks + 2 review fixes (`0e7108c..a1ff9d8`). 21 unit + 3 cross-validation tests. 31/31 conformance + 34/34 src + e2e green. Final cross-cutting review: CLEAN after 2 fix rounds. Pushed to origin/main on 2026-04-10. |
| done | `specs/2026-04-10-m55-h2-client-server.md` → `plans/2026-04-10-m55-h2-client-server.md` | M5.5 — HTTP/2 client/server + TLS/ALPN. 19 commits (`41b1e1d..90bf233`). H2HandlerServer (7 handler tests) + H2Session (7 session tests) + 3 e2e tests + 2 TLS ALPN tests. 39/39 src + 31/31 conformance + e2e green. Final cross-cutting review (opus): 3 important issues fixed (missing __del__, streaming body rejection, canonical response parser). |
| done | `specs/2026-04-13-m26-h2-coro-server.md` → `plans/2026-04-13-m26-h2-coro-server.md` | M2.6 — H2CoroServer + coroutine-based reverse proxy. 10 commits (`b11b815..18324fa`). H2CoroServer adapter (581 LoC) + 6 unit tests + proxy refactor (-231 lines net). 40/40 src + e2e green. Final review: 1 important issue fixed (concurrent backend handles). |

## Constraints

- **Mojo:** 0.26.2 (see `~/.claude/projects/-home-donokami-Projets-perso-mojo-tquic/memory/project_mojo_syntax.md` for syntax notes)
- **TLS:** rustls 0.23 via librustls-mojo (Cargo.toml in `crates/librustls-mojo/`)
- **I/O:** boucle from `~/Projets/perso/boucle/` (CompletionLoop / ReadinessLoop)
- **Test runners:**
  - `bash conformance/scripts/run_tests.sh` (31/31)
  - `bash scripts/run_tests.sh` (39/39 src tests)
  - `bash scripts/test_reverse_proxy.sh` (TLS+io_uring e2e via Python backend)

## Milestone state (post-M2)

- **M2 — HTTP/1.1 + reverse proxy:** ✅ shipped, merged to main 2026-04-07
- **M2.5a — Unified HTTP API trait surface (HC-4 unblocker):** ✅ shipped, merged to main as `c93aaf9` and pushed to origin 2026-04-07
- **M2.5b — Helpers (priority, alt_svc, sse) (M6 unblocker):** ✅ shipped, merged to main as `3eb7b47` on 2026-04-09
- **HC-4 — HTTP/2 connection layer:** ✅ done — Phase 0 + HC-4a (connection core) + HC-4b (stream data path) all on main. 31/31 conformance tests. M5.5 unblocked.
- **M5.5 — HTTP/2 client/server + TLS/ALPN:** ✅ done — H2HandlerServer + H2Session + TLS ALPN. 39/39 src tests. 19 commits.
- **librustls Wave 2 — QUIC handshake lifecycle:** pending (blocks M3)
- **M3 — QUIC transport core:** pending
- **M4 — Loss recovery + congestion control:** pending
- **M5 — HTTP/3 + QPACK:** pending
- **M6 — Unified HTTP client:** pending; depends on M5.5 + M5 + M2.5b
- **M2.6 — H2CoroServer (async handlers via ucontext):** ✅ done — 10 commits (`b11b815..18324fa`). H2CoroServer adapter + proxy refactor. Supersedes blocked M2.6 (AsyncBody adapter). 40/40 src + e2e green.

## Open follow-ups (post-M2.5a)

- **HC-4 design pass.** The HC-4a/4b/4c split was sketched before M2.5a's trait surface was concrete. Worth re-walking the spec against the now-shipped types — particularly `StreamHandler.on_request` taking `var body` (cross-callback streaming bodies need either `body.try_detach()` on a `mut` ref or splitting into `on_request_headers` + `on_request_body`), `Session.run_until` taking `Deque[UInt64]`, and `RequestBody` having no trailer slot.
- **Mojo native async re-spike.** Check Mojo changelog for `Waker` / `Executor` / `co.resume` exposure when 0.27 lands. If shipped, could replace ucontext-based coroutines with native ones (drop-in via CoroHandle API).
- **Reverse proxy main.mojo deeper refactor.** The example uses `H1Session` for the backend now (`68973f3`), but the client side still uses `ServerConnection` directly because `H1HandlerServer`'s synchronous `StreamHandler` model can't wait for an async backend response. A full `StreamHandler`-based refactor needs an async backend-response callback in the trait surface — natural HC-4 work.

## Session history

- 2026-04-07 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-tquic/629c84f4-5986-4f20-8a33-508efc270de7.jsonl` — M2.5 brainstorming. Decided HTTP/3-canonical shape, callback-only execution model, γ hybrid body with explicit `detach()`, standalone `H3StreamExtension` trait, compile-time monomorphic Session with M6 composition deferred, owning `RequestHandle`, hyper-matched defaults. Spec written, two rounds of independent review (1 blocking issue from round 1 fixed via `RequestBody` tagged union in round 2). Split into M2.5a + M2.5b. Ready for planning.
- 2026-04-07 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-tquic/7a5fc503-1831-4e4c-8509-d62960d67da7.jsonl` — M2.5a plan written. 22 TDD tasks, decision to add new `H1HandlerServer` / `H1Session` adapters next to existing `ServerConnection` / `ClientConnection` (rather than mutating the wire-format wrappers). DetachedBody push mechanism: typed-pointer via handler ownership, registry approach reserved as fallback. Open Mojo 0.26.2 questions (`def close(deinit self)`, copy ctors on Method/Version/Headers, Response body field) flagged at point-of-use for verification during implementation.
- 2026-04-07 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/d50abffa-5695-40f5-9018-fad00875cf17.jsonl` — M2.5a implemented on branch `m25a-unified-http-api` in worktree `.worktrees/m25a-unified-http-api`. All 22 tasks landed via TDD. 30/30 src tests + 27/27 conformance tests passing. Spec deviations documented in commits: (a) request trailers dropped in H1 parser since RequestBody is bytes-or-stream-only; (b) `Session.run_until` takes `Deque[UInt64]` of handle IDs instead of `List[RequestHandle]` because Mojo 0.26.2 stdlib collections require Copyable elements; (c) `StreamHandler.on_request` takes `var body: RecvBody` instead of `mut body` so handlers can `body^.detach()`; (d) `BodyFrame.error()` returns by value (not by ref) due to Optional-borrow origin issues; (e) `ResponseWriter` uses captured-state pattern with `_take_*` methods instead of the spec's `_send_headers_id: UInt64` registry. Fixes from Phase 1 spec/quality reviewers: SendBody.abort clears queued frames; RecvBody._set_end is idempotent; RecvBody._push drops post-terminal pushes; ResponseWriter._take_informational[_headers] expose 1xx data. Reverse proxy main.mojo refactor deferred — pre-existing boucle.net import errors on main are out of scope; new tests/test_reverse_proxy_refactor.mojo proves the trait surface supports the proxy pattern via MockSession backend. Research spike `research/mojo-async-executor.md` concluded M2.6 (AsyncBody) is blocked-on-Modular: Mojo 0.26.2 has no public waker API for plugging custom executors into the coroutine runtime.
- 2026-04-07 — same session, post-implementation cleanup: investigated the "boucle.net errors blocking the reverse_proxy refactor" follow-up and discovered the diagnosis was wrong — the example builds cleanly with the proper `-I "$HOME/Projets/perso/boucle"` include path, and the M2 e2e suite (`bash scripts/test_reverse_proxy.sh`) passes against the Phase 4 `Request.body → RequestBody` migration. Did a targeted refactor swapping the per-connection `ClientConnection` for `H1Session` (commit `68973f3`, +21 LoC) to validate the new Session trait against TLS+io_uring; client-side `ServerConnection` left in place because `H1HandlerServer`'s synchronous `StreamHandler` doesn't fit a proxy that needs to wait for an async backend response. Merged the m25a-unified-http-api branch onto main as merge commit `c93aaf9` (--no-ff to match project style) and pushed `1467bb0..c93aaf9` to origin/main. Removed the worktree and deleted the local branch. Reconciled `specs/2026-04-07-m25-unified-http-api.md` with inline `# M2.5a:` notes describing all five forced deviations + a "Reading this spec post-M2.5a" preamble so HC-4 readers see them up front.
- 2026-04-07 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/d50abffa-5695-40f5-9018-fad00875cf17.jsonl` — M2.5b plan written: `plans/2026-04-07-m25b-helper-modules.md`. 11 TDD tasks (Priority §7.1: 3 tasks; Alt-Svc §7.2: 4 tasks; SSE §7.3: 3 tasks; acceptance gate: 1 task). Two sketched deviations carried forward from M2.5a discipline: (a) flat `tests/test_*.mojo` layout instead of the §10.3 `tests/http/test_*.mojo` sketch; (b) `try_write_event` is a stateless free function instead of the spec's `EventStreamWriter` struct wrapping an `UnsafePointer[ResponseWriter]` (the spec's sketch contradicted its own "does not take ownership" doc and carried lifetime risk in Mojo 0.26.2). Open questions flagged inline at their call sites for implementation-time verification: `atol` availability, `Dict.pop` signature, string slice syntax, `KeyElement` trait composition for `Origin`, `WHATWG retry` parsing policy.
- 2026-04-07 — M2.5b implemented via subagent-driven-development on branch `m25b-helper-modules` in worktree `.worktrees/m25b-helper-modules`. All 11 tasks landed as 10 TDD commits (`2f1f1e2..486a366`) + 1 post-review fix commit `8f43e38`. Every task went through per-task spec + quality reviews; final full-range review (opus, cross-cutting) flagged an SSE livelock edge case (`is_end()` returning False forever if the body terminated mid-event) which was fixed by discarding the trailing partial-event buffer per WHATWG §9.2 semantics, with a new regression test `test_reader_partial_event_at_end_discarded`. 33/33 src + 27/27 conformance + reverse-proxy e2e all green. Mojo 0.26.2 forced deviations encountered during implementation: (a) `comptime X = N` without `: Int` annotation (matches existing `ALPN_*` pattern); (b) byte-scanning via `.as_bytes()` + `UInt8` constants + `chr(Int(b))` accumulation throughout all parsers because String `[i]` and `[start:end]` are unsupported; (c) `struct Origin(KeyElement)` instead of `(Copyable, Movable, Hashable, EqualityComparable)` — `KeyElement` is the composite Dict-key trait in `std.collections.dict`; `Hashable` lives under `hashlib.hash` and `EqualityComparable` does not exist (only `Equatable`); (d) `AltSvcCache.lookup/clear/clear_expired` marked `raises` because `Dict.__getitem__`/`pop` raise internally; (e) `AltSvcCache.clear` takes `origin: Origin` by borrow (not `var`) to avoid forcing callers to pre-copy; (f) `_split_top_level` takes `sep: UInt8` instead of `sep: String`; (g) `Optional[T]` direct-assign in copy ctors (Mojo 0.26.2 Optional has `.copied()` not `.copy()`, and Optional is `ImplicitlyCopyable`); (h) mid-file imports in `sse.mojo` for `ResponseWriter`/`WriteResult` matching the existing pattern in that file (`DetachedBody` is already imported mid-file). Worktree setup: symlinked `lib/` (librustls_mojo.so) and `conformance/vectors/hpack-stories/` (nested git repo fixtures) from the main repo checkout because worktrees don't inherit untracked files. Ready for merge to main and cleanup.
- 2026-04-09 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/9056decb-c699-4631-911d-55d872232f4b.jsonl` — HC-4 brainstorming + Phase 0 implementation. Brainstorming: researched 5 questions in parallel. Decided Approach A (mut body + try_detach). Spec written + reviewed. Phase 0: 4 commits (`50b890e..f07a0f6`). Per-task + final reviews CLEAN. 34/34 src + 27/27 conformance + e2e green.
- 2026-04-09 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/c5dc73e4-853c-4e68-8229-71315aebd2a9.jsonl` — HC-4a plan written + implemented. 15 TDD commits (`64338e3..9955b95`). H2Connection sans-I/O state machine (~870 LoC): preface, SETTINGS, PING, GOAWAY, stream table, CONTINUATION assembly, connection-level flow control. Oracle: Python h2 4.3.0. Tests: 24 unit + 3 cross-validation. Mojo deviations: Dict[Int, StreamState], make_stream_ended rename, .copy() workarounds.
- 2026-04-10 — same session — HC-4a pushed to origin/main. HC-4b plan written + implemented. 13 TDD tasks + 2 review fixes (`0e7108c..a1ff9d8`). Stream data path: HPACK decode/encode wiring, send_headers with CONTINUATION splitting, client response HEADERS, inbound DATA dispatch with recv window checks, send_data with fragmentation + send window checks, stream-level flow control (auto WINDOW_UPDATE), inbound trailers with END_STREAM validation, RST_STREAM handling (inbound + outbound stream close), SETTINGS INITIAL_WINDOW_SIZE window adjustment. Oracle extensions: h2_roundtrip, h2_stream_data_scenario. Tests: 21 unit + 3 cross-validation. 31/31 conformance + 34/34 src + e2e green. Final cross-cutting review (opus): 2 issues fixed (CONTINUATION trailer half-close transition, inbound DATA flow control check, trailer END_STREAM validation). Re-review: CLEAN.
- 2026-04-10 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/c5dc73e4-853c-4e68-8229-71315aebd2a9.jsonl` — M5.5 brainstorming + planning + implementation. Brainstorming: decided wrap pattern, full scope (server + client + TLS/ALPN), UnsafePointer per-stream state, drain-on-feed, separate ALPN setter FFI. Spec reviewed (opus): 3 blocking + 9 important resolved. Plan: 14 tasks across 5 phases. Implementation: 19 commits (`41b1e1d..90bf233`). H2HandlerServer wraps H2Connection with StreamHandler dispatch (7 tests). H2Session implements Session trait with concurrent handles (7 tests). 3 e2e client↔server tests. TLS ALPN: Rust FFI + Mojo wrappers + 2 negotiation tests. Final cross-cutting review (opus): 3 important issues fixed (missing __del__, streaming body rejection, canonical response parser). 39/39 src + 31/31 conformance + e2e green.
- 2026-04-13 — `~/.claude/projects/-home-donokami-Projets-perso-mojo-net/bafe4277-bf40-4f56-8897-927600684a50.jsonl` — M2.6 full cycle (brainstorm + plan + implement + finish). Reviewed boucle stackful coroutines (ucontext FFI, commit `0877862`) — all tests pass, feedback given and addressed (mprotect raw syscall, __del__ assert, unchecked swapcontext comment, 3 new tests). Decided: new H2CoroServer adapter alongside H2HandlerServer (not modifying existing code), bare CoroBody function (not trait), handler-level coroutines only (I/O layer stays event-driven). Two blocking review issues resolved: (1) boucle.stackful allowed in src/ (control-flow, not I/O); (2) M2.6 label supersedes blocked AsyncBody adapter. Spec written + independently reviewed: 2 blocking + 5 important + 3 minor findings resolved. Spec: `specs/2026-04-13-m26-h2-coro-server.md`. Plan: `plans/2026-04-13-m26-h2-coro-server.md` — 10 tasks across 3 phases. Implementation: 10 commits (`b11b815..18324fa`) on main. H2CoroServer adapter (581 LoC, `src/h2/h2_coro_server.mojo`) + 6 unit tests (615 LoC) + proxy refactor (`examples/h2_reverse_proxy/main.mojo` 1165→1151 lines). Key deviation: `backend_handles: Dict[Int, UInt64]` replaces singular `Optional[RequestHandle]` to support concurrent backend submissions (review-caught bug). Key verification: mut method calls through UnsafePointer dereference work in Mojo 0.26.2. 40/40 src + e2e green. Retrospective: `plans/2026-04-13-m26-h2-coro-server-retrospective.md`.
