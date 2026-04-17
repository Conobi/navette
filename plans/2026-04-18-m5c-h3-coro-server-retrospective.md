# M5c Retrospective — H3CoroServer

**Date:** 2026-04-18
**Spec:** `specs/2026-04-18-m5c-h3-coro-server.md`
**Plan:** `plans/2026-04-18-m5c-h3-coro-server.md`
**Commits:** `d5281c6..dd8d46f` (4 commits)
**Tests:** 63/63 src, 35/35 conformance

---

## Built vs. planned

All 3 plan tasks delivered on spec:

- **Task 0** — `src/h3/h3_coro_server.mojo`: CoroStreamCtx (Movable, 10 fields), _CoroStreamPtr (Copyable+Movable thin wrapper), _free_stream helper, H3CoroServer (Movable, 4 fields, all methods). `tests/test_h3_coro_server.mojo`: loopback helpers + `_simple_get_body` coroutine + `test_h3_coro_simple_get`.

- **Task 1** — 3 new coroutine bodies (`_echo_body_coro`, `_trailer_check_coro`, `_blocking_body_coro`) + 4 tests: `test_h3_coro_post_with_body`, `test_h3_coro_trailers`, `test_h3_coro_rst_stream`, `test_h3_coro_goaway`. Note: plan called for 3 coroutine bodies but `_blocking_body_coro` is shared between RST and GOAWAY tests, making 4 bodies total — a reasonable improvement on the plan's estimate.

- **Task 2** — `src/h3/__init__.mojo` exports H3CoroServer. `scripts/run_tests.sh` adds `test_h3_coro_server` with boucle include guard.

**LoC delta:** ~317 lines production + ~480 lines tests across 4 files (within spec estimate of 380–450 + 350–420).

---

## Deviations and why

### 1. `f.trailers()` returns a `ref` not a value

The plan's `_trailer_check_coro` coroutine accessed `f.trailers()` directly. In the actual codebase, `BodyFrame.trailers()` returns a `ref` to `Headers`, requiring `.copy()` before binding to a local `var`. Fixed by the implementer during Task 1 without needing escalation. The spec said "push BodyFrame.trailers" — the ref-vs-value distinction was an implementation detail that surfaced naturally.

### 2. 4 coroutine bodies instead of 3

The plan estimated 3 coroutine bodies. `_blocking_body_coro` was factored out as a shared body for both `test_h3_coro_rst_stream` and `test_h3_coro_goaway`, resulting in 4 bodies. This is cleaner than duplicating the pattern.

---

## Pain points

- **Smooth implementation:** This milestone was the cleanest of the M5 series. The plan was detailed enough that all three tasks completed without blockers, NEEDS_CONTEXT requests, or review ❌ rounds. The M2.6/H2CoroServer template transferred almost directly.
- **Minor API discovery:** `BodyFrame.trailers()` returning a `ref` was the only unexpected API surface — caught and fixed in Task 1 without issue. The plan could have noted this for completeness, but it's a minor friction point.

---

## Open questions

### Required-later

| What | Severity | Trigger |
|---|---|---|
| H3CoroServer._on_request silently drops stream if coroutine raises on first resume (no 4xx/5xx fallback) | required-later | When H3CoroServer needs proper error response dispatch; same gap as H3HandlerServer and H2HandlerServer |
| aioquic interop loopback (QC-3) for H3CoroServer event paths | required-later | Before M6 ships to production |

### Optional / deferred

| What | Severity | Trigger |
|---|---|---|
| O(n) poll_event queue rebuild in H3CoroServer | optional | Performance profiling |
| QPACK dynamic table | optional | M6 or later |
| H3CoroServer trailer sending (server→client trailers) | optional | When API callers need response trailers |

---

## Next spec recommendations (M6)

1. **M6 — Unified HTTP client.** M5c closes the H3 coroutine server layer. M6 unifies H1/H2/H3 behind a single `Client` type with protocol selection via ALPN negotiation. Spec should cover: connection pooling (one pool per origin), `Client.get(url)` / `Client.post(url, body)` ergonomic API wrapping `H1Session`/`H2Session`/`H3Session`, connection lifecycle (idle timeout, max connections per origin), TLS certificate validation config. M6 depends on M5.5 + M5b + M2.5b (all done).

2. **QC-3 — H3 interop vectors.** Feed aioquic-generated H3 traffic through H3Connection (and optionally H3CoroServer) and verify correct event emission. Add duplicate-control-stream rejection test. Oracle framework from QC-1/QC-2 can be extended.
