# M4a Retrospective — QUIC Congestion Control Core

**Date:** 2026-04-17
**Spec:** `specs/2026-04-15-m4a-quic-cc-core.md`
**Plan:** `plans/2026-04-15-m4a-quic-cc-core.md`
**Commits:** `b5b0cde..d9bbdcf` (15 commits, +1722 / -18 lines across 17 files)
**Tests:** 56/56 src, 33/33 conformance

---

## Built vs. planned

All 11 plan tasks delivered:
- Task 0: Mojo-API spikes (UInt128, nested-Copyable, UINT64_UNLIMITED)
- Task 1: `cc/cc_trait.mojo` — shared types + constants
- Task 2: `cc/pacing.mojo` — TQUIC-style token-bucket pacer
- Task 3: `cc/dummy.mojo` — no-op CC for tests
- Task 4: `cc/cubic.mojo` — RFC 9438 CUBIC + Newton's cube root + integer math
- Task 5: `cc/controller.mojo` — tag-discriminated CcController
- Task 6: `pn_space.mojo` — `last_ae_acked_time_sent` tracker
- Task 7: `recovery.mojo` — CC + pacer integration
- Task 8: `connection.mojo` — `_anti_amp_ok` extraction, `_can_send` helper
- Task 9: `connection.mojo` — ACK flow rewire + persistent-congestion detection
- Task 10: `connection.mojo` — `timeout(now)` + pacer deadline + send-site token commit
- Task 11: final integration test + test-runner registration

Prerequisite M3c-cov plan (5 tasks, ~300 LoC new integration tests) landed before M4a as intended.

**LoC delta:** 1722 prod + test insertions vs. plan estimate of ~2590. The gap is mostly optimistic plan estimates for integration test depth (actual test LoC came in leaner) and connection.mojo modelling fewer interaction paths than anticipated.

---

## Deviations and why

### 1. `cc_trait.mojo` filename (planned: `trait.mojo`)
`trait` is a reserved keyword in Mojo 0.26.2 — importing `src.quic.cc.trait` causes a parse error at import time. Renamed to `cc_trait.mojo`; all imports updated. Caught in Task 0 spike.

### 2. Pacer split: `next_send_time` (pure) vs. `refill_and_check` (mutating)
Plan originally had a single `check(rate, now)` method. Split required because `timeout()` is non-mutating (`self`, not `mut self`) and needs to query the pacer deadline without committing tokens. This was anticipated in the spec §8.3 ("pure variant") but the plan tasks didn't call out the split explicitly — caught during Task 2 implementation.

### 3. `(ImplicitlyCopyable, Movable)` instead of `(Copyable, Movable)`
Mojo 0.26.2 requires `ImplicitlyCopyable` for structs that need implicit copy (`var o2 = o`). Using `Copyable` alone causes a compile error. Caught in Task 0 spike and applied consistently.

### 4. Persistent-congestion spec evolved through 3 review rounds
- Round 1: `max_ack_delay` was gated on Data space only → corrected to unconditional (RFC 9002 §7.6.2).
- Round 2: 64-entry ring buffer for acked-range tracking → replaced with single-UInt64 `last_ae_acked_time_sent` conservative tracker (ring buffer is undersized for seconds-scale congestion periods at high packet rates).
- Round 3: `_anti_amp_ok` used `self.is_client` (doesn't exist) → `not self.is_server`; dropped `_addr_validated()` guard in original draft.

### 5. `CC_KIND_CUBIC=0 / CC_KIND_DUMMY=1` swap (post-final-review fix)
Final cross-cutting review found the constants were inverted vs. spec (code had DUMMY=0, CUBIC=1). All dispatch used named constants so there was no runtime bug, but the contract was wrong. Fixed in `d9bbdcf`.

### 6. `_can_send` not wired into send path (post-T10-review fix)
Task 10 correctly defined `_can_send` and added it to `timeout()`, but the actual `send()` datagram-build loop only checked `_anti_amp_ok` per-space. The CC window and pacer gate were bypassed. Fixed in `47167f4` by adding `_can_send(1200, now)` before the datagram loop.

---

## Pain points

- **Three spec revision rounds before planning.** The persistent-congestion section was the most fragile — RFC 9002 §7.6.2 is terse and the ring-buffer design from the first pass was undersized by a factor of ~10. The single-UInt64 conservative tracker is simpler and correct.
- **Rate-limit interruption (Task 9 reviewer).** The first reviewer dispatch hit the API rate limit, requiring a re-dispatch next session. No work was lost, but it broke the task cadence.
- **Connection.mojo surface area.** The file is large (~2400+ LoC at end of M4a). Tasks 8, 9, 10 all touched it sequentially and couldn't be parallelized. Suggests M4b should extract sub-responsibilities (e.g., send path) if further modifications are needed.

---

## Open questions

### Required-later (must be addressed in a future milestone)

| What | Severity | Trigger |
|---|---|---|
| HyStart++ | required-later | Loss-induced slow-start exit over-commits >2× in practice (M4b) |
| Delivery-rate estimator | required-later | M4b needs for BBR + app-limited CC |
| MinMax helper | required-later | HyStart++ baseline (M4b) |
| ECN outgoing + incoming validation | required-later | Interop with ECN-marking middleboxes (M4b) |
| BLOCKED frame emission | required-later | Interop test failures (M4b) |
| PN skipping / optimistic-ACK defense | required-later | CVE-2025-4820 class; security-posture MUST (M4b) |
| FC auto-tuning | required-later | High-BDP throughput profiling (M4b) |
| SendBuf bare-FIN bug | required-later | `on_ack(ack_len=0)` returns early before `fin_acked` check (M4b or standalone fix) |

### Optional (no timeline commitment)

- `on_mtu_update` wiring (PMTUD milestone)
- Connection-wide `send_window` cap (memory-pressure testing)

---

## Next spec recommendations (M4b)

1. Start with PN skipping — it's a security MUST and has a well-defined spec. The quinn implementation is the reference (TQUIC has a gap per CVE-2025-4820 analysis).
2. HyStart++ before delivery-rate — it layers on existing slow-start logic cleanly; delivery-rate is a bigger data-structure investment.
3. BLOCKED frame emission is small and self-contained — good warm-up task.
4. Address the SendBuf bare-FIN bug early in M4b to avoid latent test failures when stream-close paths are exercised more heavily.
5. Consider extracting the send path (`send()` + helpers) from `connection.mojo` into a `connection_send.mojo` helper module before adding more CC observability code — reduces the surface per file and makes parallel tasks possible again.
