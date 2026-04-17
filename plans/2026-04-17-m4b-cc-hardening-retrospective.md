# M4b Retrospective — CC Hardening + Interop (HyStart++, ECN, BLOCKED)

**Date:** 2026-04-17
**Spec:** `specs/2026-04-17-m4b-cc-hardening.md`
**Plan:** `plans/2026-04-17-m4b-cc-hardening.md`
**Commits:** `2a795bc..55ccd86` (12 commits, +1475 / -22 lines across 15 files)
**Tests:** 58/58 src, 33/33 conformance

---

## Built vs. planned

All 10 plan tasks delivered:

- Task 0: `src/quic/cc/minmax.mojo` — Kathleen Nichols 3-sample windowed-min filter
- Task 1: PN threading — `on_packet_sent(size, pn, now)` through cc_trait, dummy, controller, recovery
- Task 2: HyStart++ state machine in `cubic.mojo` — SS/CSS phases, 8-sample RTT, round detection
- Task 3: `_on_congestion_event` on Cubic + CcController dispatch — ECN CE mark path
- Task 4: `src/quic/ecn.mojo` — ECN codepoint + state constants + `EcnCounts` struct
- Task 5: `pn_space.mojo` ECN fields — `SentPacket.ecn_mark`, `recv_ecn`, `last_ack_ecn`, `ect0_in_flight`
- Task 6: ECN wiring in `connection.mojo` — outgoing ECT(0), recv counting, `_process_ecn_feedback`, 3-stage validation
- Task 7: BLOCKED emission in `connection.mojo` — `DATA_BLOCKED` + `STREAM_DATA_BLOCKED` with `blocked_at` dedup + MAX_DATA/MAX_STREAM_DATA reset
- Task 8: HyStart++ unit tests in `test_cc_cubic.mojo` (8 tests) + `test_cc_minmax.mojo` (4 tests)
- Task 9: ECN integration tests (`test_ecn.mojo`, 7 tests) + BLOCKED integration tests in `test_quic_connection.mojo` (4 tests) + `run_tests.sh` registration

**LoC delta:** 1475 prod + test insertions vs. plan estimate of ~1050. The gap is mostly test depth: `test_ecn.mojo` came in at 583 LoC (vs. 150 estimated) because the ECN end-to-end path requires full loopback setup — client sends ECT0, server receives with CE, server ACK carries CE counts, client processes via `_process_ecn_feedback`. Each test scenario exercises the full pipeline.

---

## Deviations and why

### 1. `MinMax` uses named fields `s0/s1/s2` instead of `InlineArray[MinMaxSample, 3]`

Spec used `InlineArray[MinMaxSample, 3]`. Mojo 0.26.2 copy-constructor semantics for `InlineArray` with non-trivially-copyable elements were uncertain. Used explicit named fields `s0: MinMaxSample`, `s1: MinMaxSample`, `s2: MinMaxSample` instead. Functionally identical; the 3-sample algorithm maps directly onto named fields.

### 2. `EcnValidator` not implemented (spec §6.1 referenced a struct that was out of scope)

The spec described `EcnValidator` as a standalone struct with `probe` / `on_ack` / `on_loss` methods. During T6 implementation, the reviewer noted this abstraction was redundant — all state (`ecn_state`, `ecn_probe_pkts_needed`, `ecn_probe_pkts_sent`, `ecn_probe_first_pn`) lived on `QuicConnection` anyway, and the 3-stage transition logic is concentrated in `_process_ecn_feedback`. The struct was collapsed into inline fields + one helper method. No functional difference; removes an indirection layer.

### 3. `_process_ecn_feedback` not gated on `has_ecn` (T9 fix)

Initial T6 implementation only called `_process_ecn_feedback` when `ack.has_ecn == True`. This was wrong: the PROBING → DISABLED transition must fire when an ACK *lacks* ECN counts (peer stripped them — bleaching detected). The guard was removed so `_process_ecn_feedback` is called unconditionally on every ACK that covers ECN-marked packets. During CAPABLE state the function is a no-op when `has_ecn=False`.

### 4. `test_ecn_ce_triggers_congestion` rewrote from direct CC call to full end-to-end (T9 fix)

Initial T9 implementation called `conn.cc.on_congestion_event(...)` directly, bypassing the entire ECN feedback path. The reviewer flagged this as Important — the test was validating a call site that didn't exist on the public API, not the actual mechanism. Rewrote to drive the full path: client ECT0 send → server `recv(ecn_mark=ECN_CE)` → server ACK with CE counts → client `_process_ecn_feedback` → cwnd drops. This is now the canonical ECN CE regression test.

### 5. STREAM_DATA_BLOCKED iterates `stream_map.streams.keys()` instead of `sendable_ids`

Plan suggested iterating `sendable_ids`. FC-blocked streams may be absent from `sendable_ids` (they can't send). Used `stream_map.streams.keys()` snapshot + `fc.available() == 0` check instead, which covers all live streams regardless of sendability state. Added `stream_limit > 0` guard (before any data is sent, `stream_limit` is 0 — no STREAM_DATA_BLOCKED until the peer grants window).

### 6. HyStart++ `_hs_on_loss()` called before suppression guard (T2 fix)

Initial T2 implementation called `_hs_on_loss()` as the first line of `on_packets_lost`. RFC 9406 §4.6 requires CSS state to be exited on loss *but* the cwnd reduction should still be suppressed within the suppression window. The call was moved to after the suppression guard check.

---

## Pain points

- **ECN test depth vs. estimate.** The 150 LoC estimate for `test_ecn.mojo` underestimated the loopback setup cost — each ECN scenario needs a complete handshake + packet exchange before the test condition can be exercised. `test_ecn.mojo` is 583 LoC (4× estimate). Future ECN-adjacent test files should budget 500-700 LoC.
- **`_process_ecn_feedback` has_ecn guard bug.** The conditional on `ack.has_ecn` was subtle — the PROBING → DISABLED transition is specifically triggered by absence of ECN counts. This class of "transition-on-absence" bug is easy to miss in first pass.
- **Worktree setup friction.** Both `.venv` (Python h2 module absent) and `conformance/vectors/hpack-stories` (circular self-symlink) needed repair before conformance tests could run. These worktree setup steps should be documented or automated.

---

## Open questions

### Required-later (must be addressed in a future milestone)

| What | Severity | Trigger |
|---|---|---|
| PN skipping / optimistic-ACK defense | required-later | CVE-2025-4820 class; security-posture MUST. Quinn implementation is reference. Deferred to M4c. |
| FC auto-tuning | required-later | High-BDP throughput profiling. Deferred to M4c. |
| SendBuf bare-FIN bug | required-later | `on_ack(ack_len=0)` returns early before `fin_acked` check. Stream completion stalls under FIN-only STREAM frames. Fix in M4c. |
| QUIC_STREAMS_BLOCKED frames (RFC 9000 §4.6) | required-later | Interop with peers that respect stream concurrency limits. Distinct from DATA_BLOCKED / STREAM_DATA_BLOCKED. |
| Delivery-rate estimator | required-later | BBR milestone infrastructure. No M4b consumer; deferred with M4b non-goals. |

### Optional (no timeline commitment)

- MinMax reuse for delivery-rate estimator (BBR milestone — same struct, different measurement)
- ECN CE marks in PMTUD probes (PMTUD milestone)
- ECT(1) support (no practical use today; ECT(0) is the universal deployment codepoint)

---

## Next spec recommendations (M4c)

1. **PN skipping first** — security MUST, well-defined spec, quinn is the reference (TQUIC has the CVE-2025-4820 gap per research/quic-cve-pattern-analysis.md). Contained and isolated change.
2. **SendBuf bare-FIN fix** — small, self-contained, unblocks stream-lifecycle correctness. Move `fin_offset` check before the `ack_len==0` early-return in `stream.mojo:518`.
3. **FC auto-tuning** — larger investment but straightforward: replace static 50%/10 MiB thresholds with BDP-driven window growth. Requires RTT estimate from CC layer (available via `smoothed_rtt` in recovery).
4. **Consider `_process_ecn_feedback` + ECN state machine extraction** — `connection.mojo` is ~2600 LoC post-M4b. The ECN logic (~80 LoC) plus BLOCKED emission (~60 LoC) are natural extraction candidates for a `connection_recv_ext.mojo` helper. Not urgent, but reduces per-file surface before M5.
