# M3c QUIC Data Path Retrospective

**Date:** 2026-04-14
**Spec:** `specs/2026-04-14-m3c-quic-data-path.md`
**Plan:** `plans/2026-04-14-m3c-quic-data-path.md`
**Commits:** `b701388..HEAD` (13 commits)

---

## Built vs. Planned

### What was built

All 7 planned tasks completed, producing:

| Task | Deliverable |
|------|-------------|
| 1 | `src/quic/flow_control.mojo` (~150 LoC) + `tests/test_quic_flow_control.mojo` (10 tests) |
| 2 | `src/quic/cid.mojo` (~400 LoC) + `tests/test_quic_cid.mojo` (12 tests) |
| 3 | `src/quic/stream.mojo` (~760 LoC) — state enums, RecvBuf, SendBuf, Stream struct + `tests/test_quic_stream.mojo` (29 tests) |
| 4 | `src/quic/stream_map.mojo` (~380 LoC) + `tests/test_quic_stream_map.mojo` (14 tests) |
| 5 | `src/quic/connection.mojo` (+ ~400 LoC) — StreamMap/CidManager wiring, frame dispatch, _handle_stream_frame/_handle_reset_stream/_handle_stop_sending, QuicEvent extensions |
| 6 | `src/quic/connection.mojo` (+ ~500 LoC) — SentStreamFrame + app_frames_sent tracking, _build_app_frames, _on_app_pkt_acked/lost, public API (open_stream, send_stream_data, recv_stream_data, reset_stream, stop_sending) |
| 7 | `tests/test_quic_connection.mojo` (+498 LoC) — 6 integration tests + `scripts/run_tests.sh` updates |

### Files changed/created

- Created: 4 production files in `src/quic/` (~1690 LoC)
- Created: 4 unit-test files (~1250 LoC)
- Modified: `src/quic/connection.mojo` (+900 LoC for M3c wiring)
- Modified: `tests/test_quic_connection.mojo` (+498 LoC, 6 new integration tests)
- Modified: `scripts/run_tests.sh` (+3 entries — test_quic_flow_control, test_quic_stream, test_quic_stream_map; test_quic_cid added during Task 6 fix round)

### LoC vs. estimate

Spec estimated ~2300 production + ~1800 test = ~4100 total. Actual: ~2590 production + ~1750 test = ~4340 total. Production exceeded estimate mainly because connection.mojo's modifications (~900 LoC) exceeded the planned ~450 — the SentStreamFrame tracking mechanism and the full CID advertised/retire-queue state machine required more glue code than anticipated.

### Test counts

- 53/53 src tests passing (up from 49 in M3b — added 4 new test files + 6 new integration tests)
- 33/33 conformance tests passing (no regressions)

---

## Deviations from Plan

### 1. STOP_SENDING states collapsed from 8 to 7 recv states

**What:** The spec review process during brainstorming collapsed the neqo-extended `STOP_SENDING_SENT` + `WAIT_FOR_RESET` two-state pattern into a single `STOP_SENDING_SENT` state for M3c.

**Why:** Both states retransmit identically in a sans-I/O model — the distinction only matters if the application needs to cancel the cancellation, which M3c doesn't support.

**Impact:** Simpler state machine. If an application needs that use case later, adding back `WAIT_FOR_RESET` is mechanical.

### 2. `_apply_m3c_defaults` helper in connection.mojo factories

**What:** The spec §2.7 defaults (10 MiB conn, 1 MiB per-stream, 100 streams) are applied via a helper function that only sets fields if they're zero, not unconditionally.

**Why:** Allows tests and advanced users to override any subset while ensuring defaults for fields they don't explicitly set.

**Impact:** Makes `_apply_m3c_defaults` slightly beyond strict M3c wiring (silent param mutation), but provides ergonomic defaults.

### 3. `advertised: Bool` field added to CidEntry during Task 2 review fix

**What:** The spec said `on_retire_connection_id` triggers replacement issuance if active count drops. The first implementation had no way to know which CIDs needed advertisement. The fix added `advertised: Bool` to CidEntry + `pending_new_cid_entries()` + `mark_advertised()` + `clear_advertised()`.

**Why:** The connection layer needs to know which CIDs to put in NEW_CONNECTION_ID frames. Without this field, we'd either re-advertise all CIDs every send or lose track.

**Impact:** Extra field + 3 methods beyond strict spec, but necessary plumbing. Also used for loss recovery (clear_advertised enables re-advertisement on packet loss).

### 4. Connection.mojo grew 900 LoC (planned ~450)

**What:** Task 5 (+384) + Task 6 (+498) + fix rounds (+18) = ~900 LoC delta on connection.mojo. Spec estimated ~450.

**Why:** The `SentStreamFrame` tracking system (for per-kind ACK/loss handling) required a separate Dict + records list + 9-case switch in both `_on_app_pkt_acked` and `_on_app_pkt_lost`. Each public API method also involved ~30 LoC of state validation + copy-back-into-Dict boilerplate due to Mojo's ownership model.

**Impact:** connection.mojo is now ~2300 LoC. The M3b retrospective's suggestion to split it into sub-tasks paid off — Tasks 5 and 6 each touched connection.mojo independently with intermediate reviews.

### 5. Round-robin scheduling fixed post-review

**What:** Initial implementation of `_build_app_frames` iterated `sendable_ids` from index 0 on every call. Review flagged that `StreamMap.send_index` was declared but never used — low-ID streams always won.

**Why:** The original task description didn't emphasize rotation enough. The fix uses `send_index % n` for start offset and advances send_index by 1 each call.

**Impact:** One-commit fix. Fairness across datagram builds.

### 6. `pending_retire_frames` drain semantics documented but not refactored

**What:** Review flagged that `pending_retire_frames()` drains the queue at build time, before the packet is committed. If build fails between drain and `on_packet_sent`, retirements are lost.

**Why:** Current code has no `raise` between the drain and commit, so the invariant holds. Refactoring to peek+remove-after-ACK would be cleaner but adds complexity. Documented the invariant instead.

**Impact:** Fragile coupling, but correct under all current code paths. Recorded as open follow-up for future hardening.

---

## Pain Points

### Blocking spec bugs found pre-planning

Independent spec review (opus) caught 2 blocking + 11 important + 7 minor issues BEFORE planning started. The most significant:

- **B1 (blocking):** FlowControl had single `consumed` field that conflated "bytes received on wire" (for enforcement) with "bytes consumed by app" (for window updates). Split into `received` + `consumed` two-counter design.
- **B2 (blocking):** `fin_offset` ownership was ambiguous between RecvBuf and Stream. Decided: lives on Stream (RESET_STREAM bypasses RecvBuf).
- **I5 (important):** SendBuf had no ACKed range tracking, so retransmit after loss could re-send already-ACKed bytes. Added `acked_offset` + buffer trimming.
- **I6 (important):** MAX_STREAMS formula was exponential (`new_limit = current + peer_completed`). Fixed to linear (`new_limit = peer_completed + initial_max_streams`).

**Lesson:** The spec review process caught real correctness bugs that would have surfaced as deadlocks, data loss, or protocol violations during implementation. The time spent on review paid off multiple times over.

### Critical bug introduced by a fix

The Task 3 `is_complete` fix used `total_received` counter — but `_count_new_bytes` didn't guard against `read_offset`, so retransmits of already-read data inflated the counter and caused `is_complete` to return True before all data arrived. The re-review caught this and the second fix added `read_offset` clamping to `_count_new_bytes`, `_insert`, and `_would_create_gap`.

**Lesson:** Every fix needs its own review pass. Introducing new invariants (like `total_received`) requires auditing all call sites that affect them.

### Connection.mojo is now 2300 LoC

Even with the M3b split recommendation, connection.mojo grew significantly. The per-frame-kind ACK/loss handling + public API methods + frame generation all pile into one file. A future refactor could extract `_build_app_frames` + `_on_app_pkt_acked/lost` into a separate `stream_path.mojo` module.

### Mojo ownership boilerplate

Every public API method follows this pattern:
```
1. get_stream(key) → copy
2. extract Optional fields: fc.value().copy()
3. mutate copy
4. move back: stream.fc_send = fc^
5. set_stream(key, stream^)
```

This is ~10-15 lines of boilerplate per operation. A future Mojo language improvement (ref-based Dict access) would significantly reduce this.

### Subagent rate limits

Two subagent dispatches hit rate limits mid-work (final reviewer + Task 7 implementer). The Task 7 agent had actually completed all the work before hitting the limit — I just needed to commit the changes. This reinforced that subagent output should be written to disk frequently so context is preserved.

---

## Open Questions

All recorded in `docs/project-context.md` "Open follow-ups":

- **BLOCKED frame emission** — Severity: optional. Trigger: interop testing with peers that observe missing BLOCKED frames. The `FlowControl.blocked_at` field exists but no generation path.

- **Integration test coverage gaps** — Severity: required-later. Trigger: before M4 relies on untested behaviors. Specifically: FC limit-violation error paths (FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR), MAX_STREAM_DATA/MAX_DATA flow cycle, linear MAX_STREAMS growth via wire, CID retire→reissue exchange, loss+retransmit of M3c frame types.

- **Pre-commit mutation vs packet-build failure** — Severity: optional. Trigger: AEAD encryption failure post-handshake. `_build_frames_for_space` drains state before packet commit — if AEAD raises, that state is lost.

- **Spurious STREAM_READABLE events** — Severity: optional. Trigger: performance profiling. Each STREAM frame touching the readable region fires STREAM_READABLE even when the app hasn't consumed anything.

- **app_frames_sent cleanup on close** — Severity: optional. Trigger: memory growth under rapid connection churn. Entries for packets neither ACKed nor detected-lost linger.

---

## Next Spec Recommendations

1. **M4 — Congestion Control + Flow Control Auto-Tuning.** The natural next milestone. M3c ships with a dummy congestion controller (bytes_in_flight tracking only) and static flow control windows. M4 implements CUBIC or BBR + RTT-based window auto-tuning. The dual-counter FlowControl design in M3c is ready for this — just wire RTT into a `window` field that grows with bandwidth-delay product.

2. **Integration test expansion before M4.** The 6 M3c integration tests cover happy paths. Before M4 adds more complexity (congestion state transitions, auto-tuning bugs), expand coverage to: FC limit violations, retransmit/recovery for all M3c frame types, MAX_* flow cycles. Would land as a single ~300 LoC test addition.

3. **Consider extracting stream_path.mojo from connection.mojo.** M3b's retrospective recommended splitting orchestrator tasks — this paid off for M3c's Tasks 5 and 6. But connection.mojo is now 2300 LoC. Extracting `_build_app_frames` + `_on_app_pkt_acked/lost` + SentStreamFrame into `src/quic/stream_path.mojo` would make M4's congestion integration cleaner.

4. **Mojo ref-based Dict access.** A persistent pain point. If Mojo's stdlib gains ref-based Dict access before M4, the public API implementations can be rewritten to avoid the copy-mutate-set-stream dance.

5. **BLOCKED frame emission in M4 or a hardening milestone.** Minor work (~50 LoC) but improves interop. Could be folded into M4's flow-control-aware congestion work.
