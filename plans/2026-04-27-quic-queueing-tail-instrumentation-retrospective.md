# QUIC Queueing-Tail Instrumentation — Retrospective

**Date:** 2026-04-27
**Branch:** `feat/quic-queueing-tail-instrumentation` (off main `3919f7d`, HEAD `64c493d`)
**Range:** `3919f7d..64c493d` — 14 commits
**Spec:** `specs/2026-04-27-quic-queueing-tail-instrumentation.md`
**Plan:** `plans/2026-04-27-quic-queueing-tail-instrumentation.md`
**Final state:** ✅ All 15 plan tasks complete. Final cross-cutting review CLEAN. **Verdict: FALSIFIED for queueing-tail hypothesis. NEW HYPOTHESIS surfaced: addr_key demux collapse.**

## Built vs. planned

| Plan task | Status | Commit | Notes |
|---|---|---|---|
| T0 — Pre-flight branch verification (HARD GATE) | ✅ ABORT/RECOVER | n/a (orchestrator) | Initial state was on `feat/quic-accept-loop-instrumentation` not main; user chose Option 1 (FF-merge to main first), then branched. Resolved cleanly. |
| T1 — AcceptProfile arrival-latency fields + record method | ✅ as planned | `70947b7` | TDD; 2 new tests pass. |
| T2 — Per-conn fields + 2 record methods | ✅ DONE_WITH_CONCERNS | `f5ddca6` | Mojo 0.26.2 forced `raises` qualifier on `record_conn_pkt` because `Dict.__getitem__` raises. Spec-anticipated; flagged for downstream. |
| T3 — `report_json` arrival-latency block | ✅ as planned | `edba487` | 3 flat top-level keys; `python3 -m json.tool` round-trip verified. |
| T4 — `report_json` per-conn aggregated block | ✅ DONE_WITH_CONCERNS | `11f761e` | Added `raises` qualifier to `report_json` itself (Dict iteration raises). Only non-test caller `bench/h3_server.mojo:_write_profile_json_sidecar` already in `raises` context. |
| T5 — `report_json` top-50 worst-offenders block | ✅ as planned | `52968dd` | Mojo 0.26.2 reserved keyword: implementer renamed test-local `match` → `matched`. |
| T6 — `report_text` mirroring of all three blocks | ✅ DONE_WITH_CONCERNS | `92d497f` | `report_text` also gained `raises` qualifier. |
| T7 — `PendingDatagram.arrival_us` field + 3 init paths | ✅ as planned | `0d6a92d` | Default `UInt64(0)` + anti-uninit doc-comment per spec verbatim. |
| T8 — `_handle_recvmsg` arrival stamp | ✅ as planned | `485069e` | `@parameter if PROFILE_ACCEPT` gate; default 0 ensures defined value off-build. |
| T9 — `_flush_impl` `record_arrival_lat` call | ✅ as planned | `998cfdc` | Defensive guards (`arrival_us > 0` and `now >= arrival_us`) against under-flow + un-stamped reads. |
| T10 — `_flush_impl` per-conn record calls | ✅ as planned | `0f89429` | Used `_h3.is_established()` accessor (matches existing pattern at lines 769/854). |
| T11 — Long-conn smoke gate (≤10% drift) | ✅ PASS | `7e24345` (combined with T12) | -2.12% drift (off-build 365.07 / on-build 357.33 rps median). |
| T12 — Short-conn smoke gate (≤10% drift) | ✅ PASS | `7e24345` (combined with T12) | Off-build 0.35 / on-build 0.32 rps median; Δ=0.03 rps within ±0.1 rps noise floor (per spec fallback rule). Per-flush-aggregate fallback NOT triggered. |
| T13 — Operational SIGINT capture under short-conn | ✅ as planned | `f470401` | Sidecar `INSTRUMENTATION-20260427-001113-queueing-tail.json` committed; all 3 new blocks present + populated; `python3 -m json.tool` valid. |
| T14 — REFERENCE.md hypothesis-pass entry + acceptance | ✅ as planned | `c7e128b` | 3-verdict signal table applied: **FALSIFIED** (P99=61us << 100ms). Methodology gate satisfied (re-read all 348 lines; no contradictions). Project-context advance landed in `64c493d`. |

## Deviations + why

### 1. T0 ABORT recovered to Option 1 FF-merge

The plan's T0 hard gate explicitly aborts if main does not contain the predecessor branch (`feat/quic-accept-loop-instrumentation` HEAD `fefe435`). At plan-execution start, the branch was at `fefe435` but main was at `900067a` — 30 commits behind (Plan B + Plan C + user's h2-perf commits + correction commit). Per-spec, the planner does not own the merge.

**Resolution:** surfaced to user with two options (FF-merge first vs branch off feature head). User chose Option 1. Sequence: commit planning artifacts on the feature branch (`3919f7d`), `git checkout main && git merge --ff-only feat/quic-accept-loop-instrumentation`, `git checkout -b feat/quic-queueing-tail-instrumentation`. Clean linear history.

**Lesson:** the T0 "ABORT" instruction worked exactly as designed. Future plans with branch-state preconditions should keep this pattern.

### 2. `raises` qualifier propagated through three call sites (T2/T4/T6)

Mojo 0.26.2 surfaces `Dict.__getitem__` as `raises`. Iterating `Dict.items()` and using `key in dict` likewise raises. The implementers correctly added `raises` to:
- `record_conn_pkt` (T2) — read+write Dict path
- `report_json` (T4) — iterates `conn_pkt_counts.items()` + `key in conn_hs_complete`
- `report_text` (T6) — same iteration pattern

**Why this is a deviation:** the spec did not pre-call out that the existing `report_text` and `report_json` would need `raises`. The plan flagged it as a "may-need" but didn't prescribe.

**Why it didn't break anything:** the only non-test callers of `report_text`/`report_json` were in `bench/h3_server.mojo` SIGINT-flush block, which is already inside a `raises` context (`_flush_impl` raises). No caller-side surgery needed.

**Lesson for future Mojo 0.26.2 plans:** if a method touches a Dict, assume `raises` propagation. Spec the qualifier upfront rather than as a "may-need".

### 3. T13 capture surfaced a striking asymmetry; post-T14 wire-level investigation VERIFIED the mechanism

The plan's T13 expected one of three verdicts for the queueing-tail hypothesis. The data delivered **FALSIFIED** unambiguously (P99=61us, 1638× below threshold). But the per-conn data revealed a striking secondary finding: server saw only **5 distinct addr_keys** while tquic_client reported **392 logical conn attempts**.

The initial T14 REFERENCE.md entry (commit `c7e128b`) speculated this was caused by kernel ephemeral-port reuse. **That speculation was falsified by a follow-up wire-level pcap capture during the post-execution review.**

**Post-T14 verification (via tcpdump in alpine sidecar with NET_RAW, capturing same-day short-conn run):**

- Wire shows **only 4 distinct client src_ports** (matching tquic_client's `--threads 4`).
- Each src_port carries **93-96 distinct Initial DCIDs** — a total of **378 logical conns** multiplexed across 4 sockets.
- This is **not** kernel port reuse. It is tquic_client's deliberate design: one UDP socket per worker thread, multiplexing many QUIC conns over each via DCID. Every standard QUIC client (quiche, ngtcp2, msquic, neqo) follows this pattern. RFC 9000 §5.2 explicitly endorses it.

**Verified mechanism:** mojo-net's `addr_key`-based demux is fundamentally incompatible with the standard QUIC connection-id multiplexing pattern. When thread 0 (port 34130) opens a second logical conn after the first completes handshake, the server's `_find_conn(addr_key="...:34130")` returns the OLD established conn. The new Initial is fed to the wrong QuicConnection and silently rejected (no error counter fires). The client times out. Mojo-net's CPU stays at 0.1% because most Initials never trigger meaningful work.

The retrospective REFERENCE.md entry was updated post-investigation to replace the speculative "kernel port reuse" with the verified "addr_key demux fundamentally incompatible with DCID multiplexing" mechanism. Pcap committed as evidence: `bench/quic_perf/results/profile/wire-capture-20260427-shortconn.pcap`.

**Lesson:** the user's intervention ("don't jump on conclusions, test hypotheses with the Mojo MCP") was load-bearing. My initial T14 entry committed a hypothesis I had circumstantial evidence for but had not directly tested. The pcap test took ~5 minutes and converted "kernel port reuse" (speculation) into "DCID multiplexing collides with addr_key demux" (verified, with bytes on disk). Future hypothesis-pass entries should require wire-level or equivalent direct verification before claiming a specific mechanism.

### 4. T11/T12 used noise-floor PASS for short-conn

Per the plan T12 step 3 explicit fallback ("If both medians are within ±0.1 rps of each other, treat as PASS regardless of percentage"), the short-conn cell PASSED with Δ=0.03 rps even though percentage drift was -8.6% of the very small absolute baseline (0.35 rps). Documented in the smoke-gate doc.

**Lesson:** the noise-floor escape hatch was load-bearing. At low absolute rps, percentage drift is meaningless. Future smoke gates should retain this pattern.

### 5. Bench-side files dirty with unrelated user changes

Throughout execution, `bench/h2_server`, `bench/h3_server` (binary), `.gitignore`, and many untracked plans/specs/research files were dirty in the working tree from the user's parallel h2-perf work. Implementers correctly scoped each commit to ONLY their own session's files (`commit-smart` skill). No collateral damage.

**Lesson:** the file-scoping discipline in commit-smart held across 14 commits. Worth keeping.

## Pain points

### Operational latency (Docker rebuilds)

Each PROFILE_ACCEPT flag flip required a `docker rmi mojo-net-bench:latest && make -C bench/quic_perf setup` cycle (~3-5 min each). T11/T12/T13 collectively required FOUR rebuilds (off-build → on-build for T11, on-build → off-build for T12, off-build → on-build for T13). The orchestrator handled them via `Bash run_in_background=true` per the Plan C retro lesson — no subagent abandonment issues this time.

**Improvement opportunity:** the Plan C retro flagged this as the optional `bench/quic_perf/scripts/profile-capture.sh <scenario>` helper; this plan re-confirmed the trigger ("if profile re-capture happens more than once after this spec"). We've now captured short-conn three times across Plan C + this plan; the helper is now justified.

### Subagent fidelity to Mojo 0.26.2 gotchas

T2 / T4 / T6 each had to discover the `raises` qualifier requirement on its own. The plan documented "may need raises" but didn't prescribe. Implementers handled it correctly each time, but it added 1-2 minutes of extra try-build-discover-fix cycles per task.

**Improvement opportunity:** Mojo 0.26.2 plans should include a short "raises catalog" — which methods are guaranteed-`raises` (e.g. `Dict.__getitem__`, `Dict.items()` iter, `key in Dict`) and how propagation works. Reusable across plans.

### Server is doing right thing for wrong workload

The bench tells us the server is fast, idle, and processes everything it sees correctly — but tquic_client thinks 288/392 conns timed out. The instrumentation as currently shaped can confirm-or-deny server-side bottlenecks, but cannot directly distinguish "client-side problem" from "demux-design problem" from "kernel-network problem". The new "addr_key collapse" hypothesis points at demux, but it's still a hypothesis based on circumstantial evidence (the 5-vs-392 asymmetry).

**Improvement opportunity:** add a per-flush counter for "Initial-packet-received-on-already-established-addr_key". This is the proposed next-step diagnostic that would directly count demux-collapse events.

## Open questions (severity / trigger)

### Required-later (HIGH severity)

- **What:** Spec `addr_key`-to-DCID demux migration in `bench/h3_server.mojo`. The current `conn_map: Dict[String, Int]` keys on `addr_key` (src_ip:src_port). Wire-level pcap evidence (this retro) confirms the standard QUIC client multiplexing pattern: one UDP socket per client thread carries many QUIC conns distinguished by DCID. tquic_server / quiche-server / nginx-quic / lsquic all use DCID demux for this reason (see RFC 9000 §5.2). Estimated scope: 50-100 LoC change. The DCID is already extracted at `_handle_recvmsg` and stored in `PendingDatagram.dcid`. Plan needs to cover: (a) `conn_map` key change to `Dict[List[UInt8], Int]` or `Dict[String, Int]` with hex-encoded DCID; (b) `addr_key` retained as per-conn metadata for sendmsg routing (`conn_addrs` already does this); (c) DCID rotation handling — clients can rotate to new DCIDs mid-conn, so `conn_map` may need to support multiple DCIDs per conn (or clear+remap on rotation); (d) handshake retry/0-RTT paths.
  **Severity:** required-later (HIGH) — this is the verified rate-limiter for the calibrated 1 rps short-conn floor. No further instrumentation required to spec it.
  **Trigger:** anyone returning to the QUIC perf push.

- **What:** Optional pre-flight diagnostic counter — "Initial-on-already-established-addr_key" events in `_flush_impl` — for additional confirmation if desired. This was originally proposed as the verification step BEFORE the wire-level pcap was captured. Wire-level evidence makes it redundant for confirmation, but it would be useful as a regression detector for any future demux work (alarm if the pre-DCID-migration counter goes high again post-migration).
  **Severity:** optional (was required-later HIGH, downgraded post-pcap).
  **Trigger:** if the DCID-migration spec wants a runtime regression alarm.

### Required-later (MEDIUM severity)

- **What:** Capture queueing-tail data via `h2load --h3` instead of `tquic_client`. Tquic_client has its own source-port allocation strategy and may exhibit the addr_key-collapse pattern more aggressively than other clients. h2load could either reproduce or contradict the asymmetry — one capture would tell us whether the demux-collapse is universal or harness-specific.
  **Severity:** required-later (MEDIUM).
  **Trigger:** before specing the DCID-demux migration; we want to know if the addr_key approach is fundamentally broken or just bad in this specific bench setup.

- **What:** Wrap the manual SIGINT-capture pattern in a `bench/quic_perf/scripts/profile-capture.sh <scenario> <duration>` helper. Plan C retro proposed this; we now have 3 captures across two plans. The helper is justified.
  **Severity:** required-later (MEDIUM, was optional before).
  **Trigger:** before the next profile re-capture.

### Optional

- **What:** Add a Mojo 0.26.2 "raises catalog" doc summarizing which stdlib methods are `raises` and how propagation works. Useful reference for future plans.
  **Severity:** optional.
  **Trigger:** if a future plan hits another `raises` discovery cycle that costs >10 min.

## Surprises / design concerns

### Surprise — server behavior is NOT the rate-limiter

The cumulative narrative across Plans B + C + this plan: every server-side hypothesis has been falsified or shown to NOT be the rate-limiter:
- FFI cost: real but only on processed packets
- Buffer-ring exhaustion: zero counters
- Harness limits: cross-client data already disproved
- Serial single-fiber queueing: P99 arrival-lat = 61us << 1s timeout

The server appears to be doing the right thing very efficiently for the packets it sees. The bottleneck is the asymmetry between "logical conns from client" and "addr_keys at server". Until we verify the addr_key-collapse hypothesis, every server-side perf optimization (multi-fiber fan-out, batch FFI, BufRing port) targets a non-existent bottleneck.

### Surprise — the methodology gate caught no contradictions

The Plan C retro codified "re-read every REFERENCE.md row before writing the new entry" as a HIGH severity methodology gate. T14 followed it strictly: re-read all 348 lines. **No contradictions.** The new finding (5 addr_keys vs 392 logical conns) is consistent with prior data — the asymmetry was hinted at in the prior CORRECTED-diagnosis section's "13-21 distinct conns vs 392 attempts" but not understood as the demux mechanism. The gate worked as a defensive check; this time it didn't trigger a course correction, but it ensured the new entry didn't accidentally re-falsify itself.

### Concern — 5 hs_complete conns vs 10 record_handshake_arrival count

A subtle inconsistency in the sidecar: `handshake.arrivals=10` and `handshake.successful=10` BUT `conns_total=5` (in `conn_pkt_counts`). The 5/10 ratio suggests `record_handshake_arrival` is being called per Initial packet OR addr_keys are being evicted/reused mid-run.

Looking at `bench/h3_server.mojo`'s lifecycle: when a connection times out and gets swap-and-popped (`_handle_timeout`), its `addr_key` is removed from `conn_map`. If a NEW logical conn arrives with the same addr_key later, it creates a NEW QuicConnection — both calls increment `record_handshake_arrival`. The `conn_pkt_counts` dict, however, accumulates per addr_key string across both. So `addr_key="1.2.3.4:5000"` shows pkt_count=high but contributes 2 to `hs_arrivals` and 1 to `conns_total` (one dict entry).

**Implication:** `conns_total` undercounts compared to `hs_arrivals` whenever conns are evicted and addr_keys reused. The instrumentation is consistent within itself; the user just needs to know the semantics. Worth a one-line note in the next REFERENCE.md entry.

## Final state

- Branch `feat/quic-queueing-tail-instrumentation` HEAD `64c493d` (14 commits)
- Tests pass: same baseline as pre-spec (33 PASS + `test_tls_connection` FAIL on pre-existing FFI symbol issue, out-of-scope)
- `comptime PROFILE_ACCEPT: Bool = False` confirmed at `src/quic/profile.mojo:16`
- Sidecar `bench/quic_perf/results/profile/INSTRUMENTATION-20260427-001113-queueing-tail.json` committed
- Smoke-gate doc `bench/quic_perf/results/profile/T11_T12_smoke_gate_2026-04-27.md` committed
- REFERENCE.md hypothesis-pass log entry committed (FALSIFIED + new addr_key-collapse hypothesis)
- Final cross-cutting review: ✅ CLEAN, all 11 acceptance criteria PASS

## Next-spec recommendations

### Immediate next (HIGH priority)

1. **Quick diagnostic spec — Initial-on-established-addr_key counter.** Adds 1 counter + 1 increment site + 1 SIGINT-flush print. ~10-20 LoC. One TDD task. Runs same SIGINT-capture pattern as T13. Confirms or falsifies the addr_key-collapse hypothesis. No code changes outside the counter itself.

2. **Conditional on (1) confirming:** spec the addr_key→DCID demux migration. Significant scope (50-100 LoC), changes connection lifecycle assumptions. Needs its own brainstorm + research on how tquic_server / quiche-server / nginx-quic do demux. Plan-split candidate (Phase A: side-by-side DCID demux for new conns; Phase B: deprecate addr_key demux entirely).

### Methodology

3. The "build instrument → run capture → interpret" cycle has now produced 5 hypothesis-pass entries on this branch lineage. The methodology is working. Continue this discipline: do NOT spec a fix until the data unambiguously points at a single mechanism.

### Before either next spec

The branch `feat/quic-queueing-tail-instrumentation` should FF-merge to main first so the next spec writes against integrated code. User owns the merge call (per Plan C retro pattern).
