# QUIC Accept-Loop Instrumentation — Plan C Retrospective

**Date:** 2026-04-26
**Branch:** `feat/quic-accept-loop-instrumentation` (renamed from `feat/quic-accept-loop-profile-b` mid-session)
**Range:** `8c25e1c..ac92e26` (Plan C: 1 commit + plan-write commit; foreign user h2 commits during execution: `88e5812`, `ca19331`)
**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`
**Plan:** `plans/2026-04-26-quic-accept-loop-instrumentation-plan-c.md`
**Final state:** ⚠ FOUR diagnoses recorded. (1) FFI dominance — falsified (only times processed packets, not the rate-limiter). (2) Buffer-ring exhaustion — falsified (zero drops on all six diagnostic counters). (3) Bench-harness floor — **also falsified** (REFERENCE.md rows 16-28 already contained N=2 cross-client validation showing both `tquic_client` AND `h2load --h3` drive `tquic_server` to 5-digit rps on the same harness). (4) **CORRECTED diagnosis:** server-side bottleneck is real; mechanism is most-plausibly serial single-fiber `_flush_impl` queueing under saturating-handshake load — invisible to existing 5-phase profiler because it only times *processed* packets, not arrival-to-processing latency. See REFERENCE.md "CORRECTED diagnosis (post-debate, 2026-04-26)" section for the full case.

## Built vs. planned

| Plan task | Status | Notes |
|---|---|---|
| C1 — Off-build baseline reproducibility GATE | ✅ PASS | Long-conn 405 rps median (calibrated 412), short-conn 0.42 rps median (calibrated 1). Both reproduce saturating-handshake regime. B14's 5-handshake anomaly was a one-off. |
| C2 — Flag flip + Docker rebuild on-build | ✅ as planned | `mojo-net-bench:latest` rebuilt with PROFILE_ACCEPT=True; ~5 min. |
| C3 — Short-conn sidecar capture | ✅ as planned | 17 handshakes / 30s, n=233 packets, SIGINT-driven sidecar JSON well-formed. |
| C4 — Long-conn-c100 sidecar capture | ✅ as planned | 5 handshakes / 30s, n=3571 packets; direct `docker run` overrode harness's `--max-concurrent-conns 25`. |
| C5 — ≥2× signal table analysis | ✅ as planned | Synthesis: short-conn → SM dominates 64.5×; long-conn-c100 → drain dominates 4.7×. |
| C6 — REFERENCE.md hypothesis-pass log + flag restore + commit | ✅ as planned | Single commit `ac92e26` with both sidecars + REFERENCE.md update + project-context advance. |
| C7 — Test baseline acceptance | ✅ PASS | Same baseline as Plan B; pre-existing `test_tls_connection` rustls FFI symbol failure out-of-scope. |

**Process deviation:** Plan C was executed directly via Bash (orchestrator) rather than through subagent-driven-development. Plan B retro had documented two abandoned subagent runs in B14 mid-Docker-rebuild ("Build still in progress" → return → no progress). For Plan C's operational tasks (Docker rebuilds, bench captures, JSON inspection), direct execution with `run_in_background` + completion notifications was strictly more reliable. No code changes meant per-task TDD/review wasn't applicable; no SDD ceremony was warranted.

## Deviations + why

### 1. Plan C executed without subagents — direct orchestrator execution

The plan was structured as 7 SDD-style tasks. In practice all 7 ran directly via Bash. Rationale:

- **No code changes.** Plan C was pure data collection; no implementer/reviewer per-task cycle made sense.
- **Subagent unreliability for long-running ops.** Plan B's B14 had two consecutive subagents that returned partially-done with messages like "Build still in progress" without completion. Subagents lack `ScheduleWakeup` for >2-min operations; long Docker rebuilds (~5-10 min) are exactly where they fail.
- **Background bash + completion notifications** are the right primitive. The orchestrator's `Bash run_in_background=true` + `until docker images | grep ...` wait-loop pattern works cleanly: kick off rebuild, get notification when done, proceed.

**Lesson for future plans:** when a plan is operational-only (no code review needed), invoke subagent-driven-development for structure but execute directly. The skill's "dispatch subagent per task" rule should have an exception for measurement-only work.

### 2. Container died on first SIGINT in C3 (recovered cleanly)

After driving 30s of short-conn load, the first `docker kill --signal=SIGINT bench-h3` caused the container to exit before the sidecar copy step. The text report appeared in `docker logs` but `docker cp` then ran against a stopped container. Worked because Docker preserves the filesystem of stopped containers until removal, so `docker cp` succeeded against the stopped container's filesystem.

This is actually expected behaviour: the bench server's main-loop check at the bottom of `_flush_impl` calls `external_call["exit", NoneType](Int32(0))` after writing the sidecar. The container exits cleanly. The harness's `stop-server.sh` then runs `docker rm -f` against the already-stopped container — also fine.

**Lesson:** the SIGINT-then-`docker cp` flow is robust. No changes needed.

### 3. C4 produced only 5 handshakes despite `--max-concurrent-conns 100`

Same anomaly Plan B's B14 hit. Long-conn with `--max-requests-per-conn 0 --max-concurrent-requests 10 --duration 30` opens a small number of long-lived connections (5 here, 5 in B14), each pumping unlimited requests. Raising `--max-concurrent-conns` from 25 to 100 didn't increase the actual handshake count — tquic_client opened the same handful of conns and saturated their stream-multiplex slots before opening more.

This is **tquic_client's behavior in long-conn mode, not a server bug.** The server can handle more handshakes; tquic_client just doesn't request them. The c100 capture measured steady-state stream serving (drain dominance), not the cold-start path.

**Conclusion:** for cold-start data, the short-conn scenario is the only path that works (each request requires a fresh handshake). The long-conn-c100 cell was useful as a control: it confirmed that in steady-state, FFI is NOT the dominant cost (sm/shim_ffi only 8us each there). Both cells together demonstrate that FFI dominance is a load-pattern-specific phenomenon (handshake CRYPTO, not steady-state STREAM).

### 4. zsh tripped on `===` in inline command

A multi-command Bash chain with `echo === TEXT REPORT ===` failed because zsh interprets `==` as a comparison operator. Quick fix: replace with `echo "[C3] text report:"`. Recovered without losing data (server was still up, sidecar still in container).

**Lesson:** when scripting against zsh, avoid bash-isms like raw `===` literals. Use quoted strings or different separators.

## Pain points

### Bench harness friction

- **`bench.sh` ends via container teardown, not SIGINT.** Plan B already documented this. Plan C used the manual pattern (`start-server.sh` + `run-tquic-client.sh` + `docker kill --signal=SIGINT` + `docker cp` + `stop-server.sh`) and it worked, but it's ~10 lines of orchestration for what should be a single-command operation. Future improvement (low-priority): wrap the manual pattern in a `bench/quic_perf/scripts/profile-capture.sh <scenario>` helper.

- **Harness's `run-tquic-client.sh` hardcodes `--max-concurrent-conns 25`.** For C4's 100-conn override, had to bypass the wrapper and `docker run` tquic_client directly. Not a blocker, but means the harness is only directly usable for the standard-config matrix.

- **`tquic_client` long-conn behavior is workload-shape-dependent.** `--max-concurrent-conns N` is an upper bound, not a target. With long-lived conns and unlimited per-conn requests, tquic_client opens a few conns and saturates them — never reaching N. This caught both Plan B's B14 and Plan C's C4.

### Process observations

- **Two user h2-perf commits landed mid-execution.** `88e5812 perf(h2): use boucle CoroutinePool in H2CoroServer` and `ca19331 docs(retro): combine Task 0 + Task 1 results, with R5 3×120s numbers` appeared on the branch during Plan C's run. The user is doing parallel h2 work. Both commits ride along to integration when the branch FF-merges.
- **Plan B + Plan C now share a branch.** The renamed `feat/quic-accept-loop-instrumentation` holds 17+ commits from Plans B and C plus the user's h2 work. Single FF-merge to main delivers everything together.

## Open questions (severity / trigger)

### Required-later (HIGH severity)

- **What:** Rust-side counters in `librustls-mojo/quic_hs.rs` to disambiguate FFI marshalling overhead from rustls work itself.
  **Severity:** required-later (high) — PREREQUISITE for choosing the cold-start fix.
  **Trigger:** anyone returning to the QUIC perf push. Spec a small Rust pass: per-call wall-clock timing (clock_gettime around the rustls calls inside `quic_conn_read_hs` / `quic_conn_write_hs` / `quic_conn_take_keys`), exposed via a new FFI getter the bench server calls during the SIGINT flush. Result: a new sidecar field `rustls_internal_us` showing how much of the 127us shim_ffi is FFI marshalling vs rustls processing.

- **What:** Cold-start fix — choice depends on Rust-side counters result.
  **Severity:** required-later (high)
  **Trigger:** after Rust-side counters land. If FFI marshalling dominates → spec **batch FFI** (one call carries N packets through `quic_conn_read_hs`, amortizing per-call setup). If rustls processing dominates → spec **handshake-cache for repeated client-Initial patterns** (Retry/0-RTT acceleration; harder, requires upstream rustls coordination or a custom handshake replay path).

### Required-later (medium severity)

- **What:** Multi-fiber accept fan-out (the original suspect from the pacer-bypass falsification log).
  **Severity:** required-later (medium) — still relevant if the rustls global lock is NOT the bottleneck (i.e., FFI marshalling is, and batch FFI works).
  **Trigger:** if batch FFI lands and shim_ffi drops, but the cold-start floor doesn't lift correspondingly, the per-packet serialization in `_flush_impl` may be the next bottleneck. Profile after batch FFI to confirm.

- **What:** `bench/quic_perf/scripts/profile-capture.sh <scenario>` helper to wrap the manual SIGINT-capture pattern.
  **Severity:** required-later (low/medium) — quality-of-life.
  **Trigger:** if profile re-capture happens more than once more.

### Optional

- **What:** `tquic_client` long-conn behavior should match `--max-concurrent-conns` more aggressively. Currently the flag is an upper bound that's rarely reached.
  **Severity:** optional
  **Trigger:** if cold-start via long-conn becomes desirable (currently short-conn covers the saturating-handshake regime fine). Submit a tquic upstream PR or document the workaround.

## REVISED diagnosis (post-Plan-C, independent investigation)

After Plan C's commit, the user asked an independent code-explorer subagent to analyse the "99.8% idle but saturated" paradox. The subagent's conclusion overturns Plan C's "FFI dominance" finding:

**The cold-start floor is buffer-ring exhaustion in the io_uring provided-buffer pool, not FFI cost.**

Trace (in `bench/h3_server.mojo:main()` ~lines 894-919 + `boucle/boucle/completion.mojo:774-789`):
1. `loop.poll(wait_nr=1)` drains all available CQEs, calls `on_flush()`, returns
2. Main loop iterates `consumed_bufs`, **queues** reprovide SQEs but does NOT submit them
3. Reprovides sit unsubmitted until next `loop.poll()`'s `submit_and_wait`
4. During that gap, kernel has no buffers; multishot recvmsg returns `-ENOBUFS` and terminates
5. `_handle_recvmsg` early-returns on `result <= 0` → no packet processed, no signal that anything was dropped
6. Re-arm fires but pool still empty → tight failure loop
7. Only the 50ms `submit_timeout` tick rescues it (forces `poll()` → submits queued reprovides → kernel sees buffers → brief acceptance window)

**Why Plan C's data still looks the way it does:**

- Server 99.8% idle: blocked in `poll()` because no CQEs arrive (kernel has no buffers).
- Only 17 arrivals: most Initials dropped at kernel-recvmsg before reaching `pending_rx`.
- Server-side timeout count = 0: server only sees the connections that arrived.
- FFI=127us "dominates": that cost is real for the 17 successful handshakes' packets, but the 80+ DROPPED Initials never accrued any FFI cost — the cost can't be the rate-limiter when 80% of attempts never reach FFI.

**What this means for the next steps:**

- Plan C's "Rust-side counters → FFI batching" recommendation is wrong as the cold-start fix. FFI cost is invisible to dropped packets.
- The user's recent commit `82905d5 perf(bench/h2): drop per-conn recv_buf, use boucle register_buf_ring` already ports h2 to the better `BufRing` API (zero-syscall reprovision via userspace atomic tail update). **The fix for h3 is to mirror this** — port h3 from `IORING_OP_PROVIDE_BUFFERS` (legacy SQE path) to `BufRing.add_buffer()` (current path).
- FFI batching stays on the queue as a steady-state (long-conn) optimization, but it's secondary, not the rate-limiter.

**Verification step (the user accepted; pending execution):** add `-ENOBUFS` counter to `_handle_recvmsg` (`if result <= 0: counter++`) + expose via SIGINT-flush sidecar. Re-run short-conn capture; if counter shows hundreds-thousands per second, hypothesis is confirmed.

**Open question (revised) — required-later, HIGH severity:**

- **What:** Port h3 to `BufRing.add_buffer()` mirroring `82905d5`'s h2 fix.
  **Severity:** required-later (high) — this IS the cold-start fix.
  **Trigger:** after the -ENOBUFS counter verification confirms buffer exhaustion is the rate-limiter.

**Lesson for future investigations:** instrumenting CPU-side (per-packet decomposition, per-leg averages) doesn't catch upstream rate-limiters in the kernel/io_uring layer. The bench server's `idle %` was a red flag we should have weighted more heavily — 99.8% idle plus reported saturation upstream is almost always "we can't see the problem from inside the loop, it's gating arrival." Future instrumentation should include kernel-level metrics (`nstat`, `-ENOBUFS` counts) as a first-class data source, not an afterthought.

## RE-REVISED diagnosis (post-buffer-ring-falsification, 2026-04-26)

**The buffer-ring exhaustion hypothesis was tested with diagnostic counters and FALSIFIED.** Six counters added to `bench/h3_server.mojo` (`enobufs_count`, `multishot_term_count`, `quic_server_err_count`, `h3_handler_err_count`, `feed_datagram_err_count`, plus `nstat -az` for kernel-side `UdpRcvbufErrors`). All six show **zero drops** across multiple short-conn runs. The server is processing every packet it sees, without error.

**TRUE diagnosis: the calibrated 412/1 rps floors are bench-harness limits, not server limits.**

The numbers:
- tquic_client: 392 "conns attempted", sent 3228 packets
- Server profile: 13-21 handshake arrivals, no errors anywhere
- Server processed every received packet successfully
- No drops at io_uring, kernel UDP, or app layers
- pkts_per_flush histogram totals match (~3500-7000 inbound, all entering pending_rx)

The only explanation consistent with the data: the 392 "conns" reported by tquic_client are largely the same source ports cycling through "open → send Initial → wait → timeout → re-open" multiple times. Only ~13-21 distinct slots manage to complete a handshake within the per-slot timeout in 30s. The "calibrated 412 rps long-conn / 1 rps short-conn" numbers from REFERENCE.md are PRODUCTS of (tquic_client's connect-and-cycle behavior) × (server's actual handshake completion rate), not pure server-side throughput limits.

**Implication for QUIC perf push:** optimizing the server stack at this level (FFI batching, multi-fiber fan-out, BufRing port) **would not lift the calibrated 412/1 rps floors**, because the harness can't actually saturate the server's processing capacity. The per-packet FFI cost (127us) is real but invisible at 0.4-0.7 conn-arrivals/sec.

**Real next investigation:**
1. **Inspect `tquic_client` source** to determine whether "conns: total 392" counts distinct source ports or per-attempt cycles. If distinct ports, server saw all 392 and dropped most → real server bottleneck → resume buffer-ring or upstream investigation. If per-attempt cycles, harness is the bottleneck → spec a better harness.
2. **Run multiple parallel tquic_client containers** to multiply the load and see if server saturates.
3. **Replace tquic_client with a packet flooder** that doesn't have per-slot timeout cycling.

**Lesson — this is the lesson for future perf investigations:**

When a server reports very low CPU usage AND a benchmark reports very low success rate, the most common explanation is the BENCHMARK is the bottleneck, not the server. Calibrated baseline numbers should always be cross-checked with diagnostic instrumentation BEFORE optimizing. We spent 3 plans (B + C + investigations) chasing server-side bottlenecks when the answer was upstream of the server entirely.

**Diagnostic counter changes left in place** (in `bench/h3_server.mojo`) — they cost ~6 UInt64 fields + ~5 atomic increment sites + 3 first-error prints. Worth keeping as permanent instrumentation for future runs.

**Open question (re-revised) — required-later, HIGH severity:**

- **What:** Determine whether the bench harness can be made to saturate mojo-net's server, OR whether the calibrated 412/1 rps floors are intrinsic to tquic_client's connect-cycling behavior. Do NOT spec further server-side optimizations until this is resolved.
  **Severity:** required-later (HIGH)
  **Trigger:** anyone returning to QUIC perf push.

## Surprises / design concerns

### Surprise — long-conn-c100 produced only 5 handshakes

Same anomaly as B14, now understood. tquic_client's long-conn workload-shape opens a handful of conns and saturates them. Raising the upper bound (25 → 100) doesn't change behavior. Short-conn is the only reliable cold-start exerciser.

This is now well-documented, but it would have saved Plan B's B14 misadventure if we'd realised this during Plan B brainstorming. **Lesson for future operational specs:** check the actual load shape produced by the test driver, not just its config flags.

### Surprise — short-conn idle was 99.8%

The bench server is BARELY using CPU during cold-start saturation (busy 0.2% / idle 99.8%). All the wall-clock cost is in serial per-packet FFI calls that the server fiber blocks on. This explains the calibrated baseline's "<6% CPU" observation: the server isn't CPU-bound; it's serially-blocked on rustls work.

**Implication:** vertical scaling (faster CPU) won't help. Horizontal scaling (multi-fiber accept) won't help if rustls work itself is the cost. Only **per-packet cost reduction** (batch FFI, handshake cache, or fewer-FFI-calls-per-handshake) addresses this directly.

### Concern — n=233 packets in short-conn capture is small

The short-conn capture saw only 233 packets total over 30s. This is because saturation throttles the entire pipeline: tquic_client opens a conn, sends Initial, server pumps a few CRYPTO+ACK packets back, conn dies, repeat. The bucket-estimated p50/p90/p99 (6/101/246) over n=233 has wide error bars on the tails.

For a more robust dominant-cost claim, a longer run (60-90s) would help. But the **per-leg averages** are sums over n=233 — those are exact, not bucket-estimated, and that's where the 64.5× SM dominance signal comes from. So the small n doesn't undermine the conclusion.

## Final state

- Branch `feat/quic-accept-loop-instrumentation` HEAD: `ac92e26`
- 17+ commits on branch (15 Plan B + 2 Plan C + 4 user h2-perf commits over 2 days)
- Tests pass (33 loopback, test_quic_profile, test_quic_profile_wiring; pre-existing test_tls_connection failure out-of-scope)
- `comptime PROFILE_ACCEPT: Bool = False` (off-build default) confirmed
- Two sidecar JSONs committed: `INSTRUMENTATION-20260426-203147-short-conn.json` + `INSTRUMENTATION-20260426-203304-long-conn-c100.json`
- REFERENCE.md hypothesis-pass log entry committed (with the FFI dominance finding)
- Plan B retrospective: `plans/2026-04-26-quic-accept-loop-instrumentation-plan-b-retrospective.md`
- Plan C retrospective: this file

## Next spec recommendations

### Immediate next (high priority) — REVISED post-debate

1. **Spec arrival-to-processing-latency instrumentation** in `bench/h3_server.mojo`. Stamp each datagram with `monotonic_us()` at `_handle_recvmsg` / pending_rx insertion; record `now - stamp` into a new histogram at `record_pkt`. Add a per-conn-id packet counter (`Dict[ConnID, UInt64]`) dumped to sidecar on SIGINT. Re-run short-conn capture. Expected signal: queueing-tail P99 ≥ tquic_client's per-conn handshake timeout; per-conn-id counts showing 80+ conn-ids with N≥3 packets and no handshake-complete event. This disambiguates "queueing under saturating drain" from any other server-side mechanism.

2. **Conditional on the above:** if queueing tail confirms, spec **multi-fiber accept fan-out** OR **batch FFI** (decision deferred until queueing-tail data shows whether per-packet processing or serial dispatch is the dominant cost). The Rust-side counters pass is *still* useful but is downgraded — without arrival-to-processing data we can't choose between the FFI fixes and the dispatch fixes.

3. **DO NOT** spec server-side optimizations until the queueing-tail data lands. Three preceding diagnoses each picked an optimization that the next investigation invalidated; the discipline now is: instrument, then optimize.

### Methodology fix — required-later (HIGH severity)

**What:** Before any future "TRUE diagnosis" entry in REFERENCE.md, re-read every existing row and verify the new claim doesn't contradict prior data. The four-diagnosis chain in this branch was caused by each investigation integrating only its own freshly-gathered data while ignoring REFERENCE.md's existing cross-client row (h2load) and tquic_server reference column.
**Severity:** required-later (HIGH).
**Trigger:** before drafting any future REFERENCE.md hypothesis-pass log entry.

### Before either spec — verify integration

The branch `feat/quic-accept-loop-instrumentation` holds Plans B + C + the user's h2-perf work. Before specing the next instrumentation pass, integrate this branch to main (FF-merge) so the next spec writes against current production code, not a feature branch. The user's pending h2 commits (`88e5812`, `ca19331`) ride along; coordinate.
