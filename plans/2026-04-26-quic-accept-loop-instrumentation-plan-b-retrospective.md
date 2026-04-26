# QUIC Accept-Loop Instrumentation — Plan B Retrospective

**Date:** 2026-04-26
**Branch:** `feat/quic-accept-loop-profile-b`
**Range:** `1acaa7b..e4e1fd4` (16 commits — 15 Plan B + 1 unrelated user h2-perf commit `82905d5` mid-branch)
**Spec:** `specs/2026-04-25-quic-accept-loop-instrumentation.md`
**Plan:** `plans/2026-04-26-quic-accept-loop-instrumentation-plan-b.md`
**Final review:** ✅ CLEAN (1 false positive on test-runner location)

## Built vs. planned

| Plan task | Status | Commit |
|---|---|---|
| B1 — monotonic_us microbench gate (≤30 ns/call) | ✅ PASS at 13 ns/call | `c0cecc9` |
| B2 — QuicConnection 4 always-present fields + AcceptProfile docstring + test | ✅ as planned | `4d51ef6` |
| B3 — `QuicConnection.server` accepts `profile_ptr` + stamps arrival | ✅ as planned | `a0cc3f1` |
| B4 — `recv_from_buffer` 5-phase decomposition + `record_pkt` emission | ✅ as planned | `c3ce47b` |
| B5 — `_drive_handshake` shim FFI accumulator (3 wrapped FFI calls) | ✅ as planned | `3abfe0f` |
| B6 — `_on_handshake_complete` latency record (server-side only) | ✅ as planned | `1cf96b3` |
| B7 — `H3UdpHandler` AcceptProfile field + idle/busy/fan-out in `_flush_impl` | ✅ as planned (preemptive scope-restructure used) | `36e599c` |
| B8 — `profile_ptr` threading + `record_drain` wiring | ✅ as planned | `70a02c8` |
| B9 — Eviction-site timeout count in `_handle_timeout` | ✅ accessor adapted (`_h3.is_established`) | `fe4de01` |
| B10 — SIGINT handler + main-loop check + report flush | ⚠ deviation: mmap'd flag at `0x60000000`; 1 Important issue (MAP_FIXED → MAP_FIXED_NOREPLACE) fixed in-task | `10465e0` + `765cc9b` |
| B11 — JSON sidecar dir + UTC timestamp formatter | ⚠ deviation: pivoted to `interop.file_io.write_file` + `mkdir_p` (stdlib FFI symbol collisions on `fclose`/`write`) | `4fca005` |
| Mid-execution fix — drop `thin` qualifier for Mojo 0.26.2 compat | ⚠ host 0.26.3.dev vs Docker 0.26.2 mismatch | `4d1de37` |
| B12 — `bench/quic_perf/README.md` "Profile build" section | ✅ as planned | `72bb3c6` |
| B13 — Single-cell smoke gate (off-build vs on-build, ≤10% drift) | ✅ PASS at -0.40% drift | (no commit — operational gate; results gitignored) |
| B14 — Streamlined sidecar capture (option B; full bench-mvp matrix skipped) | ⚠ honest finding: did NOT reproduce cold-start saturation | `e4e1fd4` |

## Deviations + why

### 1. B10 — module-level `Atomic` rejected; mmap'd page workaround

The plan called for `var g_profile_dump_pending = Atomic[Int32](0)` at module scope. Mojo 0.26.2 rejects all module-level `var` declarations with "global variables are not supported; move this into a function body or use 'comptime' to declare a constant."

The implementer also tried `comptime FLAG_PTR: UnsafePointer[Int32, ...] = _heap_alloc(...)` but reported empirically that this resolves to *different addresses* in different functions (claimed addresses differed by 0x40 mod 256). Plausible: comptime expressions are evaluated independently in each function's constant-folding context.

**Workaround:** mmap an anonymous page at the fixed virtual address `0x60000000` using `MAP_FIXED_NOREPLACE` (0x110). Both `main()` and the `fn _profile_signal_handler` synthesise an `UnsafePointer[Int32]` from the literal comptime constant `PROFILE_FLAG_ADDR = 0x60000000`, which resolves to the same word in both functions. Setup is in `_profile_install_signal_handlers()`, called from `main()` under `@parameter if PROFILE_ACCEPT:`.

**Why this is OK:** `MAP_FIXED_NOREPLACE` (Linux 4.17+) returns `ENOMEM` instead of clobbering an existing mapping; the return-address check at line 111 plus an updated error message ("address already in use or out of memory") give correct fail-fast semantics. The implementer's first attempt used plain `MAP_FIXED` which would silently clobber — flagged Important by the B10 reviewer; fixed in-task via commit `765cc9b`.

**Lesson for future plans:** When a plan instruction reads "module-level Atomic[Bool] flag," proactively check Mojo 0.26.2's restrictions before writing the plan. Module-level `var` is forbidden; the workaround is a known-painful pattern. Flagging this in the plan would have saved discovery time.

### 2. B11 — `fopen`/`fputs`/`fclose` external_call collisions

The plan's pseudocode used `external_call["fopen", ...]`, `["fputs", ...]`, `["fclose", ...]`. Mojo 0.26.2's stdlib already declares `fclose` and `write` with conflicting signatures — adding more `external_call` declarations triggered "existing function with conflicting signature" + LLVM legalization errors.

**Pivot:** the implementer used `interop.file_io.write_file(path, bytes)` and `interop.file_io.mkdir_p(path)` — both already in the repo, both raises-clean, both exactly what Plan B needed. `write_file` internally uses `open(O_WRONLY|O_CREAT|O_TRUNC) + pwrite64 + close` and also calls `mkdir_p` on the parent before opening, so directory creation is doubly covered.

**Why this is better than the plan:** the plan's pseudocode required hand-rolling C-string allocation (`String + "\0"` doesn't necessarily null-terminate the underlying buffer in Mojo 0.26.2). `interop.file_io._to_cstr` handles this internally. The pivot also avoids extending the FFI surface unnecessarily.

**Lesson:** when a plan calls for FFI to libc, search for existing helpers in the repo first. `interop/file_io.mojo` has a comprehensive set of file/dir/mkdir wrappers that should be the default for any bench-side I/O.

### 3. Mid-execution — `thin` qualifier breaks Mojo 0.26.2 build

B10 introduced `var fn_ptr: fn(Int32) thin -> None = _profile_signal_handler` because the implementer believed without `thin`, the function pointer would point to a stack-closure trampoline rather than the text segment.

The host has Mojo `0.26.3.dev2026042005` which accepts `thin`; the Docker image's pinned `mojo-compiler 0.26.2.0` rejects it ("unknown function effect 'thin', expected 'raises', 'capturing', or 'escaping'"). B13's smoke gate failed at "build off-build" because of this.

**Fix:** dropped the `thin` qualifier (commit `4d1de37`). The bare `fn(Int32) -> None` from a top-level `fn` produces a stable text-segment address — verified empirically via SIGINT smoke (the report dump fired correctly).

**Why this wasn't caught earlier:** the per-task review of B10 ran on the host Mojo where `thin` is recognised; the Docker build never executed during per-task validation (Docker rebuilds only happen in B13/B14). Per-task tests use the host compiler; smoke tests use Docker. The version mismatch is a known but routine pain point.

**Lesson:** for any FFI-adjacent code, the per-task verification command should include a Docker rebuild OR explicitly note that Docker validation is deferred to a later task.

### 4. B14 — full bench-mvp matrix skipped per user choice (option B)

The plan's B14 called for `make bench-mvp` (~50 min, 24 cells) followed by SIGINT-driven sidecar capture. After B13 PASSed at -0.40% drift on the load-bearing cell, the user chose option B (skip the matrix; do single-cell SIGINT capture only). Rationale: the matrix's purpose was overhead validation, which B13 already proved at <0.5% drift; the dominant-cost identification needed the sidecar's per-packet decomposition, not the rps matrix.

**Why this is documented:** REFERENCE.md's new entry explicitly notes the methodology shortcut and why it was taken. project-context's session entry mirrors this. Anyone returning to this work knows the matrix was skipped intentionally.

### 5. B14 — bench.sh ends via container teardown, NOT SIGINT

Operational discovery: the harness's `start-server.sh`/`stop-server.sh` flow stops the container with `docker stop`, NOT SIGINT — so `bench.sh` runs produce zero profile sidecars on their own. The plan assumed SIGINT-after-bench-mvp would capture the median-iteration sidecar; in practice the server is already gone by then.

**Workaround used in B14:** start the server via `start-server.sh mojo-net`, drive `run-tquic-client.sh 1k long-conn 30`, then `docker kill --signal=SIGINT bench-h3`, then `docker cp` the sidecar out before `stop-server.sh`.

**Lesson:** any future "report on shutdown" instrumentation in bench/ should hook into the harness's stop path (e.g., `stop-server.sh` could send SIGINT and wait briefly before `docker stop`) so the sidecar lands automatically. Out of scope for Plan B; flagged for future bench-harness work.

### 6. B14 — single-cell capture did NOT reproduce cold-start floor

**The biggest finding.** The 30 s `tquic_client 1k long-conn` capture produced only **5 handshakes** (100% success), not the calibrated baseline's "~400 attempts → 3-10 successes" pattern. tquic_client opened 5 long-lived connections and pumped streams through them rather than constantly reconnecting.

Steady-state stream serving dominated; the saturating-handshake load that produced the 412 req/s + 99% timeout floor (the very phenomenon the spec was designed to characterise) did not manifest.

**The data IS valid for what it captured:** per-packet RX is fast (~15 us p50 total), fan-out weighted-mean is 2.47 (well below ≥8), no in-recv leg dominates by ≥2×. Drain (bench TX) is the largest leg at 31 us avg but is expected to dominate steady-state. Handshake p99/max=29 ms vs p50=1.3 ms (n=5) is suggestive of the cold-start cost on the first connection but n is too small.

**The data is NOT valid for the cold-start hypothesis** that motivated the spec.

**Required-later (high severity):** re-capture under saturating-handshake load. Triggers documented in REFERENCE.md and in `## Open questions` below.

## Pain points

### Mojo 0.26.2 quirks

- **Module-level `var` is forbidden** — drove the mmap'd-flag workaround in B10. Painful to discover during implementation; should be flagged in any future plan that calls for global mutable state.
- **`thin` function effect added in 0.26.3, not in 0.26.2** — host had it, Docker didn't; broke the build at B13. Any function-pointer FFI must use the bare `fn(...) -> ...` form (which is implicitly thin in 0.26.2) and verify in Docker before merging.
- **`external_call` symbol collisions with stdlib FFI** — `fclose`, `write` are pre-declared in the stdlib; redeclaring them in user code triggers LLVM legalization errors. Drove the B11 pivot to `interop.file_io`.
- **Default-Value `UnsafePointer[T, MutAnyOrigin]()` works as null** — B3 verified this idiom; the `Int(ptr) != 0` check disambiguates null. Plan A's retrospective had flagged this as a possible pain point but it landed cleanly.
- **`@parameter if PROFILE_ACCEPT:` deprecation warnings** — Mojo 0.26.2 emits warnings for `@parameter if`; future Mojo wants `comptime if`. Followed the existing codebase pattern (which still uses the old syntax).

### Process observations

- **Per-task combined review caught one Important issue early** (B10's MAP_FIXED → MAP_FIXED_NOREPLACE) — the reviewer surfaced the latent silent-clobber risk before any operational damage. Fixed in-task via dedicated fix-it commit.
- **Build/smoke validation gap** — B10 passed per-task review on the host compiler but failed Docker compilation in B13. Mid-execution `thin`-qualifier fix unblocked it. Future plans should prefer Docker-equivalent validation per-task for FFI-adjacent code.
- **Two abandoned subagent runs in B14** — both got stuck waiting for Docker rebuild and returned partial output ("Build still in progress"). Subagents lack ScheduleWakeup; long-running operational tasks (>2 min) should be done by the orchestrator directly with `run_in_background` + completion notifications. Wasted ~10 min.
- **Mid-branch foreign commit** — `82905d5` (h2-bench register_buf_ring perf) authored by the user landed on the feature branch during B13/B14 execution. It's unrelated to Plan B but rides along to integration. Not a problem; just unusual.

## Open questions

### Required-later (high severity)

- **What:** Re-capture profile data under cold-start saturating-handshake load.
  **Severity:** required-later
  **Trigger:** anyone returning to QUIC perf push. Plan: `tquic_client` with `short-conn` scenario (forces frequent reconnect) AND/OR raise `--max-concurrent-conns` from 25 to 100+. Expected output: much higher `arrivals` (~100/s), much lower `successful` rate, and per-packet decomposition that may finally show fan-out (≥8 weighted-mean) or in-recv leg dominance (≥2×).

### Required-later (medium severity)

- **What:** `interop/udp.mojo:266-276` `monotonic_us` heap-allocates per call (Plan A retrospective carried this forward; Plan B did not need it because B13 measured -0.40% drift).
  **Severity:** required-later
  **Trigger:** if a future profile re-capture under saturating-handshake load shows >10% drift attributable to bench-side `monotonic_us`. Port the `InlineArray[Int64, 2]` stack-buffer pattern from `src/quic/profile.mojo:27-32`.

- **What:** Off-build asm spot-check (objdump on `recv_from_buffer`, `_drive_handshake`, `_flush_impl`).
  **Severity:** required-later
  **Trigger:** if a downstream reviewer or a Mojo-version upgrade raises doubt about `@parameter if PROFILE_ACCEPT:` codegen elimination. Run `mojo build --emit-llvm` off-build vs on-build and diff the IR.

### Required-later (low severity)

- **What:** Bench-harness `stop-server.sh` should send SIGINT before `docker stop` so profile sidecars land automatically during `bench.sh` runs.
  **Severity:** required-later (low)
  **Trigger:** if Plan B's instrumentation gets used routinely (more than the one-off cold-start hunt). Currently the manual SIGINT pattern is documented in `bench/quic_perf/README.md`.

### Optional

- **What:** `signalfd` integration with io_uring so the SIGINT report flushes within bounded latency under low-traffic conditions.
  **Severity:** optional
  **Trigger:** if operators report the documented "may take seconds to flush" caveat as painful during instrumentation runs.

- **What:** `n_closed` variable name in `report_text`/`report_json` is misleading (means "non-overflow packet count," not "closed connections").
  **Severity:** optional
  **Trigger:** code-style sweep.

## Surprises / design concerns

### Surprise — Mojo 0.26.2 module-level state really is hard

Plan A and Plan B between them spent 3 separate workarounds on Mojo 0.26.2's module-level-state restrictions:
- Plan A: `comptime PROFILE_ACCEPT: Bool = False` (works because comptime constants ARE allowed at module scope).
- Plan B: `comptime PROFILE_FLAG_ADDR: Int = 0x60000000` + mmap'd page (works around runtime mutable state).
- Plan B: `fn _profile_signal_handler` at module scope (works because `fn` IS allowed).

But the natural primitive — a module-level `Atomic[Int32]` — is rejected. This is a recurring Mojo-0.26.2 friction point. When Mojo eventually supports module-level `var`, the mmap workaround can be removed (~30 LoC of hand-rolled FFI deletes cleanly).

### Concern — drain (bench TX) is the dominant per-packet leg in steady state

`drain.avg = 31 us` vs in-recv legs all ≤11 us. The drain wraps `_drain_and_send` which:
1. Calls `H3HandlerServer.drain_datagrams(now)` → builds outgoing packets (response framing, flow-control, packet protection / outgoing AEAD)
2. Allocates UdpTxSlot, copies bytes, registers token, queues `_SUBMIT_SENDMSG` for io_uring

In steady state, the TX path naturally dominates because RX is mostly ACKs while TX is full HTTP/3 response payloads. **This is not actionable** as a perf hypothesis — it just confirms the loop spends most per-packet time generating responses, which is what we want it to do.

If a future cold-start saturation re-capture ALSO shows drain dominance, that would be more concerning — it would mean the *handshake* response generation (Initial+Handshake CRYPTO+ACK packets) is somehow expensive. Worth re-examining at that point.

### Concern — only 5 handshakes in a 30 s tquic_client long-conn run

This is the biggest design concern from B14. The bench harness's `tquic_client 1k long-conn` invocation does NOT reproduce the cold-start saturation pattern that produced the calibrated baseline's 412 req/s + 99% timeout floor. Either:
- (a) The calibrated baseline was running under a different load pattern than `bench.sh mojo-net 1k long-conn tquic_client` reproduces today (parameter drift?).
- (b) `tquic_client` in long-conn mode genuinely just opens N=25 conns and pumps streams; the cold-start floor is a short-conn-mode phenomenon.
- (c) Something about running tquic_client during a profile build (or this specific time of day, or this specific tquic-bench:latest image) prevents handshake saturation.

Worth a quick verification before Plan C: compare an off-build `bench.sh mojo-net 1k long-conn tquic_client --iters 1` from today against the 2026-04-25 run (412 rps, 290/388 timeouts). If today's off-build also shows 5 handshakes / 100% success, the calibrated baseline is unreproducible and the spec's premise is suspect.

## Next spec recommendations

### For the next spec ("Plan C — saturating-handshake re-capture")

1. **Test the load pattern before designing the spec.** Run `bench.sh mojo-net 1k short-conn tquic_client --iters 1` (off-build) and check the handshake-attempt count from tquic_client's stdout. If it shows the 100+/30s pattern that 99% timeouts implies, proceed. If not, the bench harness needs adjustment first.

2. **Use the existing instrumentation as-is.** Plan B's profile module is on main (Plan A) + insertion is on the feat branch. After integration, just hand-edit the flag and re-run.

3. **Prefer short-conn over higher concurrency.** `tquic_client --duration 30 --max-concurrent-conns 100 --max-requests-per-conn 1` should produce the saturating-handshake regime more reliably than long-conn at any concurrency.

4. **Verify the calibrated baseline is reproducible** before drawing conclusions. If 412 rps + 99% timeouts can't be reproduced today off-build, the cold-start floor may have already been fixed by an unrelated change (the user's `82905d5` h2-perf commit is a candidate for accidental QUIC perf impact, though h2 and QUIC are separate stacks).

### For follow-up specs (post-Plan C)

- **Multi-fiber accept fan-out spec** — Triggered if Plan C re-capture shows `pkts_per_flush_histogram` weighted-mean ≥ 8.
- **Rust-side counters spec** — Triggered if Plan C re-capture shows `shim_ffi.avg ≥ 2 ×` next-largest leg.
- **AEAD batch path spec** — Triggered if Plan C shows `aead.avg ≥ 2 ×` next-largest leg.

## Final state

- Branch `feat/quic-accept-loop-profile-b` HEAD: `e4e1fd4`
- 16 commits in range (15 Plan B + 1 unrelated user h2-perf commit `82905d5`)
- Tests pass on both off-build and on-build (per-task verified; final pre-existing `test_tls_connection` failure is documented out-of-scope rustls FFI symbol issue)
- B13 single-cell smoke gate: -0.40% drift (PASS, ~25× headroom on the 10% budget)
- B14 sidecar JSON committed: `bench/quic_perf/results/profile/INSTRUMENTATION-20260426-183256.json`
- REFERENCE.md hypothesis-pass log entry committed
- `comptime PROFILE_ACCEPT: Bool = False` (off-build default) confirmed in final state
- ~150 LoC added in `bench/h3_server.mojo` + ~40 LoC in `src/quic/connection.mojo` + ~10 LoC in `src/quic/profile.mojo` (struct docstring) + ~80 LoC in `tests/test_quic_profile_wiring.mojo` + ~80 lines in `bench/quic_perf/README.md` + ~50 lines in `bench/quic_perf/results/REFERENCE.md` + 1 microbench script
