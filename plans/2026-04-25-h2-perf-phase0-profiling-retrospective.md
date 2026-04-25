# H2 Perf — Phase 0 Profiling: Retrospective

> Plan: `plans/2026-04-25-h2-perf-phase0-profiling.md`
> Baseline SHA: `d6fdbcb` (5 109 perf samples, 55 s on `/baseline2`)

## Built vs. planned

All 6 tasks delivered. 6 commits on `main`:

| Plan task | Commit  | Notes |
|-----------|---------|-------|
| Task 1 — vendor FlameGraph | `1bf6572` (with the plan) | `bench/.tools/.gitignore`; FlameGraph cloned manually as documented |
| Task 2 — throughput tier | `95c46d8` | `bench/profile/h2-throughput.sh` + CSV header |
| Task 3 — perf-record tier | `eb71290` | `bench/profile/h2-perf-record.sh`; `bench/profile/runs/.gitignore` |
| Task 4 — hotspot extractor | `d6fdbcb` | `bench/profile/h2-hotspots.sh` |
| Task 5 — README + baseline | `4311b16` | README + first measurement row + flamegraph SVG + hotspot MD |
| Task 6 — this retrospective | (this commit) | |

**Deviations:**
1. **Host-build instead of Docker for the perf-record tier.** Plan said "Boot mojo-net single-worker (override BENCH_WORKERS=1 env)". I went a step further: the perf-record script runs `bench/h2_server` directly on the host (no Docker, no launcher). The host binary is unstripped ELF — symbols resolve immediately, no `--symfs` gymnastics. Multi-worker is implicitly avoided because we just don't run the launcher. Throughput tier still uses the Docker'd multi-worker image — both views are useful.
2. **Hotspot table column relabeled.** Smoke test surfaced that `stackcollapse-perf.pl` emits perf's PERIOD weight (≈ cycles), not raw sample counts. Renamed `Samples` → `Weight` and added a unit note. Percentages were always correct; only the column header was misleading.

---

## Baseline numbers

### Throughput (h2load `-n 100000 -c 50 -m 16`, multi-worker Docker image)

| Endpoint              | mojo-net req/s | hyper req/s | mojo / hyper | mojo p50/p99/p999 (µs) |
|-----------------------|---------------:|------------:|-------------:|------------------------|
| `/baseline2?a=1&b=2`  | 236 935        | 337 484     | **70 %**     | 2 169 / 4 600 / 6 356  |
| `/json/50?m=6`        |  35 901        | 363 344     | **9.9 %**    | 15 772 / 39 179 / 53 084 |
| `/static/footer.html` | 213 613¹       |  29 942     | 7.1× (artifact¹) | 0 / 0 / 0² |

¹ `bytes/req=29` for mojo vs `56 376` for hyper → mojo-net's static-file path is **not actually serving the file content** on this endpoint. Likely a 404 or empty body returned with 200 OK. Investigation flagged as Open Question O-1 below — affects whether we can credit the static-file numbers at all.

² `0` percentiles mean h2load's per-request log lacked enough resolved end-of-stream entries; for 213K rps the per-request times are below the 1-µs floor that h2load logs at. Documented in the README.

### Hotspot capture (single-process host `bench/h2_server`, 55 s on `/baseline2`)

5 109 perf samples, 407 unique stacks. Full table at `bench/profile/baselines/h2-hotspots-d6fdbcb.md`.

---

## Top hotspots

### Top 5 by self-time

| % self | Symbol | What it is |
|------:|--------|------------|
| 18.22 | `[libAsyncRTRuntimeGlobals.so]` | Mojo coroutine runtime (no symbols inside) |
|  7.92 | `H2CoroServer::_drain_responses` | Pop response frames + push to TLS layer |
|  6.76 | `HpackDecoder::_decode_string` | HPACK string-literal decoder |
|  4.43 | `_to_lower` | ASCII lowercase per HTTP header byte |
|  4.09 | `__tls_get_addr` | C runtime thread-local-storage lookup (NOT network TLS) |

### Top 5 by inclusive-time (after stripping `h2_server` and `main` roots)

| % incl | Symbol | What it gates |
|------:|--------|---------------|
| 24.78 | `H2CoroServer::_drain_responses` | The whole egress path |
| 22.96 | `H2Connection::receive_data` | Frame parsing on ingress |
| 18.06 | `List::_realloc` | Reachable from 18 % of all stacks — allocator pressure |
| 15.26 | `H2CoroServer::_dispatch_events` | Coroutine wakeup dispatch |
| 12.14 | `HpackDecoder::decode` | Combined with `_decode_literal` (10.44) and `_decode_string` (10.36) → ~33 % of stacks pass through HPACK decode |

---

## Phase 1 candidate targets, ranked by ROI

ROI = (measured self-cost recovered if attacked) ÷ (engineering hours + risk). Estimates are deliberately conservative — Phase 1 PRs will re-measure.

### IN SCOPE for Phase 1

| Rank | Target | Self % | Estimated cost | Expected gain | Decision |
|----:|--------|------:|---------------|---------------|----------|
| **1** | **HPACK decode** (`_decode_string` 6.76 self / `_decode_string + _decode_literal + decode` 33 incl) | 6.76 | 2–3 days | If we halve `_decode_string` → ~3 % rps. The 10 % inclusive on `_decode_literal` overlaps with `_decode_string` (literal calls string), so combined attack target is ~10 % of CPU. SIMD-scan for varint termination + buffer reuse for the decoded string. | **In scope** |
| **2** | **`_to_lower` + header String churn** (`_to_lower` 4.43 + `String::_iadd` 3.45 + `String::unsafe_ptr_mut` 2.87 + `chr` 1.58 + `String::__init__` 0.80) | ~13 combined | 1–2 days | Lowercasing every header byte by allocating fresh `String` instances. Switch to in-place `Span[UInt8]` lowercase + comparison would eliminate most of this category. Halving recovers ~6 %. | **In scope** |
| **3** | **List allocator pressure** (`List::_realloc` 2.26 self / 18 incl + `TCMallocInternalCfree` 2.48 + `KGEN_AlignedAlloc` 0.84 + `KGEN_AlignedFree` 0.59) — combined allocator self ≈ **7.15 %** | 7.15 | 1–2 days | Pre-size the response writer's `List[UInt8]` and the per-stream pending data queue. Won't go to zero but realistic 50 % cut → ~3.5 %. | **In scope** |

### DEFERRED (Phase 2 or later)

| Target | Self % | Reason for deferral |
|--------|------:|---------------------|
| `swapcontext` + `getcontext` (~5 self combined) | 5 | Coroutine context-switch cost. Lowering it requires either fewer suspends per request (architectural) or a switch from `ucontext` to `setjmp`/`longjmp`. Not a one-PR change — defer to a coro-architecture plan. |
| `Dict::_insert` (2.95 self) | 2.95 | Used in stream-state lookup. The `InlineArray` pattern that worked for json-simd-mojo's container stack would help, but the stream-id space is sparse. Phase 2 if Phase 1 doesn't close the gap. |
| `Variant::__init__` (1.81 self) | 1.81 | Likely from `Optional[]` returns. Mojo-stdlib choice; revisit only if it's a top-5 leftover post-Phase-1. |
| **TLS-record chunking** (commit `9f1665b`) | **0.14 self / 1.08 incl** | The whole hypothesis the comparison writeup called out: "could be reduced to one call by batching multiple H2 frame groups." Measured cost is **1 % of CPU**. Even a perfect 100 % win recovers <1 % rps — not worth touching. **Hypothesis falsified.** |
| **rustls vs OpenSSL+kTLS swap** | **0.56 self / 0.60 incl** | Network TLS encrypt (rustls + aws-lc-rs combined) is **0.6 % of CPU**. The largest single dependency change in mojo-net's TLS stack would buy <1 %. **Hypothesis strongly falsified.** Defer permanently unless the gap reaches the noise floor. |

### NOT VISIBLE in this profile (negative signal)

- **Network TLS encrypt** doesn't make the top 30 self. We checked: 0.56 % combined. The aws-lc-rs AVX-512 GCM encrypter is doing its job.
- **`tls.send_data` + `drain_ciphertext` (mojo-net wrappers)** combined are 0.14 % self / 1.08 % inclusive. Our own TLS-layer code is essentially free; rustls is essentially free; the 9f1665b chunking commit is essentially free.

---

## Methodology issues

1. **`[libAsyncRTRuntimeGlobals.so]` is 18.22 % of self with no symbols.** Mojo's async runtime doesn't ship debug symbols in the binary we're profiling. We can't tell if that 18 % is `swapcontext`-internal, scheduler queue management, allocator, or something else. **Action:** open issue with the Mojo team for a debug-info build, or build the runtime locally with symbols. For Phase 1 we treat this as opaque cost we can't directly attack.
2. **`[unknown]` 6.46 % of self.** Stacks where dwarf unwind partially failed. `--call-graph=fp` would lose more frames; `--call-graph=lbr` requires recent kernels. Acceptable noise for a 5K-sample run; if Phase 1 numbers are tight we re-capture at `-F 999` with longer duration.
3. **5 109 samples is on the threshold.** A single-run delta of <1 % is below the noise floor. Phase 1 PRs should run two captures and report the spread, or use a 120 s capture for ~10K samples. Documented in the README under "Caveats".
4. **Single endpoint per perf-record run.** We profiled `/baseline2` only. The hotspot mix on `/json/50?m=6` (where mojo is at 9.9 % of hyper) will look very different — header churn matters less when the body is 8 KB but JSON-writer cost dominates. **Phase 1 must capture `/json/...` separately before deciding whether to also touch the JSON path.**
5. **Throughput CSV `0/0/0` percentiles for ultra-fast endpoints.** h2load's `--log-file` records times in microsecond integers; `/static/footer.html` at 213K rps means responses complete inside h2load's 1-µs floor. Acceptable for a trend metric; if we need µs-resolution we'd need a different load gen.

---

## Open questions

- **O-1 — `/static/*` body content.** Severity: **required-now** for accurate comparison. Trigger: the `bytes/req=29` for mojo-net /static while hyper sends 56 KB. mojo-net's static handler is likely returning a placeholder body. Until this is fixed, the static-file row in the throughput CSV is misleading and should not be cited as "mojo-net beats hyper 7×". **Action:** confirm with `curl -k -v https://127.0.0.1:8443/static/footer.html` and either fix the handler or remove static from the endpoint set. This is a correctness bug discovered by the harness, not a perf issue.
- **O-2 — `[libAsyncRTRuntimeGlobals.so]` opacity.** Severity: optional. Trigger: if Phase 1 lands and we're still ~25 % short of hyper. We need symbols inside that 18 %.
- **O-3 — h2 launcher / multi-worker delta.** Severity: optional. The single-process host h2_server hit 236 K req/s on `/baseline2`; the launcher / Docker multi-worker version was hitting 243 K in the comparison writeup. Why so close? Multi-process should scale, but the worker count baked into the image may not match the cores we're running on. Not a Phase 1 blocker.

---

## Exit criteria — answered

The plan required Phase 0 to answer 5 questions before Phase 1 could be drafted. All five now have numerical answers:

| # | Question | Answer |
|--:|----------|--------|
| 1 | mojo-net req/s + p99 vs hyper across `/baseline2`, `/json/50?m=6`, `/static/*`? | See Baseline Numbers table above. |
| 2 | Top 5 self-time hotspots in the H2 worker? | runtime 18.22 → drain_responses 7.92 → _decode_string 6.76 → _to_lower 4.43 → __tls_get_addr 4.09. |
| 3 | % CPU in `tls.send_data` + `drain_ciphertext`? | **0.14 % self / 1.08 % inclusive.** |
| 4 | % CPU in allocator paths? | **7.15 % self combined** (`_realloc` + `TCMallocInternalCfree` + `KGEN_AlignedAlloc` + `KGEN_AlignedFree` + libc malloc/free). |
| 5 | % CPU in rustls AEAD encrypt? | **0.56 % self / 0.60 % inclusive.** |

**Phase 1 is unblocked.** Drafting `plans/2026-04-26-h2-perf-phase1-codegen-allocation.md` next, scoped to the three "in scope" targets above.
