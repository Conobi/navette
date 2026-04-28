# H3 phase-leg instrumentation: closing the long-conn unaccounted gap

**Date:** 2026-04-29
**Origin:** Q1 follow-on from `plans/2026-04-28-quic-accept-loop-subleg-instrumentation-retrospective.md` (Subagent B's finding from sub-leg pass)
**Predecessor research:** `research/2026-04-28-long-conn-unaccounted-gap.md` — names 3 untimed phases inside `feed_datagram_from_buffer`'s post-recv tail (`H3HandlerServer._drain_responses` 12-16s, `H3Connection._drain_stream` 5-8s, `BenchHandler` dispatch 1-3s).

---

## 1. Goal

Decompose the **24.4s long-conn `unaccounted_us_total` ε** (82% of `busy_us_total`) into 3 named `AcceptProfile` phase legs so the next long-conn-targeted optimisation spec has a clear, evidence-backed target.

**Diagnostic-only spec.** No RPS lift expected. Success metric is `unaccounted_pct` reduction (82% → <15% on long-conn) and naming the dominant phase.

## 2. Why this exists / why now

Q3 (Dict[UInt64,Int] DCID demux) just shipped (`cd12818`); long-conn now sits at ~14k rps (16.2% of tquic_server). The next long-conn-moving optimisation requires phase-level visibility into the post-recv H3 tail; without it, we cannot tell whether to attack QPACK encode, STREAM-buffer writes, handler invoke, or the H3 stream-readable drain. Per Q3 retrospective, Q1 is the highest-priority next spec.

The sub-leg pass (`488f113`) named the dominant short-conn FFI sub-leg (`ffi_read_hs` at 93.3%); this spec is the long-conn analogue, naming the dominant unattributed phase.

## 3. Scope

**In scope:**
- `src/quic/profile.mojo`: 3 new `UInt64` fields (`h3_drain_resp_us`, `quic_post_recv_us`, `h3_dispatch_us`) + 3 new `record_*` methods + JSON/text emission + budget-closure ε refresh.
- `src/h3/h3_handler_server.mojo`: new `profile_ptr` field, ctor-arg threading, 2 brackets (`_dispatch_h3_events` line 130, `_drain_responses` line 132).
- `src/h3/connection.mojo`: new `profile_ptr` field, ctor-arg threading, 1 bracket around `feed_datagram_from_buffer`'s poll-loop tail (lines 264-296).
- `bench/h3_server.mojo`: thread `profile_ptr` through `H3HandlerServer` constructor at line 843 (post-Q3-merge line; Subagent B's research cited line 822 pre-merge).
- `tests/test_quic_profile.mojo`: +6 unit tests (3 leg emit + 1 JSON-emit + 1 budget-closure refresh + 1 sum-invariant).
- `bench/quic_perf/results/REFERENCE.md`: new shipped-pass row.

**Out of scope (explicit non-goals):**
- Touching `src/quic/connection.mojo` or `src/quic/codec.mojo` — already instrumented sufficiently by sub-leg pass.
- Optimising any of the 3 newly-named phases — that's the next spec's job.
- Adding sub-legs WITHIN any of the 3 new phases (e.g., splitting `quic_post_recv_us` into `_quic.timeout` + `_drain_stream`) — deferred until evidence shows the leg dominates AND further decomposition is needed.
- Bracketing the non-buffer `feed_datagram` variant at `h3_handler_server.mojo:116-120` — bench uses `_from_buffer` exclusively post-zero-copy; production callers (if any) get no instrumentation. Acceptable because PROFILE_ACCEPT is bench-only.
- Nested record_* brackets inside the `_quic.timeout` / `poll` callees of `quic_post_recv_us` — explicit non-goal to prevent double-counting via timer-fire recursion.
- Short-conn `unaccounted_pct` reduction — short-conn ε is only 18% (handshake-bound), already small; if the 3 new legs don't bring it below 5%, file a follow-on (open-question).

## 4. Design decisions (validated 2026-04-29)

| # | Decision | Rationale |
|---|---|---|
| D1 | Option A wiring (src/-touching, decomposed 3 legs) | Bench-only outer wrap (Option B) only gives a single combined number. Hybrid (1 inner + outer) loses post_recv vs dispatch decomposition. Decomposition is the whole point. |
| D2 | 3 phase legs (h3_drain_resp + quic_post_recv + h3_dispatch) | Subagent B's prediction shape (12-16s / 5-8s / 1-3s) is distinct enough to disambiguate (2-3× spread). Collapsing loses the Rank 1 vs Rank 3 signal. |
| D3 | `profile_ptr` threading via ctor-arg | Mirrors existing `H3UdpHandler.profile` field pattern. Type system catches missing wires. Thread-local globals would couple `src/` to fragile concurrency state. |
| D4 | 5-gate validation (unaccounted_pct + RPS x4 + sum invariant + correctness) | RPS non-regression on/off-build both cells is the critical guard for `src/`-touching diagnostic work. Sub-leg sum invariant catches bracket overlap. |
| D5 | Single-pair clock-read pattern with hoisted `var t_start: UInt64 = 0` | Same as the **sub-leg pass T4** (already validated under Mojo 0.26.2 lexical scope; see `plans/2026-04-28-quic-accept-loop-subleg-instrumentation-retrospective.md` §lessons). Disambiguation: this references the previous spec's T4, NOT this spec's T4 (which owns budget-closure refresh tests per §6 and §11). |

## 5. File-level change list

### 5.1 `src/quic/profile.mojo`

Add 3 new `UInt64` fields to `AcceptProfile` (alongside existing `loop_pop_dispatch_us`/`loop_post_pkt_us`/`loop_teardown_us`):

```mojo
# H3 application-layer phase legs (post-recv tail of feed_datagram_from_buffer):
var h3_drain_resp_us: UInt64       # _drain_responses: QPACK encode + H3 frame encode + STREAM-buffer writes
var quic_post_recv_us: UInt64      # Post-recv tail of QuicConnection.feed_datagram_from_buffer (timeout + poll + _drain_stream)
var h3_dispatch_us: UInt64         # _dispatch_h3_events: handler invoke + Request/Response/Body construction
```

Add 3 record methods:

```mojo
fn record_h3_drain_resp(mut self, us: UInt64):
    self.h3_drain_resp_us += us

fn record_quic_post_recv(mut self, us: UInt64):
    self.quic_post_recv_us += us

fn record_h3_dispatch(mut self, us: UInt64):
    self.h3_dispatch_us += us
```

Update `report_json` to emit a new `h3_phases_us` block:

```json
"h3_phases_us": {
    "drain_resp": {"total": ..., "avg_per_iter": ...},
    "post_recv": {"total": ..., "avg_per_iter": ...},
    "dispatch":  {"total": ..., "avg_per_iter": ...}
}
```

Update budget-closure ε computation (`unaccounted_us_total`) to subtract the 3 new legs. Explicit formula post-Q1:

```
unaccounted_us_total = busy_us_total
                       − Σ(per_pkt_us legs)
                       − drain_us
                       − Σ(loop_phases_us legs: pop_dispatch + post_pkt + teardown)
                       − h3_drain_resp_us
                       − quic_post_recv_us
                       − h3_dispatch_us
```

`unaccounted_pct = unaccounted_us_total / busy_us_total * 100`. Both fields gated by `if busy_us_total > 0` to avoid divide-by-zero on empty-iter sidecars. T4's `test_budget_closure_subtracts_h3_legs` enforces bit-exact equality on a synthetic profile.

Update `report_text` similarly.

### 5.2 `src/h3/h3_handler_server.mojo`

Add `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` field. Field is **unconditional** (matching `QuicConnection.profile_ptr` precedent at `src/quic/connection.mojo:334`); the empirical struct-layout-drift guard is AC#5 (off-build RPS non-regression). Rollback plan if AC#5 fails: remove the field, not gate it (Mojo 0.26.2 does not cleanly support `@parameter if`-gated struct fields in a way that changes layout per-build).

Update `__init__` to accept `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin] = UnsafePointer[AcceptProfile, MutAnyOrigin]()` kwarg (default-null), store it on `self.profile_ptr`, and forward it to `self._h3` post-construction via `self._h3.profile_ptr = profile_ptr` (Shape B, locked in §5.3 — `H3Connection.server`/`.client` have ~15 call sites across `src/h3/` and `tests/` so default-null kwarg threading would balloon scope).

Bracket `_dispatch_h3_events` at line 130 (single-pair clock-read, function-scope hoisted `var t_start: UInt64 = 0`):

```mojo
var t_start: UInt64 = 0
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        t_start = profile_monotonic_us()
self._dispatch_h3_events(now)
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        self.profile_ptr[].record_h3_dispatch(profile_monotonic_us() - t_start)
```

Same shape around `_drain_responses` at line 132 with `record_h3_drain_resp`.

### 5.3 `src/h3/connection.mojo`

Add `profile_ptr: UnsafePointer[AcceptProfile, MutAnyOrigin]` field (unconditional, same precedent as §5.2). Initialise to default-null in `H3Connection.__init__` and in the `H3Connection.server` / `H3Connection.client` factory methods so existing call sites compile unchanged.

**Threading shape (locked):** Shape B post-construction setter — `H3HandlerServer.__init__` sets `self._h3.profile_ptr = profile_ptr` AFTER `H3Connection.server(...)` returns. Locked over Shape A (ctor-arg threading) because `H3Connection.server`/`.client` have **~15 call sites across 4 `src/h3/` files (h3_handler_server, h3_session, h3_streaming_server, h3_sync_server) and 5 test files** — Shape A would require all of them to grow a default-null kwarg. Shape B is a single line in `H3HandlerServer.__init__` and leaves all other call sites untouched.

The bracket in `H3Connection.feed_datagram_from_buffer` reads `self.profile_ptr` (set by H3HandlerServer post-construction) and runs the null-check pattern.

Bracket the poll-loop tail of `feed_datagram_from_buffer` (lines 264-296). The bracket spans `_quic.timeout(now)` + the `while True: poll()` event loop including `_drain_stream`:

```mojo
self._quic.recv_from_buffer(buf, buf_len, now)  # already timed by record_pkt
var t_start: UInt64 = 0
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        t_start = profile_monotonic_us()
self._quic.timeout(now)
while True:
    var ev = self._quic.poll()
    if ev.is_none():
        break
    # ... _drain_stream(ev.stream_id, now), etc.
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        self.profile_ptr[].record_quic_post_recv(profile_monotonic_us() - t_start)
```

### 5.4 `bench/h3_server.mojo`

In `_flush_impl` cold-create at line 843, thread `profile_ptr` through, mirroring the existing `QuicConnection.server(...)` `@parameter if PROFILE_ACCEPT:` / `else:` split at lines 795-815 (verbatim form):

```mojo
# Existing site at line 843 (post-Q3-merge), pre-spec:
# h3 = H3HandlerServer[BenchHandler](quic=quic^, handler=handler^)
# Post-spec: split via @parameter if PROFILE_ACCEPT, mirroring QuicConnection.server:
@parameter
if PROFILE_ACCEPT:
    h3 = H3HandlerServer[BenchHandler](
        quic=quic^,
        handler=handler^,
        profile_ptr=UnsafePointer(to=self.profile),
    )
else:
    h3 = H3HandlerServer[BenchHandler](
        quic=quic^,
        handler=handler^,
    )
```

The split is required because Mojo 0.26.2 materialises `UnsafePointer(to=self.profile)` eagerly even in code that would later be elided; the existing pattern at `bench/h3_server.mojo:795-815` proves this is the correct shape and the codegen for the `else:` branch is identical to a vanilla call (no pointer materialisation). `H3HandlerServer.__init__` accepts `profile_ptr` as a default-null kwarg per §5.2 so the `else:` branch type-checks.

Inside `H3HandlerServer.__init__`, `profile_ptr` is forwarded to `self._h3` per §5.3's chosen shape (A or B).

## 6. Tests (+6, locked at AC#1)

Owning task in parens — T1 owns 4 (record methods + JSON emit), T4 owns 2 (sum invariant + budget closure refresh).

- `test_record_h3_drain_resp_increments_total` (T1) — single-call increment.
- `test_record_quic_post_recv_increments_total` (T1) — same.
- `test_record_h3_dispatch_increments_total` (T1) — same.
- `test_report_json_emits_h3_phases_block` (T1) — round-trip parse the emitted JSON; assert `h3_phases_us.{drain_resp,post_recv,dispatch}.total` keys exist with correct values.
- `test_h3_phase_legs_sum_within_unaccounted_bucket` (T4) — synthetic profile with known `busy_us_total` + per_pkt + drain + loop legs; assert `h3_legs.total ≤ unaccounted_bucket` (catches bracket overlap).
- `test_budget_closure_subtracts_h3_legs` (T4) — synthetic profile; assert `unaccounted_us_total = busy_us_total − Σ(per_pkt) − drain − loop − h3_legs` (bit-exact equality).

## 7. Validation gate composition

**Hard Gate 1 — Long-conn `unaccounted_pct` reduction (primary diagnostic deliverable)**
- Build: `PROFILE_ACCEPT=True`, `ASSERT=none` on-build, freshly rebuilt with tag isolation (`mojo-net-bench:q1-post-on`).
- Capture: n=3 long-conn SIGINT sidecars.
- Threshold: median `unaccounted_pct` **<15%** (down from 82% on current main).
- The dominant of the 3 new legs is named in the REFERENCE.md row + retrospective.
- **Soft floor:** if `unaccounted_pct` lands in [15%, 25%], the dominant phase is still named and the spec ships SHIPPED-with-caveat; a follow-on for sub-bracket decomposition is filed (mirrors sub-leg pass's pre-existing-gap precedent). Hard fail only at >25%.

**Hard Gate 2 — On-build long-conn RPS non-regression**
- Command: `MOJO_NET_IMAGE=mojo-net-bench:q1-post-on bash bench/quic_perf/scripts/bench.sh mojo-net 1k long-conn tquic_client --iters 10`
- Threshold: median drift ≥ −2.0% vs current main `cd12818` on-build baseline (rebuild a `q1-pre-on` image at T0 to anchor).

**Hard Gate 3 — On-build short-conn RPS non-regression**
- Same command/threshold for short-conn.
- Both cells gated since the brackets land in `src/h3/`, on the hot path of every server build.

**Hard Gate 4 — Off-build RPS non-regression both cells**
- `PROFILE_ACCEPT=False`, freshly rebuilt (`mojo-net-bench:q1-{pre,post}-off`).
- Long-conn + short-conn 10-iter, same ≥ −2.0% threshold.
- This is the critical "did we accidentally tax the production hot path?" check. If the new fields cause struct-layout drift even with `@parameter if`-gated brackets compiled out, this catches it.

**Hard Gate 5 — Sub-leg sum invariant**
- For each long-conn sidecar: `h3_drain_resp_us.total + quic_post_recv_us.total + h3_dispatch_us.total` ≤ `busy_us_total − per_pkt_legs.total − drain_us.total − loop_phases.total`.
- Prevents over-count from bracket overlap.

**Hard Gate 6 — `dcid_mismatch_pkts == 0` correctness regression check**
- Both cells, all sidecars. Prevents demux breakage from the `H3HandlerServer` ctor signature change.

## 8. Acceptance criteria

| # | Description | Pass condition |
|---|---|---|
| AC#1 | Unit test count delta = +6 | `TESTS_FILTER=test_quic_profile bash scripts/run_tests.sh` PASS; filtered count = T0 anchor + 6 (T0 captures the anchor at branch creation; T1 + T4 land 4+2 tests respectively). |
| AC#2 | Hard Gate 1: long-conn `unaccounted_pct` < 15% | Median over n=3 sidecars on `mojo-net-bench:q1-post-on`. |
| AC#3 | Hard Gate 2: on-build long-conn drift ≥ −2.0% | n=10 vs `q1-pre-on` baseline. |
| AC#4 | Hard Gate 3: on-build short-conn drift ≥ −2.0% | n=10 vs `q1-pre-on` baseline. |
| AC#5 | Hard Gate 4: off-build drift ≥ −2.0% both cells | n=10 each, vs `q1-pre-off` baseline. |
| AC#6 | Hard Gate 5: sub-leg sum invariant | All n=3 long-conn sidecars satisfy the inequality. |
| AC#7 | Hard Gate 6: `dcid_mismatch_pkts == 0` | All sidecars (n=3 long-conn pre + n=3 long-conn post + n=3 short-conn post). |
| AC#8 | REFERENCE.md entry | Names the dominant long-conn phase + per-leg medians + budget-closure ε before/after. |
| AC#9 | Flag revert | `comptime PROFILE_ACCEPT: Bool = False` post-capture. |

## 9. Open questions / required-later items

| What | Severity | Trigger |
|---|---|---|
| Next opt-spec target = the named dominant phase from this run | required-later (high) | This spec ships; the named winner (predicted: `h3_drain_resp`) becomes the optimisation target. |
| Short-conn `unaccounted_pct` residual | optional | Q3-style soft gate — captured but not gated. If post-Q1 short-conn ε > 5%, file a follow-on. |
| `_quic.timeout` and other early-return paths in `recv_from_buffer` | optional | Subagent B says cheap; trigger if Hard Gate 1 fails to reach <15% AND the 3 named legs cumulatively account for <70% of pre-existing ε. |
| Sub-bracket of `quic_post_recv_us` (split timeout vs _drain_stream vs poll) | optional | Trigger: if `quic_post_recv_us` is the named winner of this run AND its share is comparable to `h3_drain_resp_us` (otherwise drain_resp dominates and is the next target). |

## 10. Risks

- **Off-build codegen drift (AC#5).** Adding `profile_ptr` fields to `H3HandlerServer` and `H3Connection` may change struct layout/alignment. The fields are unconditional (matching `QuicConnection.profile_ptr` precedent at `src/quic/connection.mojo:334` which has shipped on a similar hot path); AC#5 (off-build RPS non-regression ≥ −2.0% both cells) is the empirical guard. **Rollback plan if AC#5 fails:** remove the field entirely and re-route brackets to a different mechanism (e.g., thread-local), not gate the field per-build (Mojo 0.26.2 does not cleanly support `@parameter if`-gated struct fields with layout differing per-build).
- **Bracket overlap.** `_dispatch_h3_events` and `_drain_responses` are sequential within `H3HandlerServer.feed_datagram_from_buffer`, no overlap. `quic_post_recv_us` runs INSIDE `H3Connection.feed_datagram_from_buffer` (which is called by `H3HandlerServer.feed_datagram_from_buffer` BEFORE the dispatch + drain_resp brackets), so all 3 brackets are in disjoint code paths. Hard Gate 5 (sub-leg sum invariant) catches any future regression.
- **Profile_ptr null guard cost.** Each bracket has an `if Int(self.profile_ptr) != 0:` check. On-build (PROFILE_ACCEPT=True) this fires once per `_dispatch_h3_events` + once per `_drain_responses` + once per `_h3.feed_datagram_from_buffer` per packet. At long-conn 14k rps load that is ~42k extra branches/sec — single predictable branch each, negligible CPU share. Off-build (`@parameter if False:`) the entire block elides at compile time.
- **Test count discipline.** AC#1 locks at +6. T1+T4 split (4 tests in T1, 2 in T4) must reconcile to exactly 6 tests; Q3's lesson on test-count drift applies.

## Appendix A — Estimated implementation size

| File | LoC |
|---|---|
| `src/quic/profile.mojo` | +30 (3 fields + 3 methods + emit + budget closure) |
| `src/h3/h3_handler_server.mojo` | +25 (field + ctor + 2 brackets + threading to `_h3`) |
| `src/h3/connection.mojo` | +20 (field + ctor + 1 bracket) |
| `bench/h3_server.mojo` | +5 (ctor call site) |
| `tests/test_quic_profile.mojo` | +50 (6 tests) |
| **Total** | **~130 LoC** |

Estimated tasks (mirrors sub-leg pass shape): T0 hard-gate (parent — branch + pre-spec test count + pre baselines + pre sidecars) → T1 profile.mojo fields+methods+emit (subagent, TDD, 4 tests) → T2 h3_handler_server brackets + ctor threading (subagent) → T3 h3/connection bracket + ctor threading (subagent) → T4 bench/h3_server profile_ptr threading + budget-closure refresh tests (subagent, 2 tests) → T5 on-build smoke gate ±10% (parent) → T6 SIGINT sidecar capture both cells + verify Hard Gates (parent) → T7 REFERENCE.md + flag revert + project-context advance (parent).
