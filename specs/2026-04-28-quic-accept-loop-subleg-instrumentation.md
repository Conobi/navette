# QUIC Accept-Loop Sub-Leg Instrumentation

**Status:** spec
**Date:** 2026-04-28
**Predecessor:** `plans/2026-04-27-quic-addr-key-to-dcid-demux-migration.md` + `plans/2026-04-27-quic-addr-key-to-dcid-demux-migration-retrospective.md` (SHIPPED — 33.6× / 4562× uplift, post-migration mojo-net at 16.2% / 46.8% of tquic_server). The migration spec file lives on the migration's feature branch; this branch (`feat/quic-queueing-tail-instrumentation` baseline) only has the plan + retrospective.

## Goal

Decompose the existing two un-attributed time buckets in `AcceptProfile` so we can name **which rustls FFI call** and **which bench-loop phase** consumes the wall-clock budget on short-conn:

1. **`shim_ffi_us_total`** is currently a single bucket aggregating three distinct rustls FFI call-sites (`quic_conn_read_hs`, `quic_conn_write_hs`, `quic_conn_take_keys`). Today's short-conn capture shows `shim_ffi` at 54μs avg per packet (74% of the per-packet `sm` leg). We cannot tell which of the three calls dominates.
2. **Loop overhead** (the time spent in `_flush_impl` outside the per-pkt processing legs and `record_drain`) is currently un-instrumented. Computed as a residual `busy − Σ(per_pkt_legs) − Σ(drain)`, it accounts for ~26% of busy time on short-conn but we cannot tell which loop phase (demux, post-pkt, teardown) absorbs it.

The output of this work is data — extended sidecar JSON with 6 new sub-legs — and a single hypothesis-pass log entry in `REFERENCE.md` that names the dominant FFI call-site and the dominant loop phase on short-conn. **No fix is in scope.** This spec is diagnostic-only; the optimisation lever it identifies will be the subject of a follow-on spec.

## Background

The post-migration baseline (10-iter median, image rebuilt 2026-04-27 22:24:28):

| Cell | mojo-net | tquic_server | Gap |
|---|---|---|---|
| Long-conn | 14,109 rps | 87,113 rps | 16.2% |
| Short-conn | 1,186 rps | 2,535 rps | 46.8% |

The smaller short-conn gap (47%) suggests handshake throughput is now competitive; the long-conn gap (16%) indicates the steady-state per-packet hot path is the bigger problem. But on short-conn, the existing sidecar (`INSTRUMENTATION-20260427-200716-postmigration-shortconn.json`) shows `shim_ffi: avg=54μs total=9.72s` over a 30s run — the dominant single contributor at ~28% of wall-clock. Per-packet, `shim_ffi` is 90% of the `sm` leg (54μs / 60μs avg). Sub-legging it tells us whether the lever is `read_hs` (consume), `write_hs` (produce), or `take_keys` (key materialisation).

The 26% un-attributed loop overhead is the second-largest opaque bucket. Sub-legging it into `pop_dispatch / post_pkt / teardown` tells us whether to focus optimisation on the demux path (DCID hex encoding + Dict lookup), the post-pkt bookkeeping (handshake polling + addr update), or the per-flush teardown (`pending_rx.clear`).

The migration spec (2026-04-27-quic-addr-key-to-dcid-demux-migration.md) is the immediate predecessor; its retrospective open-question 8 (T0 docker image hygiene) is closed by the docker-image-hygiene memory now active. This spec inherits no other open questions from that pass.

## Architecture

Diagnostic-only extension to `AcceptProfile`. Same comptime-gated pattern as the existing 5-phase profiler — zero hot-path overhead off-build (`PROFILE_ACCEPT: Bool = False`).

Two parallel groups of new sub-legs:

### Group 1 — FFI sub-legs (3 buckets)

Timed at the 3 existing rustls FFI call-sites in `src/quic/connection.mojo`. Each sub-leg accumulates a per-call delta (no per-pkt aggregation; we want totals across the 30s run). The existing `profile_rustls_us_accum` field on `QuicConnection` is preserved for back-compat with `record_pkt(ffi_us=...)` — the new sub-legs are recorded **alongside** the existing accumulator update.

**Single-pair clock-read pattern (mandatory).** To avoid doubling the per-FFI-call clock-read overhead from 2 to 4, each FFI site MUST take exactly ONE `t_start = monotonic_us()` and ONE `t_end = monotonic_us()` and use that single pair for BOTH the existing accumulator update AND the new sub-leg record. Because `var t_start` declared inside one `@parameter if` block is not visible inside a later `@parameter if` block (Mojo lexical block scoping), `t_start` MUST be hoisted to function scope with a zero-init default. The off-build cost of the hoisted `var t_start: UInt64 = 0` is one zero-init stack word per FFI site (DCE-eligible under `-O`); off-build remains effectively free. Concretely:

```mojo
var t_start: UInt64 = 0
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        t_start = monotonic_us()
        self.profile_rustls_us_accum -= t_start
var rc = lib[].quic_conn_read_hs(...)
@parameter
if PROFILE_ACCEPT:
    if Int(self.profile_ptr) != 0:
        var t_end = monotonic_us()
        self.profile_rustls_us_accum += t_end
        self.profile_ptr[].record_ffi_read_hs(t_end - t_start)
```

Total clock reads per FFI call: 2 (unchanged from existing). Implementations MUST NOT introduce a second timing pair.

**Lifetime accumulation (mandatory).** All 3 new `ffi_*_us_total` fields accumulate for the entire process lifetime. There is NO per-packet reset (unlike `profile_rustls_us_accum`, which is reset to 0 at the start of every `recv_from_buffer`). The cross-validation invariant relies on `Σ` totals, not per-pkt deltas.

| Field (new) | Wraps | Fires when | Predicted share (short-conn) |
|---|---|---|---|
| `ffi_read_hs_us_total: UInt64` | `lib[].quic_conn_read_hs(...)` | Server consumes incoming CRYPTO bytes; rustls advances TLS state. | ~25% (small ClientHello + Finished inputs) |
| `ffi_write_hs_us_total: UInt64` | `lib[].quic_conn_write_hs(...)` | Server emits outgoing CRYPTO bytes; loops, may fire 2-3× per packet during handshake. | ≥60% (ServerHello + Certificate + Finished are large outputs) |
| `ffi_take_keys_us_total: UInt64` | `lib[].quic_conn_take_keys(...)` | Materialises new key set after kc=1 (Handshake) or kc=2 (1-RTT) signal. ~2× per successful handshake. | ~10-15% |

Cross-validation invariant: `ffi_read_hs_us_total + ffi_write_hs_us_total + ffi_take_keys_us_total` MUST equal `ffi_shim_us_total` within ±1% across a 30s capture. The existing `ffi_shim_us_total` field is preserved unchanged; the sum-vs-parent check is the correctness gate for the wiring.

### Group 2 — Loop phase legs (3 buckets)

Timed at 3 phase boundaries in `bench/h3_server.mojo`'s `_flush_impl`. The for-loop body has 3 zones outside the per-pkt timer (which lives in `connection.mojo`'s `feed_datagram_from_buffer`):

```
for pd in pending_rx:
    [PHASE A: pop_dispatch]
    | record_arrival_lat / record_conn_pkt
    | _bytes_to_hex(dcid)
    | _find_conn_by_dcid + Strict gate
    | conn-create cold path (rare — once per new conn)
    | dual-DCID map insert (rare)
    [/PHASE A]
    
    feed_datagram_from_buffer  ← timed by record_pkt's per-pkt legs
    
    [PHASE B: post_pkt]
    | is_established() poll + record_conn_hs_complete
    | addr_update build + assignment
    [/PHASE B]
    
    _drain_and_send             ← timed by record_drain
    consumed_bufs.append

[PHASE C: teardown]
| pending_rx.clear()
[/PHASE C]
record_flush                    ← bookkeeping (not timed)
```

| Field (new) | Cadence | Covers |
|---|---|---|
| `loop_pop_dispatch_us_total: UInt64` | per-pkt | Phase A: from start-of-iter through demux + cold conn-create. **Excludes** `feed_datagram_from_buffer`. Recorded on EVERY iter, including iters that hit a `continue` early (Strict-gate skip at line 748, QuicConnection.server failure at 793, H3HandlerServer ctor failure at 817) — the time spent demuxing those iters is real loop work and must be counted. |
| `loop_post_pkt_us_total: UInt64` | per-pkt | Phase B: from after `feed_datagram_from_buffer` through `is_established` poll + `addr_update`. **Excludes** `_drain_and_send`. NOT recorded on iters that `continue`'d before reaching `feed_datagram_from_buffer`. |
| `loop_teardown_us_total: UInt64` | per-flush single-shot | Phase C: brackets `[after-for-loop-end .. just-before-t_busy_end]`. Captures `pending_rx.clear()` cost. **Explicitly excludes** the `record_flush` call itself and the `_profile_dump_pending` SIGINT-only block at lines 886-907 (one-shot at run end; not a steady-state cost). The cost of `record_flush` will land in the `unaccounted_us_total` residual ε; expected to be a few hundred ns per flush, well under the 2% gate. |

**Loop-phase avg divisor.** `loop_pop_dispatch.avg` and `loop_post_pkt.avg` are computed in `report_text` / `report_json` as `total_us / Σ(len(pending_rx))`-summed-across-flushes — i.e. divided by the count of for-loop iters actually executed, NOT by `pkt_count` (which excludes `continue`'d iters). To make this divisor available at report time, the spec adds one helper field: `loop_iter_count: UInt64`, incremented once per for-loop iter inside the for-loop body (gated by `@parameter if PROFILE_ACCEPT:`, recorded BEFORE any `continue`). `loop_teardown.avg` is `total_us / on_flush_count`.

Together with existing legs, the budget closure invariant is:

```
busy_us_total
  = Σ(per_pkt_us)              ← already accounted via record_pkt
  + Σ(drain_us)                ← already accounted via record_drain
  + Σ(loop_pop_dispatch_us)    ← new
  + Σ(loop_post_pkt_us)        ← new
  + Σ(loop_teardown_us)        ← new
  + ε                          ← unaccounted instrumentation overhead, expected <2%
```

`ε` is computed at report time and emitted as `loop_unaccounted_us_total` in the JSON sidecar. If `ε > 2%` of `busy_us_total`, the wiring has a gap (likely a missed phase boundary) — same correctness pattern as the FFI sub-leg sum check.

### Sidecar JSON additions

In `report_text` and `report_json`, six new fields plus two derived budget-closure fields. Sample output shape (numbers below are **illustrative only** — they are NOT predictions; actual values from post-impl captures must satisfy AC#5's `unaccounted_pct < 2`):

```json
"per_pkt_us": {
  ...existing legs...
  "shim_ffi": {"avg": 54, "total": 9720170},   ← preserved unchanged
},
"ffi_subleg_us": {
  "read_hs":   {"avg": 15, "total": 2728048},   ← new (avg = total / pkt_count)
  "write_hs":  {"avg": 33, "total": 5841912},
  "take_keys": {"avg":  6, "total": 1150210}
},
"loop_phases_us": {
  "pop_dispatch": {"avg": 12, "total": 2125560},   ← new (avg = total / loop_iter_count)
  "post_pkt":     {"avg":  4, "total":  708820},   ← new (avg = total / loop_iter_count)
  "teardown":     {"avg":  3, "total":   59288},   ← new (avg = total / on_flush_count)
  "loop_iter_count": 177205,                       ← new (helper for divisor)
  "unaccounted_us_total":  213340,                 ← new (derived; ε in budget closure)
  "unaccounted_pct":       0                       ← new (derived; ε * 100 / busy, integer-truncated)
}
```

`report_text` mirrors with human-readable lines under two new sections: `FFI sub-legs:` and `Loop phases:`.

## File structure

| Path | Action | Single responsibility |
|---|---|---|
| `src/quic/profile.mojo` | modify | Add 6 new `*_us_total` fields + 1 helper `loop_iter_count: UInt64` + 6 `record_*` methods (3 FFI + 3 loop) + 1 helper `record_loop_iter()` (increments `loop_iter_count`). Update `report_text` with new sections. Update `report_json` with `ffi_subleg_us` and `loop_phases_us` blocks + derived `unaccounted_us_total` / `unaccounted_pct`. Preserve `ffi_shim_us_total` unchanged. |
| `src/quic/connection.mojo` | modify | At lines 1591-1603, 1620-1634, 1665-1675: per the single-pair clock-read pattern in §Architecture, declare `var t_start = monotonic_us()` and `var t_end = monotonic_us()` ONCE per FFI call inside the existing `@parameter\nif PROFILE_ACCEPT:` / `if Int(self.profile_ptr) != 0:` branch; use those for BOTH the existing `profile_rustls_us_accum -= t_start; ... profile_rustls_us_accum += t_end` AND the new `profile_ptr[].record_ffi_<name>(t_end - t_start)`. NO second timing pair. |
| `bench/h3_server.mojo` | modify | In `_flush_impl` at lines 722-836 (PHASE A): inside the for-loop body, BEFORE any `continue`-eligible work, declare `var t_pop_dispatch_start: UInt64 = 0` (function-scope-style hoist with off-build zero-init), set it to `profile_monotonic_us()` inside `@parameter if PROFILE_ACCEPT:`, AND call `self.profile.record_loop_iter()`; at the end of demux/conn-create (just before `feed_datagram_from_buffer` at line 840), call `record_loop_pop_dispatch(profile_monotonic_us() - t_pop_dispatch_start)`. PHASE A's recording site is duplicated immediately before EACH `continue` statement (lines 748, 793, 817) so dropped iters still record their pop_dispatch cost. At lines 846-859 (PHASE B): bracket the post-pkt bookkeeping with `t_post_pkt_start` / `record_loop_post_pkt(...)`. At line 878 (just AFTER `self.pending_rx.clear()`): declare `t_teardown_start = profile_monotonic_us()` BEFORE the clear, and at line 881 (just BEFORE `t_busy_end = profile_monotonic_us()`), call `record_loop_teardown(profile_monotonic_us() - t_teardown_start)`. All gated by `@parameter\nif PROFILE_ACCEPT:` (decorator on its own line). |
| `tests/test_quic_profile.mojo` | modify | Add 6 record-method tests + 1 ffi_subleg-sum check + 2 budget-closure checks (zero residual + nonzero residual) + 2 JSON-shape tests + 1 divisor-locking test. Total: 12 new tests. |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-longconn-subleg.json` | create | Sidecar capture from long-conn cell after rebuild. |
| `bench/quic_perf/results/profile/INSTRUMENTATION-<ts>-postmigration-shortconn-subleg.json` | create | Sidecar capture from short-conn cell after rebuild. |
| `bench/quic_perf/results/REFERENCE.md` | append | Sub-leg-pass entry tabulating short-conn vs long-conn sub-leg shares + identifying the dominant FFI call-site and the dominant loop phase. |

No new files in `src/`. No `bench/quic_perf/scripts/` changes (capture uses the existing SIGINT sidecar pattern).

## Testing

### Unit tests (`tests/test_quic_profile.mojo`)

- `test_record_ffi_read_hs_increments_total` — call `record_ffi_read_hs(100us)` × 3; verify `ffi_read_hs_us_total == 300`.
- `test_record_ffi_write_hs_increments_total` — analogous for write_hs.
- `test_record_ffi_take_keys_increments_total` — analogous for take_keys.
- `test_record_loop_pop_dispatch_increments_total` — analogous for pop_dispatch.
- `test_record_loop_post_pkt_increments_total` — analogous for post_pkt.
- `test_record_loop_teardown_increments_total` — analogous for teardown.
- `test_ffi_subleg_sum_matches_shim_ffi_within_tolerance` — populate `ffi_shim_us_total` via `record_pkt(ffi_us=...)` AND the 3 sub-legs via `record_ffi_*` with the same values; assert `abs((read_hs + write_hs + take_keys) - shim_ffi) <= max(shim_ffi // 100, 1)` (±1% tolerance + at-least-1us slack for tiny totals).
- `test_loop_budget_closure_zero_residual` — populate `busy_us_total`, all per_pkt legs, drain, and the 3 loop legs with explicit values that sum exactly; assert `unaccounted_us_total == 0` and `unaccounted_pct == 0`.
- `test_loop_budget_closure_nonzero_residual` — populate values where the sum is short by 100us against `busy_us_total = 10000`; assert `unaccounted_us_total == 100` and `unaccounted_pct == 1` (integer-truncated).
- `test_report_json_emits_ffi_subleg_block` — call `report_json()`, parse with python `json.loads`, assert presence and shape of `ffi_subleg_us` block (3 keys, each with `avg` and `total`).
- `test_report_json_emits_loop_phases_block` — analogous for `loop_phases_us` (5 keys: pop_dispatch + post_pkt + teardown + loop_iter_count + unaccounted_us_total + unaccounted_pct).
- `test_loop_phase_avg_uses_loop_iter_count_divisor` — populate `loop_pop_dispatch_us_total = 10000`, `loop_iter_count = 100`, `pkt_count = 50`; assert `report_json()` emits `pop_dispatch.avg == 100` (10000/100), NOT 200 (10000/50). Locks the divisor choice against accidental refactor.

### Integration

No new integration tests beyond the `_flush_impl` wiring exercised by existing bench loopback runs. The bench captures themselves serve as the integration check (sub-leg totals must reconcile against the existing `shim_ffi` and `busy_us` totals — both invariants are emitted in the same JSON).

## Acceptance criteria

1. **Test count.** `bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'` increases by exactly 12 (the 12 new unit tests above) vs the pre-spec anchor.
2. **Off-build smoke gate.** With `PROFILE_ACCEPT = False`, `bench.sh mojo-net 1k <cell> tquic_client --iters 10` median rps must be within ±10% of the post-migration off-build baseline (long-conn 14,436 rps; short-conn 1,208 rps). Hard gate.
3. **On-build drift gate.** With `PROFILE_ACCEPT = True`, `--iters 10` median for both cells must be within ±10% of the post-migration on-build baseline (long-conn 14,109 rps; short-conn 1,186 rps). The single-pair clock-read pattern keeps total reads at 2 per FFI call (unchanged). New per-pkt loop-phase reads: 4 (2 for pop_dispatch + 2 for post_pkt) × ~6M pkts/30s × ~50ns = ~1.2s of added clock cost over 30s; within the gate, but worth verifying empirically. New per-flush reads: 2 (teardown) × on_flush_count ~17k = ~1.7ms — negligible.
4. **Sub-leg sum invariant (per capture).** In each of the two SIGINT sidecar JSONs, `ffi_subleg_us.read_hs.total + write_hs.total + take_keys.total` must equal `per_pkt_us.shim_ffi.total` within ±1%. If not, wiring has a gap.
5. **Budget closure invariant (per capture).** `loop_phases_us.unaccounted_pct < 2` in each of the two SIGINT sidecar JSONs. If not, a phase boundary is missed.
6. **dcid_mismatch_pkts == 0** in both captures (regression check inherited from the migration spec; this spec's instrumentation must not break the demux invariant).
7. **REFERENCE.md entry** identifies (a) the dominant FFI sub-leg on short-conn (the single sub-leg with the highest share of `shim_ffi_us_total`) and (b) the dominant loop phase on short-conn (the single phase with the highest share of `busy_us_total`). Verdict-grade — these two names will gate the next optimisation spec.

## Constraints

- **Mojo 0.26.2 branch-elision syntax.** Use `@parameter\nif PROFILE_ACCEPT:` — the `@parameter` decorator on its OWN line, immediately above the `if`. The codebase has not migrated to the newer `comptime if PROFILE_ACCEPT:` form yet (which IS valid in 0.26.2 and is in fact the non-deprecated form); for consistency with the surrounding instrumentation in `connection.mojo:1591-1675` and `bench/h3_server.mojo:710-907`, this spec sticks with `@parameter\nif`. A future codebase-wide migration sweep can flip both styles in one pass; mixing within a single hot path is out of scope here. New `record_*` methods follow the existing pattern (immediate-return increment of a `UInt64` field; no `def` overhead — these are hot-ish during on-build runs).
- **`profile_ptr` null-check.** Every new FFI sub-leg recording site in `connection.mojo` MUST mirror the existing guard: `@parameter\nif PROFILE_ACCEPT:\n    if Int(self.profile_ptr) != 0:`. The runtime null-check is mandatory because `profile_ptr` is set after `QuicConnection.__init__` and may be null during early-construction code paths.
- **No alias usage.** Per Mojo 0.26.2 deprecation, use `comptime` for module-scope constants (already in use throughout `profile.mojo`).
- **No string-key Dicts in hot path.** None of the new instrumentation introduces a Dict; all 6 new fields are flat `UInt64` totals. The existing per-conn `Dict[String, UInt64]` is unchanged.
- **No `record_pkt(ffi_us=...)` signature change.** Existing callers in `bench/h3_server.mojo:890` continue to pass `ffi_us=self.profile_rustls_us_accum`. The new sub-legs are recorded **in addition**, not in replacement.
- **Capture protocol.** The on-build docker image MUST be rebuilt fresh after toggling `PROFILE_ACCEPT = True` in source (per `feedback_bench_offbuild_image_hygiene.md`). The off-build baselines for the smoke gate use the existing image at `3e5facff7e72` (post-migration off-build, captured 2026-04-27 22:24:28); if that image is no longer present locally, T0 must rebuild it first with `PROFILE_ACCEPT = False` compiled in.
- **10-iter cells.** All smoke-gate measurements use `--iters 10` and report median + IQR + stdev (per `feedback_bench_iter_count.md`). Sidecar SIGINT capture is 1 iter per cell (acceptable for sidecar — internal counters aggregate across the full 30s).

## Non-goals

- **No fix.** Naming the dominant sub-leg authorises a follow-on spec; that spec is out of scope here.
- **No FFI-level changes.** rustls call signatures, `_WRITE_HS_BUF_SIZE`, key-handle allocation pattern — all out of scope.
- **No removal of `profile_rustls_us_accum`** or the `record_pkt(ffi_us=...)` parameter. The existing per-pkt FFI aggregation is preserved.
- **No splitting of `ffi_write_hs` per kc transition.** Even if the predicted ≥60% share holds, splitting per-kc would require new instrumentation inside the existing while-loop in `connection.mojo:1616-1698` — out of scope.
- **No new bench cells.** The 2-cell smoke gate (long + short) mirrors the prior counter and migration passes.
- **No changes to the existing 5-phase profiler.** `record_pkt`'s per-pkt legs (header_parse, hp, aead, frame_parse, sm, residual) are preserved unchanged.

## Open questions deferred to plan

| Question | Severity | Trigger |
|---|---|---|
| Should `ffi_is_handshaking` (per-pkt poll of `lib[].quic_conn_is_handshaking` in `connection.mojo:1705`) be added as a 4th FFI sub-leg? Distinct from the `is_established()` Mojo-side check at `bench/h3_server.mojo:852` (which reads a Mojo bitflag without an FFI call). | optional | If post-impl `loop_post_pkt` is >5% of `busy_us_total` on **long-conn**, fold a 4th FFI sub-leg in via a follow-up — long-conn polls is_established repeatedly without entering FFI for handshake state-machine work, so a non-trivial post_pkt share there would likely point at the FFI poll. |
| Should `loop_pop_dispatch` further split into demux-cost vs cold-conn-create cost? | optional | If post-impl `loop_pop_dispatch` is >10% of `busy_us_total` on **short-conn**, the cold conn-create path (rare on long-conn, ~1× per new handshake on short-conn) deserves its own sub-leg. |
| Should the spec add a per-flush `loop_unaccounted_us_buckets` histogram (24-bucket) instead of a single `unaccounted_pct`? | required-later | If the budget closure ε is non-zero AND non-uniform across captures (e.g. ε = 1% on long-conn, ε = 5% on short-conn), the residual is not a single hidden phase but a tail-distribution. A histogram tells us so. Trigger: any future spec where ε > 2% in one cell. |
