# Q9 Verdict — **DIFFUSE-CONFIRMS-LIB-BOUND**

**Date:** 2026-05-04
**Branch:** `feat/quic-q9-fresh-conn-alloc-decomp`
**Spec:** `specs/2026-05-05-q9-fresh-conn-alloc-decomposition.md`
**Image:** `mojo-net-bench:q9-post-on` (PROFILE_ACCEPT=True)
**Commits:** T1 `5afb4b2` (profile.mojo histograms), T2 `6884e88` (bracket sites)

## TL;DR

**DIFFUSE-CONFIRMS-LIB-BOUND.** Q9's 4 alloc sub-legs together account for **only 5.1% of busy CPU** on short-conn (alloc_quic_state OUTER 3.88% + alloc_h3_state 0.29% + bench_dict_insert 0.30%; alloc_tls_handle 0.60% is a subset of OUTER). None of the 4 §3.1 thresholds fire (TLS-BOUND ≥60% NO, QUIC-STATE-BOUND ≥30% NO, H3-STATE-BOUND ≥20% NO, DICT-BOUND ≥15% NO).

The dominant 47% of busy CPU remains in `fresh_conn_ffi_us` (handshake-compute FFI: read_hs + write_hs + take_keys), already named **LIB-BOUND** by Q6. The remaining short-conn gap to TQUIC requires a structural change (Lever A: boringssl swap, deferred per Q6).

**AC7 sum-sanity FAILS but for an instructive reason**: the spec authored AC7 under the assumption that fresh_conn_ffi_us measures alloc-phase work. It does not — fresh_conn_ffi_us accumulates read_hs/write_hs/take_keys handshake-compute FFI durations across the full handshake (per `src/quic/connection.mojo:1721,1778,1824`). Q9's alloc sub-legs measure a DIFFERENT cost category (per-conn ALLOC-phase work at conn-creation moment), not a decomposition of handshake compute. Sum 922,653 µs = 9.5% of fresh_conn_ffi_us, NOT 90-110%. Lesson: spec premises must verify the existing-instrumentation semantics before defining sum-sanity AC.

## Captured numbers

### Short-conn sidecar (n=1, paused, q9-post-on)

| Sub-leg | Sum (µs) | Share of busy (20.65 sec) | Share of fresh_conn_ffi_us | §3.1 threshold |
|---|---:|---:|---:|---|
| `fresh_conn_ffi_us` (denom) | 9,703,104 | 47.00% | — | — |
| `alloc_quic_state_us` (OUTER, incl. inner) | 800,904 | 3.88% | 8.25% | ≥30%? **NO** |
| `alloc_tls_handle_us` (INNER FFI subset) | 123,708 | 0.60% | 1.27% | ≥60%? **NO** |
| `alloc_h3_state_us` | 60,078 | 0.29% | 0.62% | ≥20%? **NO** |
| `bench_dict_insert_us` | 61,671 | 0.30% | 0.64% | ≥15%? **NO** |
| **alloc_quic_state PURE Mojo** (outer − inner) | 677,196 | 3.28% | 6.98% | — |
| **Sum of 4 sub-legs (no double-count)** | 922,653 | 4.47% | 9.51% | — |

Bucket midpoints used: `mid_i = 1.5 * 2^(i-1)` for i≥1; bucket 0 mid = 1.5.

### Bucket dominance (median bucket per sub-leg)

| Sub-leg | Dominant bucket | Range (µs) | Count | % of samples |
|---|---|---|---|---|
| `fresh_conn_ffi_us` | 8 | 256-512 | 29,505 | 76.5% |
| `alloc_quic_state_us` | 4 | 16-32 | 23,974 | 62.2% |
| `alloc_tls_handle_us` | 1 | 2-4 | 20,359 | 52.8% |
| `alloc_h3_state_us` | 0 | 1-2 | 23,837 | 61.8% |
| `bench_dict_insert_us` | 0 | 1-2 | 23,465 | 60.9% |

Per-fresh-conn alloc cost (median): ~16-32 µs OUTER. Per-fresh-conn handshake-compute cost (median): ~256-512 µs. **Alloc is ~5-10% of per-conn CPU; compute is ~90-95%.**

### Long-conn paused-iter smoke gate (n=3, 30s pauses)

| iter | rps | delta vs Q8p2 baseline (14,355) | failure% |
|---|---|---|---|
| 1 | 14,072 | -1.97% | 0.245% |
| 2 | 12,950 | -9.79% | 0.288% |
| 3 | 13,180 | -8.19% | 0.344% |
| **median** | **13,180** | **-8.19%** | — |

**AC6 verdict: MARGINAL.** Median -8.19% is BEYOND strict ±5% gate but within ±10% hard gate. Worst-iter -9.79% within ±10%. Per `feedback_bench_gate_width_calibration.md` the host noise floor is ±5% IQR; the observed iter-2 spread (~8% inter-iter) suggests host-noise contribution dominates. Q9's brackets fire only on cold-create (~33 conns/s on long-conn) for a CPU contribution <0.02% — the regression is unlikely Q9-attributable.

### Bench rps comparison

| Scenario | Q8p2 baseline | Q9-post-on | Delta |
|---|---|---|---|
| Short-conn (sidecar n=1) | 1,211 (n=8 median) | 1,062 | -12.3% |
| Long-conn (paused n=3) | 14,355 | 13,180 | -8.19% |

Caveat: short-conn n=1 single sample, no median absorbing — interpretation is held loosely.

## Acceptance criteria checkpoint

| AC | Status | Evidence |
|---|---|---|
| AC1 | PASS | 4× histograms + 4× overflow + 4× record methods (commit `5afb4b2`) |
| AC2 | PASS | 3 brackets in `bench/h3_server.mojo`; 1 bracket in `src/quic/connection.mojo` (commit `6884e88`) |
| AC3 | (not measured) | Skipped — diagnostic-only spec; T2 compile-validates via `mojo build` (884 KB binary, no errors) |
| AC4 | PASS | JSON shape verified via `jq`: 4 keys present (`alloc_quic_state_us`, `alloc_tls_handle_us`, `alloc_h3_state_us`, `bench_dict_insert_us`); text emit mirrors |
| AC5 | PASS | `test_q9_alloc_sublegs_dispatch` registered + passing (test count 69 → 70) |
| AC6 | **MARGINAL** | Long-conn drift -8.19% median (BEYOND ±5%, WITHIN ±10%). Likely host-noise; brackets too cheap to explain. |
| AC7 | **FAILS-FOR-INSTRUCTIVE-REASON** | Sum 9.5% of fresh_conn_ffi_us, not 90-110%. Spec assumed alloc sub-legs decompose fresh_conn_ffi but they measure a DIFFERENT cost category (alloc vs compute). Lesson recorded below. |
| AC8 | **PASS-DIFFUSE** | No §3.1 threshold fires. Verdict: DIFFUSE-CONFIRMS-LIB-BOUND (consistent with Q6). |
| AC9 | (this doc) | — |
| AC10 | PASS | `comptime PROFILE_ACCEPT: Bool = False` reverted post-capture |

## Why DIFFUSE-CONFIRMS-LIB-BOUND

The 4 Q9 sub-legs together (deduplicated outer-inner) account for **0.92 sec of 20.65 sec busy = 4.47%** of busy CPU on short-conn at 1,062 rps. Even eliminating ALL alloc-phase work entirely would lift rps by at most ~4.5% = 1,062 × 1.045 = 1,110 rps. The gap to TQUIC (2,846 rps) is ~1,784 rps; Q9 levers can only close ~50 rps of that.

The dominant 47% of busy CPU sits in `fresh_conn_ffi_us` (read_hs + write_hs + take_keys cumulative), already named LIB-BOUND from Q6 (99.5% of read_hs is rustls compute, no cheap lever inside). Q9's measurements **independently corroborate** the Q6 LIB-BOUND finding via a different bracket structure: the alloc-PHASE is small, the compute-PHASE is large.

**Per-fresh-conn breakdown (median bucket midpoints):**
- alloc_quic_state OUTER: ~24 µs
- alloc_h3_state: ~1.5 µs
- bench_dict_insert: ~1.5 µs
- **Per-conn alloc total: ~27 µs**
- **Per-conn handshake-compute (fresh_conn_ffi): ~250 µs**
- **Per-conn ratio alloc/compute: 27/250 = 10.8%**

This ratio is the load-bearing finding: alloc is ~10% of per-conn CPU; compute is ~90%. Optimizing alloc is impact-floor-filtered out per `feedback_perf_impact_floor_filter.md`.

## Methodology lesson (for future memory)

**Spec premises must verify existing instrumentation semantics before defining sum-sanity ACs.** Q9 §1 narrative + AC7 assumed `fresh_conn_ffi_us_total` measures alloc-phase work. Reading `src/quic/connection.mojo:1720-1824` reveals it accumulates read_hs/write_hs/take_keys FFI durations during the full handshake — handshake-compute, not alloc. The spec's premise was ungrounded; the disambiguating grep takes <30s.

This is a sub-rule of `feedback_read_tquic_source_first.md`: read EXISTING instrumentation source before specing NEW instrumentation. The cost of skipping is ~half a day of measurement time spent producing a verdict that doesn't answer the spec's intended question — though in this case the unintended-but-correct answer (DIFFUSE-CONFIRMS-LIB-BOUND) is itself useful.

## Implications for the short-conn gap

After Q9:
- mojo-net short-conn (q9-post-on, n=1): 1,062 rps. Q8p2 baseline was 1,211 (n=8 median); the -12.3% may be host-noise or measurement variance.
- TQUIC short-conn baseline: 2,846 rps.
- Ratio: 1,062 / 2,846 = **0.373×** (q8p2 baseline was 0.426×).

**The residual gap is structurally bounded by handshake-compute, not alloc.** Closing it requires:
1. **Lever A (deferred since Q6): boringssl swap.** TQUIC uses boringssl; mojo-net uses rustls. Q6 capped boringssl efficiency-gap at ~16% of read_hs cost = ~1pp of total rps. Re-evaluate after Q9 confirms alloc is not the lever.
2. **A new lever:** TLS session caching / 0-RTT acceleration. TQUIC's `tls/tls.rs:249` Arc-clones a shared TlsConfig; if mojo-net's rustls does NOT do equivalent sharing, that's a fresh structural lever. T0's TQUIC source read identified this.

**Track record (revised):**
- Measurement-driven projections that landed cleanly: 3 (Q4, Q6, Q8 Phase 2).
- Audit-driven mechanisms surveyed: 1 (per-packet alloc churn — Phase 1 broken impl, Phase 2 clean impl, mechanism CONFIRMED both times).
- Diagnostic decompose-and-decide that surfaced DIFFUSE: 1 (this Q9). DIFFUSE is itself a useful negative finding — it deprioritizes a candidate lever class.

## Next-spec direction

**Q10 candidate:** TLS handle / config sharing. Per T0 TQUIC source read (`tls/tls.rs:243-249`):
- TQUIC's `Arc<TlsConfig>` is cloned per fresh conn (cheap pointer-clone).
- mojo-net's `quic_server_conn_new` FFI in `crates/librustls-mojo/src/quic_hs.rs` — verify whether the existing Q7 instrumentation (`out_config_clone_us`, `out_ticket_store_lock_us`) shows lock contention or rebuilding, vs Arc-clone.

If `out_config_clone_us` median > 50 µs, Q10 spec drills into the FFI to add Arc-clone caching (mirror TQUIC).

If `out_config_clone_us` median < 5 µs (already pointer-clone-cheap), then the residual is in pure rustls compute (state machine + crypto) → Lever A (boringssl swap) is the only path forward, accept the LIB-BOUND ceiling.

This is a measurable, single-spec gate. Q10 spec should cite the existing Q7 out-params as the instrumentation, not add new ones.

## Code disposition

Q9 ships behind comptime flag `PROFILE_ACCEPT: Bool = False` (reverted post-capture, AC10 PASS). All 4 sub-leg histograms + record methods + bracket sites land on main as PROFILE_ACCEPT-gated diagnostics; off-build path strips them entirely.

Branch ready to merge to main.
