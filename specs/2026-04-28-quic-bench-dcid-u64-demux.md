# QUIC bench DCID demux: `Dict[String, Int]` → `Dict[UInt64, Int]`

**Date:** 2026-04-28
**Origin:** Q3 follow-on from `plans/2026-04-28-quic-accept-loop-subleg-instrumentation-retrospective.md`
**Predecessor research:**
- `research/2026-04-28-pop-dispatch-finer-split.md` (cost attribution; sub-agent C scoping)
- `research/2026-04-28-q3-codebase-verification.md` (line numbers stable post-Sprint-2; blast radius = 1 file, ~50 LoC, 0 test migrations)
- `research/2026-04-28-q3-mojo-dict-internals.md` (Mojo Dict = SwissTable + AHash; UInt64 lookups ≈ 4× faster than 16-char String; slot 1.67× smaller)
- `research/2026-04-28-q3-reference-stacks-cid-keys.md` (every production stack uses byte-keyed maps; no stack uses hex-string)
- `research/2026-04-28-q3-bench-gate-design.md` (sub-leg observed-drop is the only feasible gate at the conservative effect size)

---

## 1. Goal

Replace the bench-server's per-connection DCID demux table in `bench/h3_server.mojo` from `Dict[String, Int]` (16-char hex-string keyed) to `Dict[UInt64, Int]` (packed-u64 keyed) via a new `_dcid_to_u64` helper, eliminating per-packet hex-encode + String-hash overhead on the hot path.

**Predicted impact** (synthesised from Topic 2 microbench + Topic 4 cost attribution):
- `loop_pop_dispatch.total` drops by **≥8%** (≈77 ms / 30 s) on short-conn — directly observable.
- Short-conn RPS lift: **0.5–1.4% conservative** (sits at noise floor for n=10; reported but not gated).
- Long-conn impact: negligible (<10 entries; perpetually L1-hot pre-migration).

## 2. Why this exists / why now

The just-shipped sub-leg instrumentation pass (`488f113`) named `loop_pop_dispatch` as the dominant non-FFI loop phase on short-conn (5.9% of `busy_us_total`). Sub-agent C decomposed pop_dispatch and identified the `_bytes_to_hex` + `Dict[String, Int]` pair as the single biggest microoptimisable chunk inside it (8–22% of pop_dispatch ≈ 0.5–1.4% RPS uplift).

The 8-byte SCID invariant locked by the addr_key→DCID demux migration (`test_quic_connection_dcid_lengths_are_8_bytes`, `debug_assert(len == 8)` at conn-create) is the precondition that authorises packing into `UInt64`. No production stack does this because they all support variable-length CIDs up to 20 bytes; mojo-net's bench-side fixed-8-byte invariant is what enables the more aggressive design. Migration moves the codebase **toward** prior art — every surveyed stack (TQUIC, quiche, lsquic, quic-go, aioquic) uses byte-keyed maps; the current `Dict[String, Int]` (hex-string) is the outlier.

## 3. Scope

**In scope:**
- `bench/h3_server.mojo`: type migration of `conn_dcid_map` and `conn_dcids`; new `_dcid_to_u64` helper; replacement of `_bytes_to_hex` calls at the 3 hot-path sites (~line 742) and the 2 cold-create sites (~lines 816–817).
- `tests/`: 1 new unit test file or 1 new test fn in an existing file locking `_dcid_to_u64` semantics (5+ cases).
- Bench gate captures (long-conn RPS + short-conn sub-leg sidecars).
- `bench/quic_perf/results/REFERENCE.md` entry.

**Out of scope (explicit non-goals):**
- Touching `src/quic/`, `src/h3/`, or `src/tls/` — `_dcid_to_u64` is bench-local.
- Migrating the addr_key map or any other String-keyed structure (different ownership, different invariants).
- Lifting the 8-byte SCID invariant (a future spec if/when needed).
- Reporting-path changes — `profile.mojo` text/JSON sidecar formats are unchanged.
- Deletion of `_bytes_to_hex`. The helper is retained for any future debug rendering; per research §2 (codebase-verification report), grep across the entire repo (not just `bench/`) confirms `_bytes_to_hex` has no callers outside `bench/h3_server.mojo`, and all in-file callers go to zero post-migration. A source-level comment is added at the helper's definition: `# unused post-2026-04-28-quic-bench-dcid-u64-demux; retained for ad-hoc debug rendering — do not delete without re-grepping across the repo` so a future code-cleanup pass does not remove it inadvertently.

## 4. Design decisions (validated 2026-04-28)

| # | Decision | Rationale |
|---|---|---|
| D1 | Hot-path + cold-create migrated together | Single coherent commit; both call sites are on the same code path; splitting would keep `_bytes_to_hex` live for one PR cycle for no gain. |
| D2 | `_dcid_to_u64` = 8-iter shift loop (`(result << 8) \| UInt64(bytes[i])`) | ~20 ns; portable; no UnsafePointer cast; no endianness contract. Cost negligible vs the 18 ns/lookup savings. |
| D3 | Sub-leg observed-drop is the primary gate | RPS lift at conservative 0.5–1.4% sits below the n=10 noise floor (σ≈1.7–2.2% short-conn). The just-shipped sub-leg instrumentation lets us measure `loop_pop_dispatch.total` directly. |
| D4 | `_bytes_to_hex` retained as off-hot-path utility | Keeping it costs nothing and preserves debug ergonomics. Only used at hot-path/cold-create sites pre-migration; both go to zero post-migration. |

## 5. File-level change list

**`bench/h3_server.mojo`** (only file touched):

1. **Add helper** — declared near `_bytes_to_hex` (around line 164 in the helpers block):
    ```mojo
    fn _dcid_to_u64(bytes: Span[UInt8, _]) -> UInt64:
        debug_assert(len(bytes) == 8, "DCID must be 8 bytes")
        var result: UInt64 = 0
        for i in range(8):
            result = (result << 8) | UInt64(bytes[i])
        return result
    ```
    Note: `debug_assert` is gated by Mojo's `ASSERT` mode. Bench docker images (both pre- and post-migration) MUST be built with `ASSERT=none` for the on-build measurement runs so the assert is compiled out and the timed hot-path matches the predicted ~20 ns shift loop. AC#3 sidecar captures use this same build configuration.
2. **Field type changes** (in `H3UdpHandler`):
    - `conn_dcid_map: Dict[String, Int]` → `Dict[UInt64, Int]`
    - `conn_dcids: List[List[String]]` → `List[List[UInt64]]`
3. **Hot path** — `_flush_impl` per-packet lookup site (~line 742):
    ```mojo
    # before:
    # var key = _bytes_to_hex(Span(pd.dcid))
    # after:
    var dcid_u64 = _dcid_to_u64(Span(pd.dcid))
    var slot = self._find_conn_by_dcid(dcid_u64)
    ```
4. **Cold conn-create** (~lines 813–850):
    ```mojo
    # before:
    # var icid_hex = _bytes_to_hex(quic.initial_dcid)
    # var lcid_hex = _bytes_to_hex(quic.local_cid)
    # after:
    debug_assert(len(quic.initial_dcid) == 8, "initial_dcid must be 8 bytes")
    debug_assert(len(quic.local_cid) == 8, "local_cid must be 8 bytes")
    var icid_u64 = _dcid_to_u64(Span(quic.initial_dcid))
    var lcid_u64 = _dcid_to_u64(Span(quic.local_cid))
    self.conn_dcid_map[icid_u64] = slot
    self.conn_dcid_map[lcid_u64] = slot
    self.conn_dcids[slot].append(icid_u64)
    self.conn_dcids[slot].append(lcid_u64)
    ```
5. **`_find_conn_by_dcid` signature change** (~lines 587–593):
    - `fn _find_conn_by_dcid(self, dcid_hex: String) -> Int` → `fn _find_conn_by_dcid(self, dcid_u64: UInt64) -> Int`
    - Body unchanged in shape; only the Dict probe type and parameter name change. Parameter renamed from `dcid_hex` to `dcid_u64` to match the helper output naming convention.
6. **`_handle_timeout` teardown cleanup** (lines 1014–1039 in current `bench/h3_server.mojo`, swap-and-pop with no-first-match-break invariant — per `addr_key→DCID demux migration` retrospective lesson). The struct has **three parallel arrays** (`self.conn_h3s`, `self.conn_addrs`, `self.conn_dcids`), all swapped together; `_dying conn_h3s` is freed via pointer destroy + free BEFORE the swap. Post-migration verbatim form (mirrors the existing structure; ONLY the element type of `conn_dcids` changes from `String` to `UInt64`):
    ```mojo
    var ptr = self.conn_h3s[i]
    ptr.destroy_pointee()
    ptr.free()

    # B-permissive teardown: pop ALL of dying conn's DCID entries
    # (typically 2: initial_dcid + local_cid). The pre-migration
    # single-DCID single-pop with first-match-break is incorrect
    # for the dual-key shape.
    for dcid_u64 in self.conn_dcids[i]:
        _ = self.conn_dcid_map.pop(dcid_u64)

    var last = len(self.conn_h3s) - 1
    if i != last:
        # Swap the last element into position i in all parallel
        # lists (conn_h3s, conn_addrs, conn_dcids).
        self.conn_h3s[i] = self.conn_h3s[last]
        self.conn_addrs[i] = List[UInt8](copy=self.conn_addrs[last])
        self.conn_dcids[i] = List[UInt64](copy=self.conn_dcids[last])

        # Remap ALL of the swapped-in conn's DCID entries from
        # `last` → `i`. CRITICAL: do NOT break after first match
        # (the survivor has 2 entries; both must be remapped).
        for dcid_u64 in self.conn_dcids[i]:
            self.conn_dcid_map[dcid_u64] = i

    _ = self.conn_h3s.pop()
    _ = self.conn_addrs.pop()
    _ = self.conn_dcids.pop()
    # Don't increment i — the swapped-in element needs checking.
    continue
    ```
    The trailing comment + missing-increment must be preserved verbatim — it is the load-bearing detail that prevents skipping the swapped-in element. The `List[UInt64](copy=self.conn_dcids[last])` form has been verified to compile + execute correctly under Mojo 0.26.2 via Mojo MCP `execute` during spec authoring; no escape hatch needed.

## 6. Tests

- **`test_dcid_to_u64_basic_cases`** — 5 case table:
    1. All-zero bytes → 0.
    2. All-0xff bytes → `UInt64.MAX`.
    3. Ascending `[0x01..0x08]` → `0x0102030405060708`.
    4. Descending `[0x08..0x01]` → `0x0807060504030201`.
    5. Random 8-byte vector → reproduces a fixed reference value (regression-locked).
- **`test_dcid_to_u64_injective_on_distinct_inputs`** — sample N=64 distinct 8-byte vectors; assert pairwise distinctness of `_dcid_to_u64` outputs. (Trivially true for a bijection on 8-byte → UInt64; locked anyway as a regression guard.)
- **Existing tests carry over unmodified.** `test_quic_connection_dcid_lengths_are_8_bytes` and `test_dcid_demux_disambiguates_two_conns` already lock the upstream invariant; the bench-side type migration is correctness-preserving as long as `_dcid_to_u64` is injective on 8-byte inputs.

Test count target: **+2 unit tests** (locked at AC#1 below).

## 7. Validation gate composition

**Hard Gate 1 — Long-conn RPS non-regression (on-build)**
- Build: `PROFILE_ACCEPT=True`, `ASSERT=none` on-build, freshly rebuilt with tag isolation (paired with Hard Gate 2 build to amortise rebuild cost).
- Command: `bash bench.sh mojo-net 1k long-conn tquic_client --iters 10`
- Threshold: median drift **≥ −2.0%** vs pre-migration on-build baseline.
- Image hygiene: both runs use freshly rebuilt tag-isolated docker images (`mojo-net-bench:q3-pre`, `mojo-net-bench:q3-post`) per `feedback_bench_offbuild_image_hygiene.md`.
- Iter count: 10 (per `feedback_bench_iter_count.md`); report median + IQR + stdev.

**Hard Gate 2 — Short-conn `loop_pop_dispatch.total` observed drop**
- Build: `PROFILE_ACCEPT=True`, `ASSERT=none` on-build, freshly rebuilt with tag isolation.
- Capture: n=5 baseline SIGINT sidecars + n=5 treatment SIGINT sidecars on short-conn (bumped from n=3 — `feedback_bench_iter_count.md` defaults to ≥10 iters; n=5 is the minimum for a hard gate this close to the lower edge of the 8–22% prediction bracket).
- Threshold: median treatment `loop_pop_dispatch.total` **drops by ≥8%** vs median baseline.
- Decision rule (precedence — applied in order): (1) If observed treatment stdev > 5% of median OR median drop lands in the marginal zone [6%, 10%], do NOT decide on n=5+5 — escalate to n=10 baseline + n=10 treatment and re-apply the ≥8% gate to the n=10+10 medians. (2) Otherwise, n=5+5 medians decide pass/fail directly. The marginal-zone escalation handles the case where the true effect sits near the threshold; the stdev escalation handles measurement noise; the two are non-overlapping in intent and cumulative in trigger.
- Anchored to leg-total (which is what sub-agent C's prediction is in), not addressable-work — clock-read overhead is consistent across baseline and treatment so cancels out.

**Hard Gate 3 — `dcid_mismatch_pkts == 0` regression check**
- Both sidecars (baseline and treatment) must report `dcid_mismatch_pkts == 0`. Prevents silent demux breakage from the type change.

**Soft Gate — Short-conn RPS reporting**
- Captured at n=10 alongside Hard Gate 1; reported in REFERENCE.md entry; **not gated**.

## 8. Acceptance criteria

| # | Description | Pass condition |
|---|---|---|
| AC#1 | Unit test count delta | `+2` new test functions for `_dcid_to_u64`; `TESTS_FILTER=test_dcid_to_u64 bash scripts/run_tests.sh` PASS. |
| AC#2 | Hard Gate 1 (long-conn RPS non-regression) | Median 10-iter long-conn RPS drift ≥ −2.0%. |
| AC#3 | Hard Gate 2 (sub-leg observed drop) | Median `loop_pop_dispatch.total` drops ≥8% on n=5+5 short-conn sidecars (escalates to n=10+10 per Hard Gate 2's bidirectional rule). |
| AC#4 | Hard Gate 3 (demux correctness) | `dcid_mismatch_pkts == 0` in both baseline and treatment sidecars. |
| AC#5 | Off-build long-conn non-regression | Median off-build (`PROFILE_ACCEPT=False`) long-conn RPS drift ≥ −2.0% vs pre-migration off-build baseline, n=10. Same threshold as AC#2 — confirms the type change carries no surprise overhead in the no-instrumentation build. (Off-build short-conn RPS reported but not gated for the same noise-floor reason as Soft Gate.) |
| AC#6 | REFERENCE.md entry | New row appended summarising baseline/treatment `loop_pop_dispatch.total` medians, RPS deltas, and verdict. |
| AC#7 | Flag revert | `PROFILE_ACCEPT` flag back to `False` before merge; verified by grep of source. |

## 9. Open questions / required-later items

| What | Severity | Trigger |
|---|---|---|
| AHash distribution check on rustls-allocated DCIDs (sanity guard, not a likely failure mode — DCIDs are random by construction) | optional | First treatment sidecar — sample N=100 DCIDs and confirm Dict load factor sits as expected (≤7/8) at 36k entries. If clustering observed, file separate spec for custom hasher. |
| Cold-create FFI accounting (Subagent C's Rank 3) | required-later | Trigger: post-Q1 budget-gap-closure spec lands. Q3 leaves cold-create FFI cost untouched (it's the dominant cost there per Subagent C's estimate; not addressed by hex→u64 swap). |
| Q1 budget gap closure | high | Trigger: next non-Q3 perf spec — needs Subagent B's research-2026-04-28-long-conn-unaccounted-gap.md as input. |
| Q2 TLS 1.3 session resumption | high | Trigger: after Q1 gives sub-leg visibility into the H3-handler/drain paths, then ffi_read_hs deep-dive can target rustls's `quic::Connection::read_hs` directly. |

## 10. Risks

- **Teardown remap correctness** — preserving the no-first-match-break semantics under the type change is the highest-correctness-risk piece. Mitigated by: (a) AC#4 demux-correctness gate, (b) `test_dcid_demux_disambiguates_two_conns` already exercises the path, (c) the type change is type-driven (Mojo's compiler will flag missed sites).
- **Mojo `Dict[UInt64, _]` AHash on sequential-ish keys** — Topic 2 confirmed AHash mixes via folded-mul (no identity-hash gotcha) but a quick sanity-sample on first treatment sidecar is included as an open-question trigger.
- **Sub-leg gate bias from clock-read overhead** — the constant per-iteration clock-read overhead (≈300–600 ms aggregate over the 30s short-conn capture, observed in the sub-leg pass) is constant across baseline and treatment, so cancels in the relative-drop comparison; gate threshold is anchored to leg-total which is the same number the prediction is in.

## Appendix A — Estimated implementation size

- `bench/h3_server.mojo`: ~60 LoC delta (helper +10, field types +2, hot-path call site +1, cold-create call sites ~6, `_find_conn_by_dcid` signature +1, teardown remap ~10, plus mechanical change-everywhere).
- `tests/`: ~30 LoC for 2 new test functions.
- Total: **~90 LoC** across 2 files.
- Estimated tasks: T0 hard-gate (parent — branch + pre-spec test count anchor + off-build baseline) → T1 helper + tests (subagent, TDD) → T2 field type migration + call-site updates (subagent) → T3 long-conn RPS gate + off-build sanity (parent) → T4 sub-leg sidecars + decision (parent) → T5 REFERENCE.md + flag revert + project-context advance (parent).
