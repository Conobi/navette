# Phase A `loop_pop_dispatch` — Cost Attribution & Microoptimisation Report

**Date:** 2026-04-28  
**Subagent:** C (parallel investigation alongside A and B)  
**Investigation source data:** `bench/quic_perf/results/profile/INSTRUMENTATION-20260428-015250-postmigration-shortconn-subleg.json` (`loop_pop_dispatch.total = 958,147 μs`, `loop_iter_count = 306,675`, ~5.9% of `busy_us_total = 16,122,651 μs`).

**Files examined:**
- `bench/h3_server.mojo` lines 164–202, 585–594, 700–870
- `src/quic/profile.mojo` lines 84–274

---

## 1. Cost-Attribution Sketch

**Baseline counts:**
- 306,675 loop iters / 30s short-conn
- ~18,000 cold conn-creates
- ~288,675 established-conn iters (hot path)
- `loop_pop_dispatch.total = 958,147 μs`

**Caveat — self-timing overhead:** the pop_dispatch bracket wraps its own clock reads. Each iter fires `profile_monotonic_us()` twice (top + bottom of bracket) + once for `record_loop_iter`. At ~1–2 μs per `clock_gettime` call × 2 reads × 306,675 iters ≈ **300–600 ms of the 958ms is self-timing overhead**. The remaining ~350–650 ms is attributable to real Phase A sub-sections.

| Sub-section | Cadence | Est. cost (ms/30s) | % of 958ms | Confidence |
|---|---|---|---|---|
| A1: `record_arrival_lat` + `record_loop_iter` | per-pkt | 1.5–8 | 0.2–0.8% | High |
| A2: `record_conn_pkt` (`Dict[String, UInt64]`, 4 keys) | per-pkt | 15–46 | 1.6–4.8% | Low-med |
| **B: `_bytes_to_hex(Span(pd.dcid))`** | **per-pkt** | **46–123** | **5–13%** | Med |
| **C: `_find_conn_by_dcid` (`Dict[String, Int]`, 36k entries)** | **per-pkt** | **31–92** | **3–10%** | Med |
| D: `_is_long_header_initial` gate (drop sub-path) | cold-path only | <1 | <0.1% | High |
| E: `is_expected_dcid` (PROFILE_ACCEPT-gated diagnostic) | per-pkt | ~14 | ~1.5% | Med |
| F: Cold conn-create (FFI + allocs + dict inserts) | per-conn ×18k | 16–74 | 1.7–7.7% | Low |
| Clock-read overhead (profiling brackets) | per-pkt | ~300–600 | ~31–63% | Med |

**B+C combined: 77–215 ms/30s = 8–22% of pop_dispatch total, ≈0.5–1.4% of `busy_us_total`** — these are the dominant real-work costs on the hot (established-conn) path.

---

## 2. Code-Level Detail on the Hot Sub-sections

**`_bytes_to_hex` (lines 164–179):** allocates a fresh `String()` (heap), then runs 16 `+=` single-char appends via `chr()`. With initial String capacity of 0, this triggers up to 4–5 `realloc` calls before reaching 16 chars. Returns by move. Called **once per iter on every packet** at line 742, plus twice per cold create at lines 816–817.

**`_find_conn_by_dcid` (lines 587–593):** `Dict[String, Int]` keyed on the 16-char hex string from B. Short-conn's map grows to ~36,000 entries (18k conns × 2 DCIDs each). With 36k String entries the map significantly exceeds L1 (typically 32–64 KB), making each lookup an L2/L3 access with a String-hash computation on every probe. **Long-conn has ~10 entries** — perpetually L1-hot, explaining the 4× per-iter gap (3.1 vs 0.84 μs) largely independent of cold-create frequency.

**`record_conn_pkt`:** `Dict[String, UInt64]` keyed on `pd.addr_key`. Key space is 4 entries (4 tquic_client threads = 4 src_ports) — stays L1-hot on both cells. Cost dominated by String hash of `addr_key` (~20–30 ns). Moderate but not dominant.

**Cold conn-create (lines 768–850):** three major costs per create:
1. `QuicConnection.server(...)` — FFI (`quic_server_conn_new`): crosses Rust boundary. Conservative estimate: 200–2000 ns/call → 3.6–36 ms/30s.
2. Two `_bytes_to_hex` calls for `initial_dcid` + `local_cid`: 36,000 allocs at same cost as B → 5–14 ms/30s.
3. Dict inserts (`conn_dcid_map[icid]` + `[lcid]`) + 3 List appends: ~200–500 ns total → 3.6–9 ms/30s.

---

## 3. Top 3 Microoptimisations

### Rank 1 — `Dict[String, Int]` → `Dict[UInt64, Int]` via `_dcid_to_u64`

**Sketch:** Replace `_bytes_to_hex` on the hot path with `_dcid_to_u64(bytes: Span[UInt8, _]) -> UInt64` — an 8-iteration bit-shift pack (zero allocations). Change `conn_dcid_map: Dict[String, Int]` → `Dict[UInt64, Int]` and `conn_dcids: List[List[String]]` → `List[List[UInt64]]`. Update the 3 call sites (lines 742, 816, 817), `_find_conn_by_dcid`, and `_handle_timeout`'s teardown cleanup loop.

**LoC:** ~50 in `bench/h3_server.mojo` — entirely bench-local, no `src/` changes.

**Uplift:** eliminates B+C combined (77–215 ms/30s from pop_dispatch). Additionally, `Dict[UInt64, Int]` has half the per-entry memory footprint of `Dict[String, Int]`, improving cache utilisation on the 36k-entry map. Conservative **0.5–1.4% rps uplift on short-conn**; potentially 2–3% if cache-miss reduction is significant.

**Risks:**
- DCID 8-byte invariant must hold. `debug_assert(len == 8)` at lines 813–814 already present; add same assertion in `_dcid_to_u64`.
- Reporting paths that render `conn_dcid_map` for human output need updating (off-hot-path, low severity).
- Keep `_bytes_to_hex` for report rendering — still used by `profile.mojo` text output.

### Rank 2 — Eliminate heap allocs in `_bytes_to_hex` without changing Dict key type

**Sketch:** pre-reserve capacity before the encode loop: `key._buffer.reserve(16)` (or `String.reserve(16)` if available in Mojo 0.26.2 — verify via MCP `lookup` first). Reduces realloc chain from 4–5 calls to 0. Alternative: replace `chr() +=` with a direct byte-array fill into a 16-byte `InlineArray` then construct `String` once from a `Span`.

**LoC:** ~10. **Uplift:** ~0.3–0.8% rps. Strictly dominated by Rank 1; useful as a quick interim if Dict type change has blockers.

### Rank 3 — Pool `H3HandlerServer` heap allocations across cold creates

**Sketch:** maintain `free_list: List[UnsafePointer[H3HandlerServer[BenchHandler]]]` pre-allocated at startup. On cold create, pop from free list instead of `_heap_alloc`; on teardown, `reset()` + push back.

**Uplift:** `_heap_alloc` cost at 18k creates ≈ 1.8–5.4 ms/30s. **<0.1% rps uplift.** Cold-create is dominated by the FFI call, which pooling does not eliminate. De-prioritise until FFI sub-leg data justifies it.

**Risks:** high complexity — `H3HandlerServer.__del__` frees QUIC FFI resources; pooling requires a safe `reset` path.

---

## 4. Recommended First Lever

**Implement Rank 1: `Dict[UInt64, Int]` with `_dcid_to_u64`.**

This eliminates both per-pkt heap allocation (`_bytes_to_hex`) and per-pkt String-hash Dict probe (`_find_conn_by_dcid`) in a single ~50 LoC bench-local change. The DCID-8-byte invariant is already hard-gated by existing `debug_assert` and a dedicated unit test (`test_quic_connection_dcid_lengths_are_8_bytes`), so the correctness precondition is fully satisfied. The short-conn cache-miss asymmetry (36k String entries vs ~10 on long-conn) strongly suggests the Dict lookup is paying L2/L3 latency on every packet; switching to `UInt64` keys halves entry size and is expected to improve cache hit rate materially. The change carries no `src/` surface risk and requires no FFI sub-leg data to justify — it is self-evidently correct from first principles.

Spec it as the first bench-local micro-optimisation task after the current sub-leg instrumentation plan closes.

---

*All cost estimates are static-analysis + cadence arithmetic — no micro-benchmarks were run. The dominant uncertainty is the clock-read-overhead share of the 958ms. FFI sub-leg data from the in-progress `spec-quic-accept-loop-subleg-instrumentation` plan will sharpen the cold-create FFI attribution when available.*
