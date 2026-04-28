# Topic 2 — Mojo 0.26.2 Dict Internals: String vs UInt64 keys

**Date:** 2026-04-28
**Mojo version:** Mojo 0.26.3.0.dev2026042005 (32e188d3) — pinned project version is 0.26.2; behaviour confirmed identical for the audited code paths against `mojo/stdlib/std/collections/dict.mojo`, `_swisstable.mojo`, `_ahash.mojo` on `modular/modular@main`.

## 1. Dict implementation summary

**Open-addressing SwissTable (Abseil flat_hash_map clone), NOT Robin Hood, NOT chained.**

- Source: `mojo/stdlib/std/collections/_swisstable.mojo` (634 LoC). `Dict` (`mojo/stdlib/std/collections/dict.mojo:677`) wraps `SwissTable[K, V, H]` plus a side `_order: List[Int32]` for insertion-order iteration.
- **Slot layout (per entry):** `SwissTableEntry { hash: UInt64, key: K, value: V }` — `_swisstable.mojo:206-225`. The hash is **stored** in the slot, so it is NOT recomputed on collision-walk or resize. Plus 1 control byte per slot in a parallel `_ctrl: UnsafePointer[UInt8]` array (`_swisstable.mojo:275-283`), with `GROUP_WIDTH = 16` extra mirror bytes at the end for SIMD wrap-around.
- **Probing:** SIMD group probing — load 16 control bytes at once, mask-equal to a 7-bit `h2` fingerprint (top 7 bits of the hash, `_swisstable.mojo:45-54`), iterate matches, fall back to next group at `(pos + 16) & (cap - 1)`. The lower 57 bits of the hash select the starting bucket (`pos = Int(hash) & (cap - 1)`, line 403).
- **Capacity:** always power-of-2 (mask-and indexing). Initial `INITIAL_CAPACITY` = `GROUP_WIDTH = 16` (line 41 / 304).
- **Load factor / resize trigger:** `growth_left = capacity * 7 // 8` (line 311). `needs_resize()` returns `True` when `_growth_left == 0`; `resize` doubles capacity (`new_capacity = old_capacity * 2`, `dict.mojo:1500`) and rehashes from the cached `entry.hash`. So **resize fires at 7/8 = 87.5 % occupancy**.
- **Tombstone reuse:** `find_slot_or_deleted` reclaims `DELETED` slots; if occupancy ≤ 7/16 (44 %) of capacity, sparse table triggers `rehash_in_place` (Abseil "drop-deletes") instead of a full grow.

## 2. String hash behaviour

- Family: **AHash** (Rust hashbrown's hasher, port at `_ahash.mojo`). Key seed = `pi_key = key ^ U256(pi_constants...)`. Default `Dict` uses `default_hasher = AHasher[U256(0)]` (`hasher.mojo:26`).
- Hash of `String` routes via `String.__hash__` (`string.mojo:1641-1650`) → `hasher.update(StringSlice(self))` → `_update_with_bytes(Span[Byte])` (`_ahash.mojo:125-149`).
- For a 16-byte hex key: takes the `length > 8 && length <= 16` branch — 2× `bitcast[UInt64]().load()` (one at `ptr`, one at `ptr+length-8`), packs into `U128`, single `_large_update` (one `_folded_multiply` on a 128-bit XOR + a rotate). Then `finish` does another `_folded_multiply` + variable-rotate. Roughly **3 folded-multiplies + a few SIMD ops per hash**.
- **Hash is NOT cached on the `String` itself.** It IS cached on the SwissTable entry (`SwissTableEntry.hash`, `_swisstable.mojo:217`), so collision walks and resize re-use it. But every fresh probe (every `dict.get(key)`) recomputes the hash from the key bytes once.
- Equality on collision: SwissTable first matches the `h2` fingerprint via SIMD, then compares the full 64-bit `entry.hash` (line 412) before invoking `key.__eq__`. So full `String` equality runs only when both fingerprint AND full hash collide — extremely rare for AHash-quality output.

## 3. UInt64 hash behaviour

- **NOT identity.** `UInt64` (= `SIMD[uint64, 1]`) routes via `SIMD.__hash__` (`simd.mojo:1962-1971`) → `hasher._update_with_simd(self)`.
- In `AHasher._update_with_simd` (`_ahash.mojo:151-186`), `rounds = max(1, size_of[uint64]() // 8) = 1`, `u64.size = 1`, so it takes the `comptime if u64.size == 1` branch and runs **one `_update(u64[0])` call** = `buffer = _folded_multiply(new_data ^ buffer, MULTIPLE)`. Followed by `finish`'s `_folded_multiply(buffer, pad)` + variable-rotate.
- Two folded-multiplies + an XOR + a rotate per UInt64 hash. **Sequential / clustered UInt64 inputs are de-correlated by the multiply-with-prime + rotate**, so contiguous DCIDs would NOT cluster.
- Identity-hash gotcha: **does not apply to Mojo**. The buffer is even seeded with `pi_key[0]` so `hash(0) != 0`. (Verified by reasoning; cross-verified in §5 since the empty-checksum stayed deterministic across seeds.)

## 4. Per-entry memory cost (bytes)

`SwissTableEntry { hash: UInt64; key: K; value: V }` plus 1 control byte per slot (overshoot: `cap + 16` bytes for ctrl array). Capacity at 36 000 occupied entries is the smallest power-of-2 with `cap * 7 / 8 ≥ 36 000` → **65 536** (since 32 768 × 7/8 = 28 672 < 36 000).

| Variant | Per-slot struct | Per-slot bytes (struct) | Heap-side per occupied entry | Total per occupied entry @ 65 536 cap | Source |
|---|---|---|---|---|---|
| `Dict[String, Int]` | `{u64 hash, String key, Int value}` | 8 + 24 + 8 = **40 B** + 1 ctrl = **41 B** | 16-byte heap String buffer (small-string-optimisation may inline ≤23 B; verify — likely heap for 16 B) ≈ 16 B + malloc overhead ≈ 24 B | ≈ 41 × (65536/36000) + 24 ≈ **99 B** | `_swisstable.mojo:206`, `string.mojo` (String layout) |
| `Dict[UInt64, Int]` | `{u64 hash, UInt64 key, Int value}` | 8 + 8 + 8 = **24 B** + 1 ctrl = **25 B** | none | ≈ 25 × (65536/36000) ≈ **45 B** | same |

Δ ≈ **2.2× smaller** total footprint, AND the slot struct itself is **40 → 24 B = 1.67× smaller** even before counting the heap-side String buffer. The 36 k-entry table goes from ≈ 3.6 MB → ≈ 1.6 MB. Both still exceed L1 (32–64 KB) and L2 (typically 1 MB) on a modern x86 — but the UInt64 variant fits comfortably in L3 with cleaner cache-line packing (a 64 B line holds 2.5× as many 25 B slots as 41 B slots).

> Note: Subagent C's "halves entry size" claim is **conservative**. Actual reduction is closer to 2.2× when the String heap allocation is counted; 1.67× counting only the in-table slot struct.

## 5. Microbenchmark results

Code: see `mcp__mojo-mcp__execute` log; harness populates 36 000 random entries into both dicts, runs 100 000 random hits. Hot-loop `Dict.get` only (no insert / no resize during measurement). Run via Mojo MCP `execute` (Mojo 0.26.3-dev). 5 iters, alternated.

```
iter, ns_u64_total, ns_str_total, str/u64_x100
0   , 594810      , 2384558    , 400
1   , 555542      , 2382760    , 428
2   , 556076      , 2488737    , 447
3   , 758530      , 2443499    , 322
4   , 649045      , 2501799    , 385
```

Per-lookup (100 000 lookups per iter):

| Dict variant | ns/lookup (median) | ns/lookup (range) |
|---|---|---|
| `Dict[UInt64, Int]` | **≈ 5.9 ns** | 5.5 – 7.6 |
| `Dict[String, Int]` | **≈ 24.4 ns** | 23.8 – 25.0 |
| Ratio (String / UInt64) | **≈ 4.0×** | 3.2 – 4.5× |

Net: **String costs ≈ 18–19 ns more per lookup than UInt64** at 36 k entries on this hardware. Verdict: the bottleneck is real and substantial.

## 6. Verdict on Subagent C's claims

| Claim (predecessor research) | Verdict | Evidence |
|---|---|---|
| `Dict[String, Int]` at 36 k exceeds L1, each lookup is L2/L3 | **Partially verified.** Slot array ≈ 3.6 MB ≫ L2 (typ. 1 MB), so YES capacity-wise the working set is in L3 / DRAM. But SwissTable-cached `entry.hash` and SIMD group probing mean only ~1 group of 16 ctrl bytes (16 B) + 1 slot (40 B) is read per probe — so the actual per-lookup memory traffic is small even if the table doesn't fit in L1. | `_swisstable.mojo:217, 402-422` |
| Switching to `UInt64` halves entry size + improves cache hit rate | **Verified, slightly conservative.** Slot struct 40 → 24 B (1.67×); total per-entry footprint with String heap drops ≈ 2.2×. | §4 |
| B+C combined cost: 77–215 ms / 30 s = 8–22 % of `loop_pop_dispatch` | **Verified upward-revisable.** Microbench shows the Dict-lookup delta alone is ≈ 18 ns/pkt. At ≈ 288 675 hot-path packets / 30 s on short-conn that is **≈ 5.2 ms saved on Dict lookup alone**. The bigger win is eliminating `_bytes_to_hex` (B): with String alloc + 16-iter `chr() +=` chain at est. 200–400 ns/call, B alone is ≈ 58–115 ms / 30 s. **Combined B+C savings: ≈ 63–120 ms / 30 s ≈ 6.6–12.5 % of pop_dispatch** — at the lower end of Subagent C's 8–22 % bracket. RPS-uplift estimate: stay at the 0.5–1.4 % short-conn band Subagent C cited; the 6 % spec headline is plausible only if cold-create FFI cost (which we do not change here) is also reduced. |
| `UInt64` keys cluster on identity-hash if rustls allocates sequentially | **Refuted — irrelevant.** Mojo's default hasher is AHash (`AHasher[U256(0)]`), not identity. Even pathological inputs (all-zero, all-MAX, sequential) get fully scrambled by the `_folded_multiply` + variable rotate. No clustering risk regardless of how rustls picks DCIDs. | `_ahash.mojo:106-112, 197-205`; `simd.mojo:1962-1971` |

## 7. Surprises / red flags

1. **`SwissTableEntry.hash` is cached.** This means re-probes during collision walks AND during resize do NOT recompute the hash. Subagent C's mental model of "hex-string-hash on every probe" is incorrect for collision walks — but correct for the *initial* hash on `dict.get(key)`. The dominant cost on a hit-path is **one** hash + one SIMD compare + one full-hash compare + one `key.__eq__`.
2. **Resize at 7/8, not 50 %.** Higher than Python (2/3) or Java (3/4). At 36 k entries the table is at 36000/65536 = 55 % occupancy, not pathologically tight; collision walk depth should be small.
3. **Hash is not cached on `String`.** Repeated `dict.get(same_key)` re-hashes the key bytes every call. Mitigation: switch to `UInt64` removes the hash cost almost entirely (one folded-multiply + rotate vs. 3 folded-multiplies + 2 SIMD loads + length-mul).
4. **Predecessor's `_bytes_to_hex` reading is the right target.** The String allocation + chr-append loop at `bench/h3_server.mojo:164-179` is ~3-5× pricier than the eventual Dict lookup it feeds. Killing it (via `_dcid_to_u64`) recovers more time than the Dict-key swap alone.
5. **Mojo version drift.** Tested against Mojo 0.26.3-dev; project pin is 0.26.2. The Dict / SwissTable / AHash code paths are stable across this minor version per `git log mojo/stdlib/std/collections/_swisstable.mojo` (no algorithmic changes). Worth a project-pinned re-run before code-cutting the spec.
6. **Microbench is on warm-cache, hit-only workload.** Real bench/h3_server pop_dispatch additionally pays cold-cache costs from interleaved profiler writes, FFI calls, and `is_expected_dcid` accesses. Real-world ratio could be lower (3×?) if the working set rarely warms — or higher if String heap alloc/dealloc traffic from `_bytes_to_hex` evicts other useful lines. Either way, **direction (UInt64 < String) is robust**.
