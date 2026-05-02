# QPACK Optimization Findings — 2026-05-02

**Branch:** `perf/qpack-decode-fast` (off main `f22647b`)
**Status:** v4 shipped on branch, +3.6% long-conn / +1.9% short-conn RPS lift. Conformance + tests green.

## Current state on branch

Single commit `7d708b8`: instance-cached QPACK static table on `QpackDecoder`. The 99-entry static table is built once per decoder (one per H3Connection) instead of being rebuilt on every indexed lookup. Microbench: `static_get` 391 ns → 1 ns (391× faster). Macro bench: long-conn 14,870 → 15,403 rps.

## What we tried that didn't work

### Attempt 1: comptime-for unroll for static_get + huffman_decode

```mojo
comptime for k in range(99):
    if k == idx: return ...
```

- **Result:** 5× binary bloat (805 KB → 4 MB), -36% RPS regression.
- **Cause:** the compiler emits unrolled comparisons as generated code, not data. icache pressure dwarfs any per-call savings.

### Attempt 2: comptime InlineArray for static + Huffman tables

```mojo
comptime _STATIC_NAMES = InlineArray[StaticString, 99](...)
comptime _HUFF_CODES = InlineArray[UInt32, 256](...)
```

- **Result for static (99 entries):** binary unchanged at 805 KB; macro bench -13%; microbench `static_get` 50 ns. Mixed.
- **Result for Huffman (256 entries):** binary unchanged but `huffman_decode` 8.5× SLOWER in production. Inner-loop `_HUFF_NBITS[sym]` access is somehow expensive at runtime despite isolated read benchmarking at 3 ns.
- **Cause (hypothesis):** Mojo 0.26.2 partially folds `comptime InlineArray` of 256+ entries — falls back to runtime construction with apparent indexing overhead inside hot loops. A 256-arg `__list_literal__` constructor failed to compile-fold in our standalone test (variadic depth exceeded).

### Attempt 3: Instance-cached `huff_table` on QpackDecoder + method-form decode

- **Result:** macro bench -2.6% regression vs v4.
- **Cause:** `self.huff_table[sym].nbits` access inside the hot inner loop is slower than the existing `var table = _huffman_encode_table(); table[sym].nbits` pattern. Two extra pointer-dereferences per access (struct field, then List data) compounded over ~128 iters/char × 11 chars × 14k req/s.
- **`ref` binding test:** `ref table = self.huff_table` to alias without copy — same 14,671 ns/call (vs original 13,190 ns), no improvement.
- **Conclusion:** caching the encode table per-instance does NOT help. The current per-call rebuild is as fast as the inner loop allows.

## What works (v4 — shipped on branch)

Per-instance cache of the **static table only** on `QpackDecoder`:

```mojo
struct QpackDecoder:
    var static_table: List[QpackStaticEntry]

    def __init__(out self):
        self.static_table = _qpack_static_table()  # built once per H3Connection

    def decode(mut self, data: List[UInt8]) raises -> List[QpackHeaderField]:
        ...
        var entry = self.static_table[idx].copy()  # O(1), no rebuild
        ...
```

This works because:
- Static lookups happen 3-5× per request (vs Huffman's ~128 inner iters per char × multiple chars)
- Eliminating the 99-String-alloc rebuild has high leverage
- Outer-loop access (per indexed-FL parse) doesn't suffer the `self.field` overhead the way inner-loop access does

## Where the gap remains

mojo-net is at 16.2% of TQUIC long-conn RPS post-Q3-merge. With v4 we're now ~16.8%. Closing the gap requires fixing Huffman.

Per Q-drain-subleg evidence:
- 95% of `_drain_stream` time is in `self._dec.decode(...)`
- Of that, microbench shows ~85% is in `huffman_decode` (14 μs out of 16 μs for a 4-header decode with 1 Huffman value)
- TQUIC's Huffman is sub-µs/req per Topic 1 §4 — **~30× faster**

## The next big win: state-machine Huffman decoder

TQUIC and quiche both use a **4-bit state-machine decoder**:

```rust
const DECODE_TABLE: [[(usize, u8, u8); 16]; 256] = [...];

fn decode4(&mut self, input: u8) -> Result<Option<u8>> {
    let (next, byte, flags) = DECODE_TABLE[self.state][input as usize];
    // ... return Some(byte) if FLAG_DECODED ...
}
```

- 256 states × 16 nibbles = 4096 transition entries
- Each input byte decodes to 2 nibble lookups = **O(1) per byte**
- For an 11-char Huffman value: ~22 lookups vs current ~1408 inner-loop iters
- **Estimated ~30-50× speedup on huffman_decode**

### Implementation plan

1. **Build the decode table at QpackDecoder `__init__` time** from the encode table:
   - Build a binary tree from `_huffman_encode_table()` (each leaf = a symbol)
   - For each (state, nibble): walk 4 bits, identify next state + emitted symbol
   - Output 4096 (next_state, output_byte, flags) tuples
   - ~80-100 LoC; one-time cost ~10-30 μs at decoder init
   - **Note: the SHORTEST Huffman code is 5 bits; no nibble can complete two codes — at most 1 symbol emit per nibble. This makes the table-build straightforward.**

2. **New decode method on QpackDecoder:**
   ```mojo
   def _decode_huffman_sm(self, data: List[UInt8]) raises -> String:
       var state: Int = 0
       var out = List[UInt8]()
       for byte in data:
           # high nibble
           var entry = self.huff_decode_table[state * 16 + Int(byte >> 4)]
           if entry.flags & FLAG_DECODED:
               out.append(entry.byte)
           state = Int(entry.next)
           # low nibble
           entry = self.huff_decode_table[state * 16 + Int(byte & 0xf)]
           if entry.flags & FLAG_DECODED:
               out.append(entry.byte)
           state = Int(entry.next)
       if state != 0 and not (entry.flags & FLAG_MAYBE_EOS):
           raise "Huffman: incomplete code"
       return String(unsafe_from_utf8=out)
   ```

3. **Wire into QpackDecoder.decode** (replace the existing `huffman_decode` calls in §4.5.4 / §4.5.6 paths).

4. **Conformance check:** the existing 6 huffman tests in `tests/test_h3_qpack.mojo` cover roundtrip + edge cases. Plus `bash conformance/scripts/run_tests.sh` for the full 36-test conformance suite.

### Risks

- **Table-build correctness:** the 4-bit state-machine derivation is a known algorithm but easy to get wrong on edge cases (EOS, partial-byte padding). Need to cross-validate against TQUIC's hardcoded table values for the first few states (TQUIC `huffman.rs:422-...`).
- **The "self.field overhead" found in v5:** even with a precomputed table, accessing `self.huff_decode_table[state * 16 + nibble]` may still pay the struct-field indirection cost. **However:** the access pattern is O(1) per nibble (constant 2 accesses per byte) vs the current O(N×K), so even with overhead the result will be dramatically faster.

### Estimated impact

- `huffman_decode` 14 μs → ~500 ns = ~28× faster per Huffman string
- Per HEADERS frame (with ~3 Huffman values): 50 μs → ~5 μs = ~10× faster
- Long-conn RPS: 14k → ~30-50k rps = **~2-3× speedup**

This is the biggest remaining structural win. Worth a dedicated follow-up spec.

## Reusable lessons

1. **Mojo 0.26.2 doesn't have const-array equivalents for >100 entries.** TQUIC's `const STATIC_DECODE_TABLE: [(&[u8], &[u8]); 99]` and `const DECODE_TABLE: [[(usize, u8, u8); 16]; 256]` are the cleanest implementation in Rust. Mojo's `comptime InlineArray` works for ≤99 entries but breaks down at 256+ and has unexplained runtime indexing overhead in inner loops. Per-instance List cache built at __init__ is the workable approximation.

2. **Microbench != macro bench.** Even with same-window measurements, isolated lookups optimized 391× translate to ~3.6% RPS win. The dominant factor in production is wall-clock per HEADERS frame, where many costs compound.

3. **Comptime-for unroll bloats binary 5× and regresses production by 36%** despite 21× microbench speedup on the unrolled lookup. Avoid for tables larger than ~10-20 entries.

4. **Inner-loop `self.field` access is measurably slower** than local `var x = ...` patterns (Mojo 0.26.2). For state-machine decoders we need to test whether `ref table = self.huff_decode_table` aliasing recovers the speed; if not, the table-build cost may need to be paid differently (one-time global-init via UnsafePointer).

5. **The microbench-to-macro discrepancy must be empirically verified.** The static-table fix microbench → macro pipeline gave +391× → +3.6% RPS, which is consistent given share-of-time. The Huffman cache microbench → macro went +0% → -2.6% — different from prediction because the inner-loop overhead amplified at scale.

## Files / References

- Branch HEAD: `7d708b8`
- TQUIC reference: `tquic/src/h3/qpack/huffman.rs:422+` (DECODE_TABLE), `tquic/src/h3/qpack/static_table.rs:381` (STATIC_DECODE_TABLE)
- quiche reference: `quiche/src/h3/qpack/decoder.rs:204` (lookup_static)
- Q-drain-subleg evidence: `bench/quic_perf/results/profile/Q-drain-subleg_post_evidence_2026-05-01.md`
- Predecessor research: `research/2026-05-01-tquic-quiche-stream-read-paths.md`


## Update: v6 — TQUIC-style state-machine Huffman decoder SHIPPED

**Commit:** `89ca855` on `perf/qpack-decode-fast`.

The 4-bit-at-a-time state-machine pattern works in Mojo via a per-instance cache built at `QpackDecoder.__init__`. Build algorithm: encode-table → binary tree → 256-state × 16-nibble decode table.

### Results

| Metric | Before (main) | After (v6) | Change |
|---|---|---|---|
| `huffman_decode("example.com")` microbench | 11,736 ns | 132 ns | **89× faster** |
| `decode(4-header, 1 Huffman)` microbench | 16,402 ns | 323 ns | **50× faster** |
| Long-conn RPS macro (n=10, same-window) | 14,847 | **36,007** | **+143% / 2.43× speedup** |
| % of TQUIC reference (87k rps) | 16.2% | **41.4%** | +25 pp |
| Short-conn RPS macro (n=5) | 1,229 | 1,139 | **-7%** |
| Binary size | 805 KB | 809 KB | +4 KB |
| `__init__` build cost | <1 μs | ~52 μs | +51 μs/decoder |
| Conformance | 36/36 | 36/36 | ✓ |

### The short-conn regression

Per-connection `QpackDecoder.__init__` now costs ~52 μs (46 μs for HuffDecodeTable + 6 μs for static table). At ~1,200 conn/sec on short-conn, that's ~62 ms/sec = ~6% CPU spent on table-build. Matches observed -7%.

Three paths to fix this:

1. **Process-shared table via UnsafePointer singleton:** Mojo 0.26.2 doesn't allow module-level mutable vars, but UnsafePointer-backed lazy-init is possible via a struct-static pattern. Need a way for the FIRST QpackDecoder to populate, subsequent ones to skip. Synchronization would matter in a multi-threaded context but mojo-net bench is single-threaded.

2. **Comptime-baked decode table:** Pre-compute the 4096 entries at compile time, embed as 3 parallel comptime InlineArrays. Test result earlier: 256-entry comptime InlineArray fold worked; 4096-entry untested. May fail compiler folding or regress runtime indexing speed (we saw this on 256-entry attempt for huff_codes).

3. **Cheaper build:** Current build is ~46 μs; theoretical minimum is ~10 μs if we skip the binary-tree intermediate and walk the encode table directly. Would still leave ~12 ms/sec on short-conn, ~1% CPU.

### Recommendation for next spec

Path 1 (UnsafePointer singleton) is most promising and Mojo-native. Sketch:

```mojo
# Module-level: not allowed, so use struct-static via UnsafePointer indirection.
struct _HuffTableSingleton:
    @staticmethod
    fn get() -> UnsafePointer[HuffDecodeTable]:
        # Lazy-init on first call; cache via UnsafePointer.
        # Mojo lacks module-level mutable vars; need to work around.
```

This is the next optimization. Long-conn win locks in the bulk of the gap; short-conn cleanup is a smaller follow-up.

### Path to closing the rest of the TQUIC gap

Current: 41% of TQUIC long-conn. Remaining 59% likely lives in other parts of `_drain_stream` that Q-drain-subleg attributed to `qpack_decode_us` but which are now down to ~3 μs/call (below noise floor) — we need a new sub-leg pass to find what's now dominant.

Alternative: profile the actual `quic_post_recv_us` bracket (Q1's ~22M μs / 30s). After v6, what fraction is now in the FFI receive path vs in `_drain_stream`? If FFI is the new dominant, that's the next target.


## Update: v7 — encoder-side caching SHIPPED

**Commit:** `4edb39a` on `perf/qpack-decode-fast`.

After v6 shipped state-machine Huffman DECODER, the SIGINT sidecar profile shifted dramatically: `drain_stream_us_total` dropped from 22M → 3.7M μs (-83%), `qpack_decode_us` from 21M → 1.3M μs (-94%), and the new dominant H3 phase became **`drain_resp` (encoder side) at 13.2M μs** (38% of busy). The encoder still:
- Rebuilt the static table on every `qpack_static_find` / `qpack_static_find_name` call
- Rebuilt the 256-entry Huffman encode table on every `huffman_encode` call

v7 caches both tables on `QpackEncoder` (mirroring `QpackDecoder`'s pattern), with private methods `_huffman_encode` / `_static_find` / `_static_find_name` / `_encode_string`.

### Cumulative results

| Version | Long-conn RPS | % of TQUIC | Δ vs main |
|---|---|---|---|
| main (Q1 + Q3 shipped) | 14,847 | 16.2% | — |
| v4 (decoder static-table cache) | 15,403 | 17.7% | +3.6% |
| v6 (state-machine Huffman decoder) | 36,007 | 41.4% | **+143%** |
| **v7 (encoder caching)** | **40,776** | **46.8%** | **+175%** |

Closing 30.6 percentage points of the TQUIC gap in 3 commits.

Binary size: 805 KB → 809 KB (+4 KB total). Conformance: 36/36 pass throughout. Src tests: 72/72 pass throughout.

## Next bottleneck (post-v7)

After v7, the long-conn `drain_resp` should drop substantially. Need a fresh SIGINT sidecar to identify:
- `drain_resp` new size vs `post_recv` vs `dispatch`
- Whether QUIC FFI calls (recv_stream_data, send_stream_data) are now dominant
- Whether IO-loop work (read_pkt, send_pkts) is the bottleneck
- Whether per-flush bookkeeping (Dict ops, per-conn state) dominates

The trajectory `+143% → +175%` suggests there's still room. Realistic projection: another ~50% lift from fixing `drain_resp` internals, getting to ~60-70% of TQUIC. Beyond that, FFI batching (send_stream_data at the wire layer) is likely the next structural change.
