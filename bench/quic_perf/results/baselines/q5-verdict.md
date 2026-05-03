# Q5 Verdict — `read_hs` Per-Call Decomposition

**Date:** 2026-05-04
**Branch:** `feat/quic-q5-read-hs-decomp`
**Image:** `mojo-net-bench:q5-post-on` (PROFILE_ACCEPT=True; source HEAD post-T2 `4c5f924`)
**Method:** n=3 short-conn captures, 30s × 4 client threads × 25 concurrent conns × 1 request per conn (`SESSION_FILE` enabled per P2). Resumption rate >99% (P2 unchanged).

## VERDICT: FALSIFIED

**Lever B (batching `read_hs` across recv_from_buffer iter boundaries) is dead-on-arrival.** The observed 2-3 read_hs calls per handshake are **architectural minimum** dictated by rustls's per-encryption-level API, not redundant calls amenable to batching.

## Captured numbers

### Per-iter rps + CPU

| Iter | rps | CPU% |
|---|---|---|
| 1 | 1,321.7 | 57.7 |
| 2 | 1,321.5 | 58.0 |
| 3 | 1,339.5 | 58.8 |
| **median** | **1,321.7** | **58.0** |

Consistent with P2/Q4 short-conn baseline (1,224-1,281 rps, 57-58% CPU). No regression from Q5's instrumentation.

### Per-handshake `read_hs` call count distribution

| Iter | bucket=1 | 2-3 | 4-7 | 8-15 | 16-31 | 32-63 | 64-127 | 128+ |
|---|---|---|---|---|---|---|---|---|
| 1 | 0 | 48,588 | 0 | 0 | 0 | 0 | 0 | 0 |
| 2 | 0 | 48,586 | 0 | 0 | 0 | 0 | 0 | 0 |
| 3 | 0 | 49,474 | 0 | 0 | 0 | 0 | 0 | 0 |

**100% of handshakes land in bucket "2-3"**. No bimodal distribution — every server connection makes exactly 2 or 3 read_hs calls.

### Per-call duration distribution (24-bucket pow2 µs)

| Iter | bucket 7 (64-128µs) | bucket 8 (128-256µs) | bucket 9 (256-512µs) | bucket 10+ | overflow | total |
|---|---|---|---|---|---|---|
| 1 | 94,572 (97.3%) | 2,379 (2.4%) | 218 | 8 | 0 | 97,177 |
| 2 | 94,589 (97.3%) | 2,361 (2.4%) | 210 | 12 | 0 | 97,172 |
| 3 | 96,374 (97.4%) | 2,377 (2.4%) | 187 | 10 | 0 | 98,948 |

**~97% of calls in bucket 7 (~64-128µs).** Per-call cost is high (well above the 32µs threshold).

### Cross-validation

`handshakes_total == count_records` per iter (48,588 / 48,586 / 49,474). Every counted handshake produced a recorded read_hs count. No leaks, no double-counts.

## Why FALSIFIED, not VIABLE

Spec §3.1 verdict table maps:
- count = 1 → FALSIFIED (already batched)
- count ≥ 3 + per-call ≥ 32µs → VIABLE (batching could reduce count)

Observed count is in bucket "2-3" with per-call ~64-128µs. Naively this matches "count ≥ 3 + high per-call cost" → VIABLE. **But the architectural reality overrides:**

1. **rustls's `read_hs(level, bytes)` API is per-encryption-level.** Bytes for level 0 (Initial) and level 2 (1-RTT) cannot be merged into a single FFI call.
2. **Resumed handshakes (99.3% of conns at the bench's resumption rate) span exactly 2 levels:**
   - Initial: ClientHello with PSK extension → 1 read_hs(level=0)
   - 1-RTT: Client Finished → 1 read_hs(level=2)
3. **Full handshakes (0.7% of conns) span 3 levels:** Initial + Handshake + 1-RTT.
4. **The 2 (resumed) or 3 (full) calls are architectural minimum.** "Batching across recv_from_buffer iter boundaries" only helps if multiple calls fire at the SAME level across different inbound datagrams. With per-level API, that pattern doesn't occur for handshake CRYPTO.

mojo-net's `_drive_handshake` already iterates over levels and drains all pending CRYPTO at each level in a single read_hs call per level per invocation. There is no across-iter same-level read_hs pattern to batch.

## Implications for next optimization spec

Three remaining levers (per Q4 retro), revised:

### Lever A — TLS-lib swap (rustls → boringssl)
- **Pros:** boringssl is empirically faster than rustls per handshake (literature suggests ~10-20% on TLS 1.3 server-side). Direct attack on the ~64-128µs/call cost.
- **Cons:** major scope (~weeks; new FFI surface, replace `librustls-mojo` with `libboringssl-mojo`). Per Topic 2 research, both stacks are competitive on full handshakes for ECDHE-RSA but rustls historically 5-15% slower for TLS 1.3 PSK resumption.
- **Expected lift:** ~5-15% short-conn rps (96µs × 0.15 saving × 1281 conns/sec = 18ms/sec saved = ~3% of CPU = ~5% rps lift; could be higher if PSK-resumption gap is wider).

### Lever D — Non-FFI cost decomposition (drain, frame_parse, conn alloc, QPACK setup)
- **Pros:** Q4 measured `per_pkt_us.drain` at 13.4% + `per_pkt_us.frame_parse` at 6.3% = 19.7% of busy. Plus conn allocation + QPACK/H3 setup not yet decomposed (likely ~5-10% more).
- **Cons:** requires a new diagnostic spec (Q6) to decompose these phases per-fresh-conn. Likely smaller per-frame wins (each frame ~5-10% of busy individually).
- **Expected lift:** combined ~15-25% rps potential; concrete numbers need Q6.

### Lever C — Reduce `read_hs` call count by reducing levels
0-RTT (P3) lets request data piggyback on ClientHello at level 0, eliminating the level-2 round-trip — but the client's Finished still arrives separately at level 2, so server-side read_hs count would NOT drop from 2 to 1 (still 2 levels). 0-RTT primarily reduces wall-clock (saves 1 RTT) and datagram count, not read_hs count. Marginal Q5 lever.

### Recommended next: **Lever D — Q6 non-FFI cost decomposition spec**
- Highest single-spec lift potential without major scope changes.
- Lower risk than Lever A's TLS-lib swap.
- Diagnostic-first per `feedback_perf_impact_floor_filter.md` — decompose drain/frame_parse/QPACK setup before authoring optimization specs.

P3 (0-RTT) and Lever A (boringssl) remain pending; pursued only after Lever D's measurement evidence indicates it's the bigger lever.

## Off-build flag

`comptime PROFILE_ACCEPT: Bool = False` reverted post-capture at `src/quic/profile.mojo:16`.

## Image SHAs (tag-isolated)

- `mojo-net-bench:q5-pre-off`: `dc7717c49121` (re-tag of `gate-cal-off`)
- `mojo-net-bench:q5-pre-on`: `fb9d2dfc8b78`
- `mojo-net-bench:q5-post-off`: built T3
- `mojo-net-bench:q5-post-on`: built T3 (currently in use)

To be torn down at T5 per `feedback_bench_offbuild_image_hygiene.md`.
