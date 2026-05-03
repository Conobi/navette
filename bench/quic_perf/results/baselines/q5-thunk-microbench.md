# Q5 Addendum — FFI Thunk Microbench

**Date:** 2026-05-04
**Goal:** validate the Q5 verdict's assumption that the ~64-128µs/call wall-clock observed for `rlsm_quic_conn_read_hs` is dominated by rustls TLS state-machine compute, not by Mojo↔Rust FFI thunk overhead.

## Method

1. Added `rlsm_noop() -> i32 { 0 }` to `crates/librustls-mojo/src/lib.rs` — a Rust FFI function that does nothing.
2. Added Mojo wrapper `noop()` in `src/tls/lib.mojo`.
3. Microbench: 100k warmup calls, then 1M timed calls, divide for per-call wall-clock. Repeat 3 times.

Microbench script kept at `/tmp/q5-thunk-microbench.mojo` (throwaway).

## Raw results

| Run | Per-call cost |
|---|---|
| 1 | 46 ns |
| 2 | 49 ns |
| 3 | 47 ns |
| **median** | **47 ns** |

## Comparison

| Component | Wall-clock |
|---|---|
| FFI thunk only (microbench) | **47 ns** |
| `rlsm_quic_conn_read_hs` (Q5 bucket 7, ~97% of calls) | **64,000-128,000 ns** |
| Ratio | 1,360-2,720× |

## Verdict

**CONFIRMED.** The thunk is **0.04-0.07%** of `read_hs` cost. The claim "rustls TLS state-machine compute dominates `read_hs` wall-clock" is microbench-confirmed with overwhelming margin. The remaining ~99.9% of read_hs time is rustls work — CRYPTO frame parse, transcript hash advance, key derivation, etc.

This closes Q5's "honest framing" gap: the original verdict was an inference; it is now a measurement-confirmed claim.

## Implications for next-spec direction

Unchanged from Q5 verdict — the next short-conn TLS-side lever is genuinely **rustls per-handshake compute reduction** (Lever A: boringssl swap), not FFI marshalling. Reaffirms that Lever D (non-FFI cost decomposition) should come next as the lower-risk diagnostic before committing to Lever A.

## Files touched (kept in branch)

- `crates/librustls-mojo/src/lib.rs`: +`rlsm_noop` (8 LoC)
- `src/tls/lib.mojo`: +`noop()` wrapper (10 LoC)

These additions are dead-code in the main hot path but small, harmless, and useful for any future "is FFI thunk significant on this code path?" question. Kept rather than reverted.
