# Q4 Verdict — Per-Fresh-Conn Server CPU Decomposition

**Date:** 2026-05-03
**Branch:** `feat/quic-q4-fresh-conn-cpu-decomp`
**Image:** `mojo-net-bench:q4-post-on` (PROFILE_ACCEPT=True; source `b39ac3b`)
**Method:** n=3 short-conn captures, 30s × 4 client threads × 25 concurrent conns × 1 request per conn (`SESSION_FILE` enabled per P2).

## VERDICT: CONFIRMED

**Top frame:** **rustls FFI thunk path** (`per_pkt_us.shim_ffi` + state-machine work).
**Contribution:** ~45% of busy CPU.
**Next-largest distinct frame:** `per_pkt_us.drain` at ~13% of busy.
**Ratio:** 3.7× — far exceeds the 1.5× CONFIRMED threshold (per spec §6, AC8).

## Captured numbers

### Per-iter rps + CPU

| Iter | rps | CPU% |
|---|---|---|
| 1 | 1,041 | 57.8 |
| 2 | 1,302 | 59.7 |
| 3 | 1,281 | 57.7 |
| **median** | **1,281** | **57.7** |

Comparable to P2's post baseline (1,224 rps, 57.3% CPU) — the +57 rps gap is host-noise within the variance band.

### Per-fresh-conn FFI total (`fresh_conn_ffi_us_buckets`)

| Iter | Bucket 8 (~256-512µs) | Bucket 9 (~512-1024µs) | Bucket 10+ | Total samples |
|---|---|---|---|---|
| 1 | 32,288 | 4,871 | 393 | 37,552 |
| 2 | 46,632 | 1,507 | 57 | 48,196 |
| 3 | 45,418 | 1,600 | 62 | 47,080 |

**Median bucket dominance: ~95% of conns in bucket 8.** Per-fresh-conn FFI total is consistently ~256-512µs/conn. At ~1,281 conns/sec, that's ~330-650 ms/sec spent in FFI per server thread = consistent with `per_pkt_us.shim_ffi` total below.

### Per-pkt phase decomposition

| Phase | Iter 1 | Iter 2 | Iter 3 | Median % busy |
|---|---|---|---|---|
| `per_pkt_us.shim_ffi` | 42.6% | 46.0% | 46.1% | **45.6%** |
| `per_pkt_us.sm` (state machine, overlaps shim_ffi) | 46.7% | 49.6% | 49.6% | **49.0%** |
| `per_pkt_us.drain` | 13.9% | 13.1% | 13.1% | **13.4%** |
| `per_pkt_us.frame_parse` | 7.3% | 6.3% | 6.3% | **6.3%** |
| `per_pkt_us.aead` | 1.8% | 1.4% | 1.4% | **1.4%** |
| `per_pkt_us.hp` | 1.2% | <1% | <1% | **<1%** |

Note: profile.mojo's residual computation explicitly says "ffi NOT subtracted (overlaps sm)". So `per_pkt_us.sm` includes the time spent INSIDE the FFI thunks. The "rustls FFI thunk path" cost is best read as the union of `shim_ffi` (the Mojo↔Rust crossing wall-time, ~45%) and the `sm` minus `shim_ffi` overlap (rustls work outside FFI ≈ 0-4%).

### Recv-batch-size histogram (`recv_batch_size_buckets`)

| Iter | size=1 | size=2-3 | size=4+ |
|---|---|---|---|
| 1 | 387,464 | 0 | 0 |
| 2 | 494,749 | 0 | 0 |
| 3 | 481,443 | 0 | 0 |

**100% of recvmsg CQEs deliver n=1 datagram.** This is the architectural reality of io_uring multishot recvmsg — each CQE = 1 datagram. The diagnostic signal is that there is **no kernel-level batching**: every datagram traverses the full Mojo dispatch path independently, and `recvmmsg` (or `io_uring_recvmsg` non-multishot with batched delivery) is a real next-spec target.

### Handshake kinds (P2 sanity)

| Iter | full | resumed | r |
|---|---|---|---|
| 1 | 298 | 37,254 | 0.992 |
| 2 | 336 | 47,860 | 0.993 |
| 3 | 336 | 46,744 | 0.993 |

Resumption rate 99.3% — confirms P2's behavior is unchanged by Q4.

## Implications for the next optimization spec

The Q4 diagnostic identifies **two complementary levers** for short-conn parity with TQUIC (which hits 2,535 rps on the same hardware):

### Lever 1 (largest): Per-fresh-conn FFI thunk reduction (~45% of busy)

Each fresh handshake spends ~256-512µs in Mojo↔Rust FFI thunks. The rustls state-machine work itself (`sm - shim_ffi` overlap) is only ~0-4% of busy — the marshalling overhead dominates. Candidate optimizations:

- **Combine FFI calls.** `_drive_handshake` makes 1× `read_hs` + N× `write_hs` + N× `take_keys` per handshake. If `write_hs` and `take_keys` could be fused into one FFI call returning (out_buf, kc, keys_handle) atomically, that's a ~50% reduction in FFI crossings on the handshake path.
- **Cache config-derived constants Mojo-side.** Each call pays for parameter marshalling. If TLS cipher info, ALPN, or other static config could be cached on first lookup and reused, marshalling cost drops.
- **Investigate boucle vs the existing FFI pattern.** TQUIC's boringssl is an in-process C library — no Rust↔Rust thunk cost equivalent. mojo-net pays Mojo→Rust→C transitions per call.

Spec target: reduce `per_pkt_us.shim_ffi` from 45% → 25% of busy. Expected rps lift on short-conn: ~30-40% (from 1,281 → ~1,700-1,800).

### Lever 2 (complementary): `recvmmsg` batching (delivery model)

Every recvmsg CQE delivers n=1 datagram. At ~485k datagrams per 30s, that's 16k CQEs/sec → 16k Mojo dispatches/sec. With `recvmmsg` (or non-multishot batched io_uring), the kernel could deliver e.g. 16 datagrams per CQE → 1k dispatches/sec, reducing per-dispatch overhead.

This is a **boucle-side change** (or a switch from multishot recvmsg to alternative io_uring patterns), not a mojo-net-internal optimization. May warrant pairing with P3 (0-RTT) since 0-RTT also reduces datagram count per fresh conn.

### What NOT to pursue next

- ~~P4 worker pool~~ — already falsified by Topic 2 research.
- ~~P3 0-RTT alone~~ — its lift compounds onto FFI cost; without Lever 1 first, P3's marginal benefit will be small.
- Long-conn optimizations — long-conn already at 1.306× TQUIC; not the binding constraint.

## Off-build flag verified

`comptime PROFILE_ACCEPT: Bool = False` at `src/quic/profile.mojo:16` post-capture. PROFILE_ACCEPT=True image (`mojo-net-bench:q4-post-on`) retained for tag teardown at T6.
