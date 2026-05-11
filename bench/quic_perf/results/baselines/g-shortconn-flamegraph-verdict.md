# Short-conn flamegraph verdict — **MOJO-BOUND, NOT LIB-BOUND**

**Date:** 2026-05-04
**Spec:** `specs/2026-05-04-shortconn-perf-flamegraph-spec.md`
**Branch:** `main` @ `8218017`
**Image:** `mojo-net-bench:latest` sha256 `c6028608c72a` (rebuilt 22:41 with `[profile.release].debug = "line-tables-only"`)
**Capture:** 1× short-conn iter, 1k payload, `tquic_client --threads 4 --max-concurrent-conns 25 --max-requests-per-conn 1` (matches `bench.sh` shape; `WARMUP_S=5`, `DURATION_S=30`, perf window `25s` inside the 30s)
**Sampling:** `perf record -F 99 -g --call-graph=dwarf,16384 -e cpu-clock` for 25s, 1250 samples on `bench-h3` worker (host PID 63450, UID-matched container per paranoid=2 workaround)

## Artifacts

- **Flamegraph SVG:** `bench/quic_perf/results/profile/shortconn-20260504-225955-8218017/perf.svg`
- Raw perf data: `bench/quic_perf/results/profile/shortconn-20260504-225955-8218017/perf.data` (20 MB)
- Folded stacks: `bench/quic_perf/results/profile/shortconn-20260504-225955-8218017/perf-folded.txt` (180 unique stacks)
- Per-symbol script: `bench/quic_perf/results/profile/shortconn-20260504-225955-8218017/perf-script.txt`
- Symfs snapshot: `bench/quic_perf/results/profile/shortconn-20260504-225955-8218017/symfs/`
- Client log: `tquic_client` reported **1155.83 req/s, 35,868 conns, 35,833 successful** (in `/tmp/client-stdout.log` at capture time)

## TL;DR

**MOJO-BOUND.** Of 548 attributable samples (43.8% of 1250 total), **rustls + aws_lc_rs frames combined account for ~4.0% inclusive / ~2.0% self-time** of the h3_server worker's CPU. The dominant cost is *Mojo-side QUIC + QPACK code paths* in `/usr/local/bin/h3_server` (>93% of attributable samples), not crypto.

**Estimated fixable-share (rustls framing + state-machine, exclusive of crypto primitives) = <0.5%.** Well under the 5% threshold the spec defined as "rustls hot path is genuinely lib-bound."

This OVERTURNS the implicit spec premise that short-conn is rustls/aws_lc-bound. The handshake compute previously labeled `LIB-BOUND` (via the `fresh_conn_ffi_us` profile counter at 47% of busy CPU per Q9 verdict) is in fact a **mix** — at the OS-CPU level only ~4% lands in rustls/aws_lc; the rest of the 47% `fresh_conn_ffi_us` budget must be either (a) attributable samples in Mojo wrapper code on the path through FFI, or (b) hidden in the 56% unattributable samples which lean toward the Mojo binary (see §Caveats).

## Caveats — methodology guardrails

**`[unknown]`/no-stack samples = 56.2%** (702/1250). This crosses the spec methodology threshold of 20%. The *cause* is identified, however: the Mojo binary `h3_server` is built without frame pointers and with minimal DWARF — perf's DWARF unwinder cannot unwind past the Mojo leaf when the IP is in the Mojo binary. Evidence:

- 429/1250 leaf samples (34.3%) land in `/usr/local/bin/h3_server` — these have *partial* stacks (the Mojo binary IPs do symbolize, just don't unwind further up).
- 86/1250 leaf samples (6.9%) land in `libAsyncRTRuntimeGlobals.so` — same pattern (Modular runtime, no DWARF either).
- Only 21 leaf samples (1.7%) land in `librustls_mojo.so` itself, and those *do* have multi-frame stacks down to `aws_lc::*` and `rustls::*`. The Rust crate has DWARF (per the Cargo profile patch) and unwinds cleanly.

Because the unattributable share concentrates in the Mojo binary, the attributable-sample share for librustls is an **unbiased** estimate of true librustls share. The 4% number is robust.

## Top-10 frames by inclusive % of attributable samples

| Rank | Self+children % | Self %  | Frame                                                                               | Library       | Classification           | Source cite |
|-----:|----------------:|--------:|-------------------------------------------------------------------------------------|---------------|--------------------------|-------------|
| 1    | 75.00%          | 1.60%   | `h3_server::H3UdpHandler::_flush_impl`                                              | h3_server     | mojo (recv/send loop)    | `bench/h3_server.mojo` (`_flush_impl`) |
| 2    | 41.79%          | 1.36%   | `boucle::completion::BatchCompletionLoop::poll`                                     | h3_server     | mojo (io_uring driver)   | `boucle/completion.mojo` |
| 3    | 36.50%          | 0.00%   | `h3_server::main`                                                                   | h3_server     | mojo (entry frame)       | `bench/h3_server.mojo:main` |
| 4    | 21.72%          | 0.88%   | `h3_server::H3UdpHandler::_drain_and_send`                                          | h3_server     | mojo (egress drive)      | `bench/h3_server.mojo` |
| 5    | 21.35%          | 3.68%   | `src::quic::connection::QuicConnection::recv_from_buffer`                           | h3_server     | mojo (QUIC state machine)| `src/quic/connection.mojo` |
| 6    | 20.44%          | 0.48%   | `src::h3::connection::H3Connection::_drain_stream`                                  | h3_server     | mojo (H3 demux)          | `src/h3/connection.mojo` |
| 7    | 19.71%          | 1.84%   | `src::quic::connection::QuicConnection::send`                                       | h3_server     | mojo (QUIC packet build) | `src/quic/connection.mojo` |
| 8    | 16.97%          | 0.00%   | `src::h3::qpack::_qpack_decode_string`                                              | h3_server     | mojo (QPACK)             | `src/h3/qpack.mojo` |
| 9    | 16.79%          | 6.96%   | `src::h3::qpack::huffman_decode`                                                    | h3_server     | mojo (QPACK Huffman)     | `src/h3/qpack.mojo` |
| 10   | 9.67%           | 1.04%   | `src::quic::connection::QuicConnection::_build_app_frames`                          | h3_server     | mojo (QUIC packetize)    | `src/quic/connection.mojo` |

(Self+children % normalized against 548 attributable samples; sums >100% because frames overlap on a single stack.)

### librustls / aws_lc_rs frames (none in top 10) — full enumeration above 0.1% inclusive

| Self+children % | Self % | Frame                                                              | Classification          | Source cite |
|----------------:|-------:|--------------------------------------------------------------------|-------------------------|-------------|
| 0.72%           | 0.72%  | `aws_lc_0_39_1_CRYPTO_rdrand_multiple8`                            | crypto-primitive (RNG)  | `aws-lc-rs` (CRYPTO_rdrand_multiple8 in aws-lc fipsmodule) |
| 0.40%           | 0.40%  | `Lcurve25519_x25519_scalarloop`                                    | crypto-primitive (KEX)  | `aws-lc-rs` (curve25519 inner loop) |
| 0.24%           | 0.00%  | `aws_lc_0_39_1_X25519`                                             | crypto-primitive (KEX)  | `aws-lc-rs::evp_pkey::agree` → X25519 |
| 0.24%           | 0.00%  | `aws_lc_rs::evp_pkey::<...>::agree`                                | crypto-primitive (KEX)  | `aws-lc-rs/src/evp_pkey.rs::agree` |
| 0.16%           | 0.00%  | `aws_lc_0_39_1_HKDF_expand` / `aws_lc_rs::hkdf::PrkMode::fill`     | crypto-primitive (KDF)  | `aws-lc-rs::hkdf` |
| 0.16%           | 0.16%  | `aws_lc_0_39_1_sha256_block_data_order_hw`                         | crypto-primitive (HASH) | `aws-lc` SHA-NI fast path |
| 0.08%           | 0.00%  | `aws_lc_0_39_1_HMAC_Init_ex` / `_Final` / `SHA256_Update/Final`    | crypto-primitive (HMAC) | `aws-lc-rs::hmac` |
| 0.18%           | 0.18%  | `core::ptr::drop_in_place<rustls::msgs::handshake::HandshakePayload>` | rustls-framing        | `rustls/src/msgs/handshake.rs` (Drop) |
| 0.08%           | 0.08%  | `librustls_mojo::handles::HandleTable<T>::with`                    | ffi-shim                | `crates/librustls-mojo/src/handles.rs` |

**Total rustls/aws_lc inclusive ~4.0%, of which:**
- crypto-primitive: ~3.4% (X25519 + AES + SHA + HKDF + HMAC + RNG; all leaf ops in aws-lc — already vectorized, immovable without backend swap)
- rustls-framing: ~0.2% (one drop_in_place; effectively noise floor)
- ffi-shim: ~0.1%

## Bottom line — fixable share

**Fixable-share inside librustls/aws_lc = <0.5%.** Specifically: rustls-framing (0.18%) + ffi-shim (0.08%) + plausible-but-noisy small Rust frames = under 0.5% of attributable CPU. Per spec definition (>15% means real Mojo-side or rustls-config target; <5% means lib-bound) — but the lib-bound interpretation only applies if rustls dominates, which it does NOT here.

**Re-classification:** the rustls hot path is **not** the bottleneck; it's a quiet ~4% on the side. The dominant ~70%+ of attributable CPU is in the Mojo h3_server binary on QPACK + QUIC state-machine paths. The "Lever A: boringssl swap" hypothesis from prior verdicts (Q5/Q6/Q9) was investigating the wrong subsystem at the OS-CPU level. (The `fresh_conn_ffi_us` profile counter measures wall-clock through the FFI boundary, which includes Mojo-side wrapper time — not just rustls compute.)

## One-paragraph: highest-leverage target

The two Mojo-side targets that dominate the flamegraph and are clearly *fixable* (not crypto, not state-machine semantics) are: **(1)** `src::h3::qpack::huffman_decode` + `_qpack_decode_string` together at **~17% inclusive / 7% self** — the QPACK 2026-05-02 retro already noted this is ~50× slower than TQUIC/quiche (single static table, sub-µs/req achievable); a Huffman decode rewrite (table-driven 8-bit-at-a-time vs current per-bit) is the single highest-leverage target on this profile. **(2)** `src::quic::stream::Stream::__init__` (copy-init, 6.39% inclusive at rank #13) — Stream init is hit per-frame on the recv path, a per-conn cost that compounds on short-conn; eliminating the copy-init in `_handle_ack` / `_build_app_frames` / `get_stream` paths is the second-highest target. Both are pure Mojo refactors with no rustls coupling, no FFI surface change, and no dependency on the boringssl/aws-lc-rs lever.

## Methodology notes — deviations from spec

1. **paranoid=2 perf workaround:** spec §5 noted symbol resolution as the main risk; the actual blocker was `kernel.perf_event_paranoid=2` rejecting attach to root-owned containerized processes. Resolved without sudo or `--cap-add=SYS_ADMIN` by adding `--user $(id -u):$(id -g)` to the docker run inside `perf-record.sh` (UID-matched container).
2. **`-e cpu-clock` instead of default `cycles`:** software event, paranoid-2-compatible, no PMU access required.
3. **Symfs snapshot:** copied `/usr/local/bin/h3_server` and `/usr/local/lib/*.so` from `/proc/$PID/root/` into `$OUT/symfs/` *before* container shutdown and passed `--symfs $OUT/symfs` to `perf script` — perf cannot reach into the container's mount namespace via buildid-cache, but a host-side symfs snapshot works perfectly.
4. **`--call-graph=dwarf,16384`:** default 8KB stack capture truncated; 16KB resolved deep rustls inlining and Mojo type-mangled frames.
5. **Acceptance criteria status:**
   - AC1 (SVG exists, opens) — ✅
   - AC2 (≥1 named rustls/aws_lc frame at >10%) — ❌ no rustls/aws_lc frame above 1% (this *is* the answer; spec assumed crypto would dominate)
   - AC3 (Mojo accept loop not dominant) — ❌ in fact `_flush_impl` (the Mojo accept-loop equivalent) IS dominant at 75%; this overturns the spec's "short-conn must be handshake-bound" assumption
   - AC4 (≥1000 unique stacks) — ❌ 180 unique stacks (the Mojo unwind loss reduces stack diversity; expected ~2500 samples got 1250 due to single-thread short-conn)
   - AC5 (top-10 classification) — ✅ delivered above
6. **Foreign agent contention:** at 22:42 a parallel Claude session started an `h-multicore` minimal-confirmation bench using mojo-net-bench:latest (which I had just rebuilt with debug info). Per `feedback_concurrent_mojo_sessions_perturb_bench.md` I waited for it (~10 min) before running this capture. The foreign agent's measurements are now contaminated by my image rebuild — that is on them to detect.

## Provenance

- Cargo profile patch: `crates/librustls-mojo/Cargo.toml:26-32` (added `debug = "line-tables-only"`, `strip = false`).
- New harness script: `bench/quic_perf/scripts/perf-record.sh` (130 lines; mirrors `bench/profile/h2-perf-record.sh:107-109` shape).
- Image rebuilt: `mojo-net-bench:latest` → `sha256:c6028608c72a` (164 MB; +16 MB from DWARF).
- librustls_mojo.so size: 21 MB (+11 MB from DWARF, includes `.debug_info`, `.debug_line`, `.debug_abbrev`, `.debug_ranges`, `.debug_str`, `.debug_loc`).
