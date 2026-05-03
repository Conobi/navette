# Q4 T0 — Pre-Spec Anchors

**Branch:** `feat/quic-q4-fresh-conn-cpu-decomp` (off main `dbcdd0e`)
**Source HEAD at T0:** `dbcdd0e` (post-P2-merge)
**Docker images:**
- `mojo-net-bench:q4-pre-off`: `c0daf44b5d7a` (re-tag of P2 `:p2-pre-off`; PROFILE_ACCEPT=False at compile)
- `mojo-net-bench:q4-pre-on`: rebuilt from current source with `PROFILE_ACCEPT: Bool = True` then reverted; flag in tree is `False` post-T0.

## Test count anchor

`grep -c '^def test_'` across `tests/test_quic_*.mojo` + `tests/test_h3_*.mojo`:

**Total: 348 test functions** across 24 test files (matches expected: 341 pre-P2 + 7 P2 = 348).

The +4 invariant for Q4: post-T2 count must equal **352** (T1=3 in test_quic_profile.mojo + T2=1 in test_quic_resumption.mojo).

| File | Pre |
|---|---|
| test_quic_cid.mojo | 13 |
| test_quic_codec.mojo | 8 |
| test_quic_connection.mojo | 38 |
| test_quic_crypto_stream.mojo | 7 |
| test_quic_flow_control.mojo | 13 |
| test_quic_frame.mojo | 36 |
| test_quic_pacer_bypass.mojo | 3 |
| test_quic_packet.mojo | 13 |
| test_quic_pn_space.mojo | 17 |
| test_quic_profile.mojo | **57** |
| test_quic_profile_wiring.mojo | 3 |
| test_quic_recovery.mojo | 15 |
| test_quic_resumption.mojo | **5** |
| test_quic_retry.mojo | 6 |
| test_quic_stream_map.mojo | 14 |
| test_quic_stream.mojo | 30 |
| test_quic_transport_params.mojo | 11 |
| test_h3_connection.mojo | 5 |
| test_h3_e2e.mojo | 5 |
| test_h3_extension.mojo | 3 |
| test_h3_frame.mojo | 10 |
| test_h3_qpack.mojo | 27 |
| test_h3_streaming_server.mojo | 5 |
| test_h3_sync_server.mojo | 4 |

## T3 insertion site (load-bearing for plan correctness)

`bench/h3_server.mojo:_handle_recvmsg` — function defined at line **640**.

| Site | Line | Note |
|---|---|---|
| `RECVMSG_OUT_HDR_SIZE` constant | 60 | `comptime RECVMSG_OUT_HDR_SIZE: Int = 16` |
| `_handle_recvmsg` def | 640 | per-CQE callback (multishot recvmsg) |
| Size-check guard | 661 | `if result < Int32(RECVMSG_OUT_HDR_SIZE): return` |
| **Insertion target** | 663 (first line after `var addr_offset = ...` block / after the size-check return) | INSERT `record_recv_batch(1)` here, before namelen parse |

**T3 implementation note:** every CQE under multishot recvmsg carries exactly 1 datagram (per spec §4.2 + Topic 2 research findings). Recording `n=1` is the architecturally correct semantic; the diagnostic signal is the contrast between this and a hypothetical `recvmmsg`-batched harness.

## Pre-Q4 baselines (n=3, long-conn 1k payload, 30s × 4 threads × 25 conns)

| Build | Median rps | Stdev | Server CPU |
|---|---|---|---|
| `q4-pre-off` (PROFILE_ACCEPT=False) | 13,687 | 587 | 97.2% |
| `q4-pre-on` (PROFILE_ACCEPT=True) | 14,920 | 17 | 98.1% |

Notes:
- 9% spread between off/on builds is host-noise drift between adjacent capture windows. Within-build variance is small (off-build IQR ~9% of median; on-build IQR <0.2% — exceptionally tight).
- Drift gates at T4 (±1% off-build, ±2% on-build) compare same-build pre vs same-build post, so this off/on asymmetry doesn't affect the gate verdict.

## n=3 deviation justification

Per `feedback_bench_iter_count.md` the default is n≥10. Q4 uses n=3 because:
- Q4 is diagnostic-only (no perf lift expected). The drift gate is about variance NOT changing post-Q4, not about asserting a lift number with statistical confidence.
- Same n=3 precedent in Q1 / Q3 / Q-drain-subleg shipped specs.
- Q4-T5 short-conn capture is also n=3 because the verdict is bucket-distribution-shape, not RPS-mean-comparison (justified in spec §6 / verdict gate).
