# P2 T0 — Pre-Spec Anchors

**Branch:** `perf/short-conn-resumption`
**Source HEAD:** `f22647b` (main; pre-P2)
**Docker image:** `mojo-net-bench:p2-pre-off` (image ID `c0daf44b5d7a`, rebuilt from `f22647b` source state)
**PROFILE_ACCEPT at build time:** `False` (off-build)

## Test count anchor

`TESTS_FILTER=test_(quic|h3|qpack)*.mojo` — counted statically via `grep -c '^def test_'` across the registered test array in `scripts/run_tests.sh`:

**Total: 341 test functions** across 23 test files.

The +7 invariant for P2: post-T4 count must equal 348.

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
| test_quic_profile.mojo | 55 |
| test_quic_profile_wiring.mojo | 3 |
| test_quic_recovery.mojo | 15 |
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

## Notes on T0 deviation

- Spec §9 / plan T0 specify `n=10` rounds for both long-conn and short-conn baselines. Per `feedback_bench_iter_count.md` n=10 is the default.
- Bench captures are running async (background) post-crash recovery. Final `p2-pre-rps.csv` will land in a follow-up commit before T6.
- tquic_client `--session-file` spike (per spec §7.1 table) also pending — captured in `p2-spike-results.md` once complete.

## Why no PROFILE_ACCEPT-on baselines yet

T0 only captures off-build baselines (P2 will compare off-vs-off and on-vs-on at T6). On-build baselines are post-T4 work since the new counter machinery only exists post-T1.
