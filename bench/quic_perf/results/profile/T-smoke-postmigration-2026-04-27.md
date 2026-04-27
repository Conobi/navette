# Smoke Gate — addr_key→DCID demux migration

Plan: `plans/2026-04-27-quic-addr-key-to-dcid-demux-migration.md`
Spec: `specs/2026-04-27-quic-addr-key-to-dcid-demux-migration.md`
Branch: `feat/quic-addr-key-to-dcid-demux-migration`
Base SHA: `a9b947e1eb347d97535f364781795b3ada6f20c4`
Date: 2026-04-27

## T0 — Pre-migration off-build baseline (`comptime PROFILE_ACCEPT: Bool = False`)

### Long-conn cell (`bench.sh mojo-net 1k long-conn tquic_client --iters 3`)

| iter | rps |
|---|---|
| 1 | 362.82 |
| 2 | 423.12 |
| 3 | 420.23 |
| **median** | **420.23** |

### Short-conn cell (`bench.sh mojo-net 1k short-conn tquic_client --iters 3`)

| iter | rps |
|---|---|
| 1 | 0.48 |
| 2 | 0.26 |
| 3 | 0.26 |
| **median** | **0.26** |

These medians are the references for T8 ≤10% drift checks (long-conn) and the absolute hard gate (short-conn ≥ 2.0 rps post-migration).

## Pre-spec test count anchor (Step 6)

`bash scripts/run_tests.sh 2>&1 | grep -cE '^PASS:'` = **33** (set -e halts at the pre-existing `test_tls_connection` failure; the count reflects what runs before the halt — same anchor as the prior counter pass).

Acceptance criterion 1 post-migration target: **33 + 3 = 36** (T1 adds `test_is_long_header_initial_5_cases`; T2 adds `test_quic_connection_dcid_lengths_are_8_bytes`; T7 adds `test_dcid_demux_disambiguates_two_conns`).

## Spec amendment (Step 5)

The spec's planned third "zero-rotation" cell is flag-equivalent to long-conn (both use `MAX_REQUESTS_PER_CONN=0` per `bench/quic_perf/configs/long-conn.env`). Adding a third config file with the same effective behavior provides no extra signal. **Cell dropped from the plan; 2-cell smoke gate (long + short) used instead, mirroring the prior counter pass.**

A future "true single-conn-per-port" cell would require parameterising `--max-concurrent-conns 25` in `run-tquic-client.sh` (currently hardcoded) — out of scope for this migration.
