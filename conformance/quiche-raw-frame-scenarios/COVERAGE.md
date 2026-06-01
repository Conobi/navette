# Quiche-Raw-Frame Coverage Index

This file is the coverage index for the quiche-raw-frame harness, scoped to
clusters C2 (RFC 9000 §12.4 / §17.x packet-layer guards), C3 (RFC 9000 §19.x
client-only frames received by server), C4 (RFC 9000 §19.x stream-id /
flow-control / encoding limits), C5 (RFC 9000 §19.15 NEW_CONNECTION_ID
encoding), and C7 (RFC 9001 §8.3 0-RTT / N/A for this cycle) from
`research/h3spec-failure-triage.md`.

## What's covered

- **Phase α (this commit):** 16 scenario binaries built. Table A rows are
  all `red` pending the Phase β Mojo guards. The companion `sanity_get`
  baseline is enumerated as Table B / SY01 (mirrors the TLS-conformance
  pattern); `coverage_check.py` is invoked with `--always-on-count 0` so
  the sanity baseline is counted exactly once.

## What's deferred

- **F30 — `deferred:quiche-raw-frame` → `not-applicable`:** 0-RTT
  injection is out of scope for v1; will be revisited when 0-RTT keys
  are scenarised (post-v1 backlog `project_h3_migration_then_0rtt`).
  Tracked in `conformance/h3i-scenarios/COVERAGE.md`; not in Table A
  here because it has no scenario binary.

## Table A — h3spec triage rows

| failure_id | cluster | rfc_clause | status | scenario_binary |
|---|---|---|---|---|
| F01 | C4 | RFC 9000 §4.1 | gated | s_f01_stream_large_offset |
| F10 | C3 | RFC 9000 §12.4 | gated | s_f10_unknown_frame |
| F11 | C2 | RFC 9000 §12.4 | gated | s_f11_no_frames |
| F12 | C2 | RFC 9000 §17.2 | red | s_f12_reserved_bits_hs |
| F13 | C2 | RFC 9000 §17.2.4 | red | s_f13_path_challenge_hs |
| F14 | C2 | RFC 9000 §17.2 | gated | s_f14_reserved_bits_short |
| F15 | C4 | RFC 9000 §19.4 | red | s_f15_reset_on_server_uni |
| F16 | C4 | RFC 9000 §19.5 | red | s_f16_stop_sending_local_not_created |
| F17 | C3 | RFC 9000 §19.7 | gated | s_f17_new_token_server |
| F18 | C4 | RFC 9000 §19.10 | gated | s_f18_max_stream_data_nonexist |
| F19 | C4 | RFC 9000 §19.10 | red | s_f19_max_stream_data_recv_only |
| F20 | C4 | RFC 9000 §19.11 | red | s_f20_max_streams_overflow |
| F21 | C4 | RFC 9000 §19.14 | gated | s_f21_streams_blocked_overflow |
| F22 | C5 | RFC 9000 §19.15 | gated | s_f22_cid_retire_prior_gt_seq |
| F23 | C5 | RFC 9000 §19.15 | gated | s_f23_cid_zero_length |
| F24 | C3 | RFC 9000 §19.20 | gated | s_f24_handshake_done_server |
| F30 | C7 | RFC 9001 §8.3 | not-applicable | — |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9000 §1 | sanity_get | Always-on baseline: a clean QUIC + H3 handshake completes successfully and the server responds to GET /, confirming the harness runner is wired before any adversarial raw-frame injection. |
