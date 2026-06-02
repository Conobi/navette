# Quiche-Raw-Frame Coverage Index

This file is the coverage index for the quiche-raw-frame harness, scoped to
F-rows F01 + F10–F24 + F30 — covering packet-layer guards (RFC 9000 §12.4 /
§17.x), server-illegal frame dispatch (RFC 9000 §19.x client-only frames),
stream-state and limit checks (RFC 9000 §19.x stream-id / flow-control /
encoding), NEW_CONNECTION_ID encoding (RFC 9000 §19.15), and the 0-RTT
CRYPTO row (RFC 9001 §8.3 — server-side decrypt path landed; the scenario
binary drives ticket issuance → resumed-connect → 0-RTT CRYPTO injection
against a navette server with `HELLO_H3_MAX_EARLY_DATA=max` enabled).

## What's covered

- **17 Table A rows + 1 Table B row gated:** all packet-layer,
  server-illegal-frame, stream-state, and Handshake-epoch
  reserved-bit / PATH_CHALLENGE guard scenarios pass, plus F30's
  0-RTT CRYPTO injection. The companion `sanity_get` baseline is
  enumerated as Table B / SY01 (mirrors the TLS-conformance pattern);
  `coverage_check.py` is invoked with `--always-on-count 0` so the
  sanity baseline is counted exactly once.

## Table A — h3spec triage rows

| failure_id | rfc_clause | status | scenario_binary |
|---|---|---|---|
| F01 | RFC 9000 §4.1 | gated | s_f01_stream_large_offset |
| F10 | RFC 9000 §12.4 | gated | s_f10_unknown_frame |
| F11 | RFC 9000 §12.4 | gated | s_f11_no_frames |
| F12 | RFC 9000 §17.2 | gated | s_f12_reserved_bits_hs |
| F13 | RFC 9000 §17.2.4 | gated | s_f13_path_challenge_hs |
| F14 | RFC 9000 §17.2 | gated | s_f14_reserved_bits_short |
| F15 | RFC 9000 §19.4 | gated | s_f15_reset_on_server_uni |
| F16 | RFC 9000 §19.5 | gated | s_f16_stop_sending_local_not_created |
| F17 | RFC 9000 §19.7 | gated | s_f17_new_token_server |
| F18 | RFC 9000 §19.10 | gated | s_f18_max_stream_data_nonexist |
| F19 | RFC 9000 §19.10 | gated | s_f19_max_stream_data_recv_only |
| F20 | RFC 9000 §19.11 | gated | s_f20_max_streams_overflow |
| F21 | RFC 9000 §19.14 | gated | s_f21_streams_blocked_overflow |
| F22 | RFC 9000 §19.15 | gated | s_f22_cid_retire_prior_gt_seq |
| F23 | RFC 9000 §19.15 | gated | s_f23_cid_zero_length |
| F24 | RFC 9000 §19.20 | gated | s_f24_handshake_done_server |
| F30 | RFC 9001 §8.3 | gated:green | s_f30_crypto_in_zero_rtt |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9000 §1 | sanity_get | Always-on baseline: a clean QUIC + H3 handshake completes successfully and the server responds to GET /, confirming the harness runner is wired before any adversarial raw-frame injection. |
