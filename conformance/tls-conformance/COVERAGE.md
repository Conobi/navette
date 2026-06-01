# TLS-Conformance Coverage Index

This file is the coverage index for the TLS-conformance harness, scoped to
clusters C1 (QUIC transport-parameter validation, RFC 9000 §7/§18) and C6
(QUIC-side TLS-alert plumbing, RFC 9001 §6/§8) from
`research/h3spec-failure-triage.md`.

## What's covered

- **8 C1 rows gated (F02–F09):** all transport-parameter guard scenarios pass;
  navette rejects forbidden/out-of-range TP values with a tagged
  `TRANSPORT_PARAMETER_ERROR`.
- **1 C6 row gated (F27):** navette rejects a QUIC handshake that omits the
  ALPN extension with a tagged `TLS_HANDSHAKE_FAILED`.
- **1 C6 row gated (Table B / SY01):** baseline TLS handshake completes
  successfully, confirming harness runner and navette TLS stack are wired.

## What's deferred

- **F25, F26, F29 — `deferred:epoch-injection`:** these rows require the
  harness driver to inject CRYPTO frames into Handshake or 1-RTT epochs.
  `quiche`'s public API does not expose raw CRYPTO-frame injection for
  post-Initial epochs; a follow-up sub-cycle must add a lower-level injection
  path (or a dedicated raw-frame harness) before these can be scenarised.
- **F28 — `deferred:f28`:** rustls 0.23.37 does not expose an API to omit the
  QUIC transport-parameters extension; no scenario binary can exercise that
  rejection path in this harness cycle.

## Table A — h3spec triage rows

| failure_id | rfc_clause | status | scenario_binary |
|---|---|---|---|
| F02 | RFC 9000 §7.3 | gated | f02_initial_scid_missing |
| F03 | RFC 9000 §18.2 | gated | f03_original_dcid_forbidden |
| F04 | RFC 9000 §18.2 | gated | f04_preferred_addr_forbidden |
| F05 | RFC 9000 §18.2 | gated | f05_retry_scid_forbidden |
| F06 | RFC 9000 §18.2 | gated | f06_stateless_reset_forbidden |
| F07 | RFC 9000 §7.4 | gated | f07_max_udp_payload_range |
| F08 | RFC 9000 §7.4 | gated | f08_ack_delay_exp_range |
| F09 | RFC 9000 §7.4 | gated | f09_max_ack_delay_range |
| F25 | RFC 9001 §6 | deferred:epoch-injection | f25_keyupdate_in_handshake |
| F26 | RFC 9001 §6 | deferred:epoch-injection | f26_keyupdate_in_1rtt |
| F27 | RFC 9001 §8.1 | gated | f27_no_alpn |
| F28 | RFC 9001 §8.2 | deferred:f28 | - |
| F29 | RFC 9001 §8.3 | deferred:epoch-injection | f29_end_of_early_data |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9000 §1 | tls_sanity_handshake | Always-on baseline: a clean TLS handshake completes successfully, confirming the harness runner and navette TLS stack are wired correctly before any adversarial tests run. |
