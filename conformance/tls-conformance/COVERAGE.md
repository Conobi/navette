# TLS-Conformance Coverage Index

This file is the coverage index for the TLS-conformance harness, scoped to
clusters C1 (QUIC transport-parameter validation, RFC 9000 §7/§18) and C6
(QUIC-side TLS-alert plumbing, RFC 9001 §6/§8) from
`research/h3spec-failure-triage.md`.

**Current state:** 13 of the 14 C1+C6 rows are `red` — binaries exist as
exit-1 stubs; they do not yet pass. Threshold file
`conformance/tls_conformance_min_pass.txt` starts at `0` and bumps to `15`
(`gated_a=13 + gated_b=1 + 1`) when implementation completes and all rows
flip to `gated`.

F28 is `deferred:f28` because rustls 0.23.37 does not expose an API to omit
the QUIC transport-parameters extension; no scenario binary can exercise that
rejection path in this harness cycle.

## Table A — h3spec triage rows

| failure_id | cluster | rfc_clause | status | scenario_binary |
|---|---|---|---|---|
| F02 | C1 | RFC 9000 §7.3 | red | f02_initial_scid_missing |
| F03 | C1 | RFC 9000 §18.2 | red | f03_original_dcid_forbidden |
| F04 | C1 | RFC 9000 §18.2 | red | f04_preferred_addr_forbidden |
| F05 | C1 | RFC 9000 §18.2 | red | f05_retry_scid_forbidden |
| F06 | C1 | RFC 9000 §18.2 | red | f06_stateless_reset_forbidden |
| F07 | C1 | RFC 9000 §7.4 | red | f07_max_udp_payload_range |
| F08 | C1 | RFC 9000 §7.4 | red | f08_ack_delay_exp_range |
| F09 | C1 | RFC 9000 §7.4 | red | f09_max_ack_delay_range |
| F25 | C6 | RFC 9001 §6 | red | f25_keyupdate_in_handshake |
| F26 | C6 | RFC 9001 §6 | red | f26_keyupdate_in_1rtt |
| F27 | C6 | RFC 9001 §8.1 | red | f27_no_alpn |
| F28 | C6 | RFC 9001 §8.2 | deferred:f28 | - |
| F29 | C6 | RFC 9001 §8.3 | red | f29_end_of_early_data |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9000 §1 | tls_sanity_handshake | Always-on baseline: a clean TLS handshake completes successfully, confirming the harness runner and navette TLS stack are wired correctly before any adversarial tests run. |
