# Coverage fixture — F03 is intentionally absent from Table A.

Tag literals exercised by scenario binaries: [QUIC-SAMPLE-A] [H3-SAMPLE-B]

## Table A — triage rows

| failure_id | rfc_clause | status | scenario_binary |
|---|---|---|---|
| F01 | RFC 9000 §1.1 | deferred:tls-conformance | — |
| F02 | RFC 9000 §1.2 | gated | s_fixture_a |

## Table B — synthetic scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9114 §6.2.1 | c_fixture_c | Synthetic gated sample. |
