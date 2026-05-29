# Coverage fixture — F03 carries status `red`; strict rejects, lenient permits.

Tag literals exercised by scenario binaries: [QUIC-SAMPLE-A] [H3-SAMPLE-B]

## Table A — triage rows

| failure_id | cluster | rfc_clause | status | scenario_binary |
|---|---|---|---|---|
| F01 | CX | RFC 9000 §1.1 | gated | s_fixture_a |
| F02 | CX | RFC 9000 §1.2 | gated | s_fixture_b |
| F03 | CX | RFC 9000 §1.3 | red | s_fixture_a |

## Table B — synthetic scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9114 §6.2.1 | c_fixture_c | Synthetic gated sample. |
