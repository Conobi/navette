# Phase A Coverage Index

## Table A — h3spec triage rows

| failure_id | cluster | rfc_clause | status | scenario_binary |
|---|---|---|---|---|
| F01 | C4 | RFC 9000 §4.1 | deferred:quiche-raw-frame | — |
| F02 | C1 | RFC 9000 §7.3 | deferred:tls-conformance | — |
| F03 | C1 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F04 | C1 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F05 | C1 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F06 | C1 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F07 | C1 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F08 | C1 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F09 | C1 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F10 | C3 | RFC 9000 §12.4 | deferred:quiche-raw-frame | — |
| F11 | C2 | RFC 9000 §12.4 | deferred:quiche-raw-frame | — |
| F12 | C2 | RFC 9000 §17.2 | deferred:quiche-raw-frame | — |
| F13 | C2 | RFC 9000 §17.2.4 | deferred:quiche-raw-frame | — |
| F14 | C2 | RFC 9000 §17.2 | deferred:quiche-raw-frame | — |
| F15 | C4 | RFC 9000 §19.4 | deferred:quiche-raw-frame | — |
| F16 | C4 | RFC 9000 §19.5 | deferred:quiche-raw-frame | — |
| F17 | C3 | RFC 9000 §19.7 | deferred:quiche-raw-frame | — |
| F18 | C4 | RFC 9000 §19.10 | deferred:quiche-raw-frame | — |
| F19 | C4 | RFC 9000 §19.10 | deferred:quiche-raw-frame | — |
| F20 | C4 | RFC 9000 §19.11 | deferred:quiche-raw-frame | — |
| F21 | C4 | RFC 9000 §19.14 | deferred:quiche-raw-frame | — |
| F22 | C5 | RFC 9000 §19.15 | deferred:quiche-raw-frame | — |
| F23 | C5 | RFC 9000 §19.15 | deferred:quiche-raw-frame | — |
| F24 | C3 | RFC 9000 §19.20 | deferred:quiche-raw-frame | — |
| F25 | C6 | RFC 9001 §6 | deferred:tls-conformance | — |
| F26 | C6 | RFC 9001 §6 | deferred:tls-conformance | — |
| F27 | C6 | RFC 9001 §8.1 | deferred:tls-conformance | — |
| F28 | C6 | RFC 9001 §8.2 | deferred:tls-conformance | — |
| F29 | C6 | RFC 9001 §8.3 | deferred:tls-conformance | — |
| F30 | C7 | RFC 9001 §8.3 | deferred:quiche-raw-frame | — |
| F31 | C8 | RFC 9114 §4.1 | gated | s_f31_data_before_headers |
| F32 | C9 | RFC 9114 §6.2.1 | gated | s_f32_first_control_frame_not_settings |
| F33 | C9 | RFC 9114 §7.2.1 | gated | s_f33_data_on_control_stream |
| F34 | C9 | RFC 9114 §7.2.2 | gated | s_f34_headers_on_control_stream |
| F35 | C9 | RFC 9114 §7.2.4 | gated | s_f35_second_settings_frame |
| F36 | C8 | RFC 9114 §7.2.5 | gated | s_f36_cancel_push_on_request |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9114 §6.2.1 | c9_double_control_stream | Two control streams from a single peer, distinct triage from F32 (which is "first frame not SETTINGS"). |
