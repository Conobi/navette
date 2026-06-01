# Phase A Coverage Index

## Table A — h3spec triage rows

| failure_id | rfc_clause | status | scenario_binary |
|---|---|---|---|
| F01 | RFC 9000 §4.1 | deferred:quiche-raw-frame | — |
| F02 | RFC 9000 §7.3 | deferred:tls-conformance | — |
| F03 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F04 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F05 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F06 | RFC 9000 §18.2 | deferred:tls-conformance | — |
| F07 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F08 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F09 | RFC 9000 §7.4 | deferred:tls-conformance | — |
| F10 | RFC 9000 §12.4 | deferred:quiche-raw-frame | — |
| F11 | RFC 9000 §12.4 | deferred:quiche-raw-frame | — |
| F12 | RFC 9000 §17.2 | deferred:quiche-raw-frame | — |
| F13 | RFC 9000 §17.2.4 | deferred:quiche-raw-frame | — |
| F14 | RFC 9000 §17.2 | deferred:quiche-raw-frame | — |
| F15 | RFC 9000 §19.4 | deferred:quiche-raw-frame | — |
| F16 | RFC 9000 §19.5 | deferred:quiche-raw-frame | — |
| F17 | RFC 9000 §19.7 | deferred:quiche-raw-frame | — |
| F18 | RFC 9000 §19.10 | deferred:quiche-raw-frame | — |
| F19 | RFC 9000 §19.10 | deferred:quiche-raw-frame | — |
| F20 | RFC 9000 §19.11 | deferred:quiche-raw-frame | — |
| F21 | RFC 9000 §19.14 | deferred:quiche-raw-frame | — |
| F22 | RFC 9000 §19.15 | deferred:quiche-raw-frame | — |
| F23 | RFC 9000 §19.15 | deferred:quiche-raw-frame | — |
| F24 | RFC 9000 §19.20 | deferred:quiche-raw-frame | — |
| F25 | RFC 9001 §6 | deferred:tls-conformance | — |
| F26 | RFC 9001 §6 | deferred:tls-conformance | — |
| F27 | RFC 9001 §8.1 | deferred:tls-conformance | — |
| F28 | RFC 9001 §8.2 | deferred:tls-conformance | — |
| F29 | RFC 9001 §8.3 | deferred:tls-conformance | — |
| F30 | RFC 9001 §8.3 | deferred:quiche-raw-frame | — |
| F31 | RFC 9114 §4.1 | gated | s_f31_data_before_headers |
| F32 | RFC 9114 §6.2.1 | gated | s_f32_first_control_frame_not_settings |
| F33 | RFC 9114 §7.2.1 | gated | s_f33_data_on_control_stream |
| F34 | RFC 9114 §7.2.2 | gated | s_f34_headers_on_control_stream |
| F35 | RFC 9114 §7.2.4 | gated | s_f35_second_settings_frame |
| F36 | RFC 9114 §7.2.5 | gated | s_f36_cancel_push_on_request |

## Table B — synthetic gated scenarios

| synthetic_id | rfc_clause | scenario_binary | rationale |
|---|---|---|---|
| SY01 | RFC 9114 §6.2.1 | c9_double_control_stream | Two control streams from a single peer, distinct triage from F32 (which is "first frame not SETTINGS"). |
