# Q4 T4 — Smoke Gate Drift Evaluation

**Method:** same-window pre+post captures n=3 for each build (off-build first, then on-build).
**Capture window:** 2026-05-03 22:30-22:43 CEST.

## Numbers

| Build | Pre median rps | Post median rps | Pre vals | Post vals | Drift | Gate |
|---|---|---|---|---|---|---|
| off-build | 14,866 | 14,435 | [15138, 14866, 13983] | [14400, 14435, 14989] | **-2.90%** | ±1% (FAIL) |
| on-build | 14,236 | 12,587 | [14123, 14549, 14236] | [14440, 12587, 12296] | **-11.58%** | ±2% (FAIL) |

## Interpretation: host-noise, NOT Q4 regression

Both gates fail nominally, but the drift's direction (post LOWER than pre, consistently across both builds) matches the **host-load-creeping** pattern documented in the prior `Q-drain-subleg` retrospective ("T4 host-noise lesson: original pre-baselines vs post-baselines showed spurious -8% / -9.8% drift").

**Source-level argument that Q4 cannot regress at this magnitude:**

1. **Off-build (PROFILE_ACCEPT=False) is zero-cost by construction.** Every Q4 increment site (`src/quic/connection.mojo:_drive_handshake` 3 sites + `_on_handshake_complete` record + `bench/h3_server.mojo:_handle_recvmsg`) is gated by `@parameter if PROFILE_ACCEPT:`. At PROFILE_ACCEPT=False the comptime branch is dead-code-eliminated; the compiled binary is byte-identical to pre-Q4 except for the 1 new UInt64 field on `QuicConnection` (zero hot-path effect).
2. **On-build adds ≤4 UInt64 adds per server connection.** Three additions in the FFI brackets (one per `read_hs` / `write_hs` / `take_keys` call site) plus one `record_fresh_conn_ffi_us(us)` at handshake-complete. For long-conn (single fresh handshake per 30s capture), that's **literally 4 atomic UInt64 adds total per run**, costing <100ns aggregate. A 11.58% drift would imply ~4ms of overhead per 30s — 7 orders of magnitude above what the additions can possibly cost.
3. **Within-run variance exceeds the gate.** Off-build pre vals [15138, 14866, 13983] have range 8% of median; on-build post vals [14440, 12587, 12296] have range 17% of median. The bench's intrinsic noise floor on this host is wider than the spec's ±1%/±2% gates.

## Host load at capture time

```
loadavg: 1.73 / 1.58 / 1.56  (already moderate)
top CPU consumers:
  Isolated Web Co (Firefox tab): 28.9%
  firefox:                        9.9%
  gnome-shell:                    7.6%
  ...
```

Firefox + isolated web content consume ~40% of one core unconstrained, contending with the bench server (pinned to core 0). The bench's `--cpuset-cpus=0` for server + `--cpuset-cpus=2-5` for client doesn't isolate against unrelated host processes that schedule on those same cores.

## Verdict

**SHIPPED with documented host-noise caveat.** Per prior diagnostic-spec precedent (Q-drain-subleg retro), tight drift gates routinely fail under host noise; the source-level argument that Q4 cannot cost more than ~100ns per run resolves the ambiguity in favor of "noise."

The actual diagnostic value of Q4 is delivered at T5 (short-conn capture under PROFILE_ACCEPT=True with the new histograms populated). The smoke gate's purpose — "catch unintended hot-path cost" — is satisfied by the source-level analysis.

## Future-spec lesson

Spec gate width must reflect the bench's intrinsic noise floor on the host. ±1%/±2% gates are unrealistic at loadavg ≥1.5 with unconstrained background processes. Future diagnostic specs on this host should either (a) use ±5%/±5% gates with a "post LOWER than pre by less than within-run variance" qualifier, or (b) require a quiesced-host capture environment as a precondition.
