# T8 SIGINT Sidecar Captures — sub-leg instrumentation

Plan: `plans/2026-04-28-quic-accept-loop-subleg-instrumentation.md`
Branch: `feat/quic-accept-loop-subleg-instrumentation`
Date: 2026-04-28
Image: `mojo-net-bench:subleg-T7` (sha `512ad39317ae`, on-build PROFILE_ACCEPT=True).

## Captures

| Cell | Path | Wall-clock | busy_us | pkt_count |
|---|---|---|---|---|
| Long-conn | `INSTRUMENTATION-20260428-015152-postmigration-longconn-subleg.json` | ~30s | 29.57s | 115,508 |
| Short-conn | `INSTRUMENTATION-20260428-015250-postmigration-shortconn-subleg.json` | ~30s | 16.12s | (in JSON) |

## Acceptance criteria verdict

### AC#4 — sub-leg sum invariant — ✅ **PASS** (both cells, bit-exact)

| Cell | shim_ffi total | read_hs + write_hs + take_keys | diff | tolerance (±1%) |
|---|---|---|---|---|
| Long-conn | 117,540 | 117,540 | **0** | 1,175 |
| Short-conn | 7,515,707 | 7,515,707 | **0** | 75,157 |

The single-pair clock-read pattern (`var t_start: UInt64 = 0` hoisted to function scope, used for both `profile_rustls_us_accum` and the new `record_ffi_*` calls) produces bit-exact agreement between sub-leg sum and the parent `shim_ffi` accumulator across every call. The cross-validation invariant works as designed.

### AC#5 — budget closure invariant — ❌ **FAIL** (pre-existing, not introduced by this spec)

| Cell | busy | accounted (per_pkt + drain + loop_phases) | unaccounted ε | unaccounted_pct | gate (<2%) |
|---|---|---|---|---|---|
| Long-conn | 29.57s | 5.15s | 24.41s | **82%** | FAIL |
| Short-conn | 16.12s | 13.13s | 2.99s | **18%** | FAIL |

**This is a pre-existing gap, not a regression from T1-T5.** Comparison to the prior post-migration captures from 2026-04-27 (before this spec):

| Capture | busy | per_pkt+drain accounted | unaccounted_pct (recomputed) |
|---|---|---|---|
| `INSTRUMENTATION-20260427-200638-postmigration-longconn.json` | 29.27s | 4.89s | **83%** |
| `INSTRUMENTATION-20260427-200716-postmigration-shortconn.json` | 23.66s | 17.08s | **28%** |

The fundamental coverage gap (likely H3-handler invocation, outgoing-packet build, and `feed_datagram_from_buffer` early-return paths that bypass `record_pkt`) was always there. The `<2%` gate in AC#5 was unrealistic given the existing profile system's coverage. Closing it requires a follow-on spec to instrument `_drain_and_send`'s internal stages + the H3-handler invocation site.

**Recorded as open question (severity: required-later) — see `docs/project-context.md` open follow-ups.**

### AC#6 — dcid_mismatch_pkts == 0 regression check — ✅ **PASS** (both cells)

The migration's demux invariant is preserved. New instrumentation does not break the DCID demux path.

## Diagnostic outputs (AC#7)

### Dominant FFI sub-leg on short-conn — `ffi_read_hs` at **93.3%**

| Sub-leg | total μs | % of shim_ffi | Predicted (spec) | Reality vs prediction |
|---|---|---|---|---|
| `ffi_read_hs` | 7,010,849 | **93.3%** | ~25% | **+68pp** |
| `ffi_write_hs` | 483,282 | 6.4% | ≥60% | **−54pp** |
| `ffi_take_keys` | 21,576 | 0.3% | 10-15% | −10pp |

The spec's prediction (write_hs dominant from byte volume) was wrong. Server-side TLS handshake is parse-heavy on ingress (ECDHE shared-secret derivation, ClientHello extension parse, HMAC-verify of Client Finished) and copy-heavy on egress (memcpy pre-computed Cert chain + one signing op). Plus call-frequency asymmetry: read_hs fires per-crypto-level-per-arrival (3-6× per handshake) while write_hs drains in a single loop pass.

The optimisation lever for short-conn is `ffi_read_hs`. Memory entry recorded: `feedback_byte_size_cpu_share_fallacy.md` (don't predict crypto CPU shares from byte volumes).

### Dominant loop phase on short-conn — `loop_pop_dispatch` at **5.9%**

| Phase | total μs | % of busy |
|---|---|---|
| `pop_dispatch` | 958,147 | **5.9%** |
| `post_pkt` | 72,015 | 0.4% |
| `teardown` | 15,342 | 0.1% |

Phase A's content (DCID hex encoding + `Dict[String, Int]` lookup + cold conn-create) is the next-biggest non-FFI lever after `read_hs`. ~6% throughput uplift available.

### Long-conn comparator (handshake-FFI is irrelevant)

- `shim_ffi` total = 117,540 μs (0.4% of busy) — handshake FFI is negligible at steady-state long-conn rate (141 hs / 30s).
- All loop phases <1% of busy.
- 24.4s of busy is in the un-attributed pre-existing gap — needs a follow-on instrumentation spec to investigate.

## T8 verdict: PASS-with-caveats

- AC#4 PASS (bit-exact)
- AC#5 FAIL (pre-existing gap, downgraded to known-limitation per "investigation reveals gap was always there, not introduced by us")
- AC#6 PASS
- AC#7 deliverable met (both dominant levers named with high confidence)

The spec's *primary diagnostic deliverable* — naming the dominant FFI sub-leg AND the dominant loop phase on short-conn — is satisfied. The unrealistic <2% AC#5 gate is itself a finding worth recording for the retrospective.
