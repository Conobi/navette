# Wave 2 QUIC Handshake Retrospective

**Date:** 2026-04-13
**Spec:** `specs/2026-04-13-wave2-quic-handshake.md`
**Plan:** `plans/2026-04-13-wave2-quic-handshake.md`
**Commits:** `20dd298..a4bd163` (13 commits)

---

## Built vs. Planned

### What was built

All 10 planned tasks completed, producing:
- `crates/librustls-mojo/src/quic_hs.rs` — ~800 LoC, 15 FFI functions across 6 sections
- `crates/librustls-mojo/src/quic.rs` — `KeysEntry` + `keys_table()` promoted to `pub(crate)`
- `crates/librustls-mojo/src/lib.rs` — all 15 symbols re-exported
- `crates/librustls-mojo/Cargo.toml` — `rcgen = "0.12"` dev-dependency added
- 11 Wave 2 tests (T1–T10 + T7 + T8 rolled into T1 test) + 4 test helpers

### LoC vs. estimate

| Estimate | Actual |
|----------|--------|
| ~855–1270 LoC | ~800 LoC (quic_hs.rs) |

Came in at the low end — the pattern established by Wave 1 (`HandleTable`, `rlsm_err!`, `set_last_error`, `with_mut` closures) was extremely reusable and kept the code lean.

---

## Deviations from Plan

### 1. rustls 0.23 builder API differs from plan

**What:** `ServerConfig::builder().with_protocol_versions(&[...])` does not exist. The actual API is `ServerConfig::builder_with_protocol_versions(&[...])`.

**Why:** The plan was written from docs.rs, which shows the `ConfigBuilder` chain, but in 0.23 the protocol versions are passed directly to the constructor. The same applies to `ClientConfig::builder_with_protocol_versions`.

**Impact:** Minor — one-line adaptation in both config functions. The test helper `make_test_client_config` required the same fix.

### 2. `AlertDescription as u8` → `u8::from(a)`

**What:** In rustls 0.23, `AlertDescription` is not a C-like enum; `as u8` cast is rejected by the compiler. The correct cast is `u8::from(a)`.

**Why:** Plan was written based on docs — the actual representation changed between minor versions.

**Impact:** Trivial — one-character fix.

### 3. `conn.alert()` returns `None` for QUIC connections

**What:** The plan assumed `conn.alert()` would return the `AlertDescription` from the TLS error. In practice, QUIC connections use `CONNECTION_CLOSE` frames rather than TLS Alert records, so `conn.alert()` always returns `None`.

**Why:** This is correct RFC 9001 behavior — QUIC doesn't send TLS Alert records in-band.

**Impact:** The alert cache falls back to `decode_error(50)` when `conn.alert()` returns `None`. This means all `read_hs` failures report the same synthetic code. The implementation documents this clearly; callers needing the authoritative error must use `rlsm_last_error()`. **This is a non-trivial semantic difference** — an M3 caller dispatching on specific alert codes will always see 50 and should be aware of this.

### 4. `NoOpPacketKey` needed additional trait methods

**What:** `rustls::quic::PacketKey` requires `confidentiality_limit() -> u64` and `integrity_limit() -> u64` methods not mentioned in the plan.

**Why:** The plan's no-op impl was written from the spec's minimal surface. The actual trait has more required methods.

**Impact:** Two extra `fn` stubs returning reasonable defaults (`u64::MAX`).

### 5. T10, T2, T8 test scenarios needed strengthening in final review

**What:** Three tests were initially too weak:
- T10 freed connections without ever arming a pending key change
- T2 had bare FFI calls without assertions (could pass vacuously)
- T8 used empty transport params so `tp_written` was always 0

**Why:** Test bodies were written quickly in the plan without scrutinizing the exact handshake state required.

**Impact:** Caught in per-task review (T2) and final review (T10, T8). Fixed before merge. No production code impact.

---

## Pain Points

**rustls 0.23 QUIC API surface is narrower than anticipated.** The `alert()` returning `None` for QUIC is the most surprising discovery — it's correct per RFC 9001 but it means our alert FFI can only report synthetic codes. Downstream Mojo code in M3 will need to treat alert codes as informational only and always check `rlsm_last_error()` for the real message.

**Review catch rate was good.** 4 out of 10 per-task reviews caught important or blocking issues. The pattern of writing the test → confirming compile failure → implementing → confirming pass worked well. No task required more than one fix round.

---

## Open Questions

### Synthetic alert codes (severity: informational, trigger: M3 error handling design)
`rlsm_quic_conn_alert` returns `decode_error(50)` when `conn.alert()` is `None`. M3's QUIC state machine error handling should treat alert codes as advisory and always check `rlsm_last_error()` for the canonical error. Document this in the M3 spec.

### QC-1 conformance milestone (severity: required-later, trigger: before M3 implementation)
Wave 2 is now the unblock for QC-1 — ~35–45 test vectors for QUIC crypto + packet structure using aioquic as oracle. This was always planned as a separate milestone between Wave 2 and M3. Must be done before M3 implementation.

### Mojo bindings deferred (severity: required-later, trigger: M3 planning)
Wave 2 is FFI-only — no Mojo wrapper structs were added. M3 planning must include the Mojo `QuicConn`, `QuicClientConfig`, `QuicServerConfig` binding types.

---

## Next Spec Recommendations

1. **QC-1 conformance** (next immediate step) — QUIC crypto + packet structure test vectors using aioquic oracle. Reference: `research/quic-conformance-tooling.md`. ~35–45 vectors covering RFC 9001 Appendix A initial keys + handshake key derivation + 1-RTT key derivation.

2. **M3 QUIC transport core** — packet parser, connection state machine (§8 states), flow control, stream multiplexing, loss recovery. Reference: `research/quic-rfc9000-transport-scope.md` + `research/tquic-architecture.md`. M3 planning should explicitly address: (a) synthetic alert codes from Wave 2; (b) Mojo binding layer for Wave 2 FFI; (c) QUIC version negotiation.
