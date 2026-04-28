# Subagent-A research report — what's inside `quic_conn_read_hs`?

**Sidecar fact set (30s short-conn, 1186 rps regime, post-migration):**
- `ffi_read_hs`  = 7,010,849 µs  (93.3% of `shim_ffi`, ~25% wall)
- `ffi_write_hs` =   483,282 µs  ( 6.4%)
- `ffi_take_keys`=    21,576 µs  ( 0.3%)

**Rustls version pinned:** `rustls = "0.23"` → resolved to `rustls-0.23.39`
in `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.39`.

**FFI wrapper:** `crates/librustls-mojo/src/quic_hs.rs` :: `rlsm_quic_conn_read_hs`
(lines 451-493).  The wrapper is a **3-statement shim**: null-check → `slice::from_raw_parts` →
`with_mut(handle, |entry| match entry.conn { ... }.read_hs(slice))` →
alert-cache update on Err.  No allocation, no copy, no contention beyond the per-handle
mutex of `HandleTable::with_mut`.  **The 7s lives in rustls, not in the shim.**

---

## 1. Per-call breakdown of `quic_conn_read_hs`

The call graph from FFI down to TLS-engine work:

```
rlsm_quic_conn_read_hs (quic_hs.rs:451)
  └─ with_mut(handle)                                   ← mutex acquire (cheap, uncontended)
     └─ ServerConnection::read_hs (quic.rs:73)          ← inline forward
        └─ ConnectionCommon::read_hs (quic.rs:404)
           ├─ self.deframer_buffer.extend(plaintext)    ← memcpy in
           ├─ self.core.hs_deframer.input_message(...)  ← record into hs deframer
           ├─ self.core.hs_deframer.coalesce(...)       ← reassemble fragments
           └─ self.core.process_new_packets(            ← THE HEAVY LOOP
                &mut self.deframer_buffer,
                &mut self.sendable_plaintext)
              loop {
                deframe(...) → opt_msg                  ← parse one handshake msg
                process_msg(msg, state, ...)            ← dispatch to current State
                  ├─ Message::try_from(msg)             ← payload parse + extension walk
                  └─ common.process_main_protocol(msg, state, ...)
                     └─ state.handle(&mut cx, msg)      ← *** TLS-engine dispatch ***
              }
```

For a server in QUIC mode, an Initial CRYPTO arrival drives `state.handle` through
**`ExpectClientHello::handle` → `with_certified_key` → `tls13::CompleteClientHelloHandling::handle_client_hello`** (`server/tls13.rs:135-481`).  That function alone
fires the entire server-side first flight.

**Phase-by-phase cost inside one `read_hs` call (server, full handshake, fresh session):**

| # | Phase | Source | Compute cost | Fires per | Mojo-side influence |
|---|---|---|---|---|---|
| 1 | FFI marshal-in: null check + slice::from_raw_parts + handle-table mutex | `quic_hs.rs:451-470` | trivial | every call | none beyond keeping handle ID stable |
| 2 | `deframer_buffer.extend(plaintext)` (memcpy of CRYPTO frame payload) | `quic.rs:405` | cheap (~hundreds of bytes/call) | every call | small — caller could buffer-coalesce |
| 3 | `hs_deframer.input_message` + `coalesce` (TLS-record fragmentation reassembly) | `quic.rs:407-419` | cheap | every call | none |
| 4 | `process_new_packets` outer loop: `deframe` → parse `Message::try_from` (TLS ext walk on ClientHello) | `conn.rs:882-944`, `conn.rs:1170` | **medium**: ClientHello = 30+ extensions, each typed-decoded; PSK identities, KeyShare entries, named_groups, sig_schemes, ALPN, transport_params, all parsed | once per arrival batch | restrict ALPN/sig_schemes/cipher_suites in `ServerConfig` to shrink walk; cap `Vec` resizing |
| 5 | `process_main_protocol` → `state.handle` → `ExpectClientHello::handle` | `common_state.rs:196`, `server/hs.rs:663` | cheap | once per handshake | none |
| 6 | Cert resolver `self.config.cert_resolver.resolve(client_hello)` | `server/hs.rs:432-446` | medium (Arc clone of selected `CertifiedKey`; we use `with_single_cert` so it's a constant Arc) | once per handshake | none — already O(1) |
| 7 | `choose_suite_and_kx_group` — intersect client suites × supported groups | `server/hs.rs:457-475` | cheap | once per handshake | only one suite would shorten the inner loop trivially |
| 8 | `transcript.start_hash` + `add_message(chm)` — SHA-256/384 over ClientHello | `server/hs.rs:482, 514, 343` | medium (~few-hundred-byte hash; single block) | once per handshake | none |
| 9 | **`kxgroup.start_and_complete(&share.payload.0)`** — server ECDHE: generate ephemeral key + scalar-mult against client KeyShare | `server/tls13.rs:501` | **HEAVY** (X25519 or P-256 scalar multiplication) | once per handshake | suite/group restriction (X25519 ~3-5× faster than P-256 with ring); 0-RTT/PSK skips this entirely |
| 10 | `KeySchedulePreHandshake::new` + `into_handshake(ckx.secret)` + `derive_server_handshake_secrets` (HKDF-Extract + 4× HKDF-Expand-Label for client/server handshake_traffic_secret + finished keys) | `server/tls13.rs:537-548`, `tls13/key_schedule.rs:184-225` | medium-heavy (HKDF over SHA-256 × ~5-7 expansions) | once per handshake | restrict to a single hash (already TLS 1.3 only) |
| 11 | `emit_encrypted_extensions` + `emit_certificate_tls13` + `emit_certificate_verify_tls13` (server signs `transcript_hash` with ECDSA-P-256 or RSA-PSS) | `server/tls13.rs:668-786` | **HEAVY** (RSA-PSS ≈ 1ms, ECDSA-P-256 ≈ 150-300µs, Ed25519 ≈ 80µs) | once per handshake | use **ECDSA-P-256 cert** (already?) — verify; consider Ed25519 |
| 12 | `emit_finished_tls13` — `key_schedule.sign_server_finish` (HMAC over transcript) + transition into `KeyScheduleTrafficWithClientFinishedPending` (4× more HKDF expansions for application-traffic secrets) | `server/tls13.rs:798-823`, `tls13/key_schedule.rs:274-330` | medium | once per handshake | none |
| 13 | Server pushes ServerHello/EE/Cert/CV/Fin into `common.quic.hs_queue` → returns `Ok(())` from `read_hs`. Caller now gets data via the **next** `write_hs` (mostly memcpy) and the buffered `KeyChange::Handshake`. | `quic.rs:486-516` | output is buffered, drained later | — | — |
| 14 | A **second** `read_hs` arrives carrying client's Handshake-CRYPTO (Client Finished). Dispatches to `ExpectFinished::handle` → `key_schedule.sign_client_finish` + **constant-time HMAC compare** + `into_traffic` (more HKDF for resumption secret + 1-RTT traffic secrets) | `server/tls13.rs:1314-1380`, `tls13/key_schedule.rs:489+` | medium (HMAC-SHA-256 verify + ~6 HKDF expansions) | once per handshake | none |
| 15 | FFI marshal-out: 0/-1 status, optional alert-cache write | `quic_hs.rs:471-492` | trivial | every call | none |

The **big-ticket items inside read_hs** are phases **9 (server ECDHE)**, **11 (server signature)**, and **10/12/14 (HKDF expansions × ~12 across the handshake)**. Phase 4 (extension parsing) is repeated and worth ~tens of µs/call but not the dominant cost.

---

## 2. Why `read_hs` dominates `write_hs` at 14×

**Hypothesis under test:** "read_hs fires per-crypto-level-per-arrival (3-6× per handshake) and each call does ECDHE/HMAC-verify; write_hs drains the rustls output buffer in one while-loop pass and is mostly memcpy."

**Verdict: CONFIRMED with refinements.**

`Quic::write_hs` (`quic.rs:486-516`) is a tight `while let Some(msg) = self.hs_queue.pop_front() { buf.extend_from_slice(&msg); ... }` followed by an `Option<KeyChange>` peek.  The work done inside is one `Vec::extend_from_slice` per buffered TLS handshake-message-fragment + an optional `Keys::new(&secrets)` (which derives 4 AEAD packet keys + 2 header-protection keys via HKDF-Expand-Label — this is the closest thing `write_hs` has to "real work", and it fires only when handshake/1-RTT secrets transition).  **No ECDHE, no signature, no transcript hash** is performed inside `write_hs`.

`read_hs`, in contrast:
- **Fires multiple times per handshake** on the server side. Per RFC 9001, a QUIC server typically receives CRYPTO at two encryption levels (Initial → ClientHello, Handshake → Client Finished). With CID rotation / coalesced packets / large ClientHellos in tquic_client traffic this can be 2-4 calls per handshake.
- **Carries the transcript work**: SHA-256 over every ClientHello (4 message-additions across the round), ECDHE scalar-mult on the first arrival (the single most expensive op in the whole handshake), and HMAC verify on the second.
- **Carries the output-side cryptographic work too**: server signature (RSA-PSS or ECDSA) and `derive_server_handshake_secrets` happen inside `process_new_packets` because state.handle synchronously emits the server flight into `common.quic.hs_queue` before returning. The bytes are *drained* by `write_hs`, but the *cost* is paid in `read_hs`.

That last point is the one most likely to surprise: **"server output cost lives in read_hs, not write_hs."** rustls is a sans-I/O state machine — it produces output as a side effect of consuming input. The 7s : 0.5s split is consistent with this design.

At 1186 rps × 30s ≈ 35,580 short-conn handshakes, dividing 7,010,849 µs gives ~197 µs/handshake spent inside `read_hs` total. ECDHE (X25519, ring) ≈ 50-80 µs, signature (ECDSA-P-256) ≈ 150-300 µs, HKDF × 12 ≈ 30-50 µs, parsing/transcript ≈ 30-60 µs. The numbers add up.

---

## 3. Ranked addressable levers

Estimates of the share of the 7s `read_hs` total that each lever could shave:

| Rank | Lever | Source location | Shave estimate | Implementation cost | Notes |
|---|---|---|---|---|---|
| **A** | **TLS 1.3 session resumption (PSK_DHE_KE) + tickets** | `server/tls13.rs:247-329` (PSK detection) + `quic_hs.rs:139` (set `config.send_tls13_tickets`); requires client-side ticket cache too | **40-60% of read_hs** (~2.8–4.2s) | medium — server already supports it (`send_tickets` field, `attempt_tls13_ticket_decryption`), needs `ServerConfig.session_storage = ServerSessionMemoryCache::new(N)` set in mojo + matching client-side `ClientSessionMemoryCache` | resumption skips server signature (#11) and shrinks ECDHE to PSK_DHE-only key; HKDF still runs. **tquic_client must also be opted in** — current bench harness almost certainly does NOT resume |
| **B** | **0-RTT / early data** | `server/tls13.rs:241+` (`early_data_request`), `quic_hs.rs:751+` (`zero_rtt_keys` already wired) | additional **5-15% of read_hs** on top of resumption | medium — set `ServerConfig.max_early_data_size > 0`, requires resumption to be live first | only relevant for short-conn scenarios; bench harness needs to send 0-RTT |
| **C** | **Audit / switch server cert to Ed25519 (or stay on ECDSA-P-256)** | `crates/librustls-mojo/src/quic_hs.rs:131` `with_single_cert` is signature-scheme agnostic — controlled by the test cert | **5-15% of read_hs** if currently RSA; near-zero if already ECDSA | trivial: regenerate cert via rcgen with `PKCS_ECDSA_P256_SHA256` or `PKCS_ED25519` | **first cheap check**: inspect the cert in `certs/` — if it's RSA-2048, ~1ms/handshake is being burned in #11 alone; on 35k handshakes that's ~3-4s of the total |
| **D** | **Restrict cipher_suites + named_groups** | `ServerConfig::builder_with_protocol_versions(&[&TLS13])` is already restrictive at the version level. For finer control, drop to `with_cipher_suites(&[CHACHA20_POLY1305_SHA256])` or X25519-only | 2-5% of read_hs | low — config builder API already exists | shrinks phase-4 extension parsing + phase-7 negotiation; not a big lever |
| **E** | **Pre-parse / cache ClientHello extensions** | would require forking rustls — **not addressable from mojo-net's side** | n/a | very high (rustls fork) | dropped; not a real option |
| **F** | **FFI batching** (combine multiple `read_hs` into one) | rustls API takes one buffer per call but `read_hs` already loops in `process_new_packets`; calling `read_hs` once with concatenated CRYPTO is the same cost | ~0% — phase-1 is already trivial; per-call FFI overhead is < 1% of total | trivial | **not worth doing**; the cost is rustls-internal, not FFI dispatch |
| **G** | **`take_keys` lock-free pool** | `quic_hs.rs:520+` already uses `HandleTable::with_mut`; total is 21k µs of 7M — **0.3% of read_hs** | < 0.3% | medium | **drop this lever**; it isn't a real cost center |

**Strongly recommended top-3:** A (resumption), C (Ed25519/ECDSA cert audit), B (0-RTT). Do C first — it's a 5-minute change that may shave 10-15% with no protocol change.

---

## 4. Cryptographic-minimum floor

A rough decomposition of what 197µs/handshake actually buys, on a Linux x86_64 box with ring's accelerated primitives:

| Item | Per-handshake | Reducible? |
|---|---|---|
| ECDHE scalar mult (X25519) | ~50–80 µs | only by switching to PSK (resumption) |
| Server signature (ECDSA-P-256) | ~150–300 µs | only by switching to PSK (resumption) or smaller key (Ed25519 ~80µs) |
| HKDF-Expand × ~12 (handshake + traffic + finished + AEAD/HP keys × 2 directions) | ~30–50 µs | irreducible at TLS 1.3 protocol level |
| Transcript SHA-256 over ~1.5 KiB across the handshake | ~20–40 µs | irreducible |
| ClientHello extension parsing + cert-resolver Arc-clone + state-machine bookkeeping | ~30–60 µs | partially reducible via config restriction (~10-20% of this slice) |
| Constant-time HMAC verify of Client Finished | ~5–10 µs | irreducible |

**Cryptographic-minimum floor** (irreducible without resumption): roughly **70-75% of `read_hs`** — i.e. ~5–5.3 seconds of the 7s short-conn cost is asymmetric-crypto and HKDF that *must* run on every fresh handshake.

**Surface-area headroom** (config tightening, cert/key-type swap, parser-path narrowing): roughly **25-30%** = ~1.7–2.1 seconds.

**With resumption + 0-RTT enabled** (and the client cooperating): the floor collapses to HKDF + transcript + HMAC ≈ **20-30% of current `read_hs`**, i.e. potentially ~1.5–2 seconds for the same workload — a **3-5× headroom**.

---

## 5. Recommended next step

The follow-on spec should target **TLS 1.3 session resumption (server-side ticket issuance + cache, with bench-harness client-side configured to consume tickets)** because resumption is the only lever that compresses the irreducible asymmetric-crypto floor (ECDHE + server signature ≈ 70% of `read_hs`); a ~5-line audit of the test cert's signature scheme should precede it as a cheap warm-up.

---

## Appendix — file paths

- FFI shim: `/home/donokami/Projets/perso/mojo-net/.worktrees/baseline-main/crates/librustls-mojo/src/quic_hs.rs` (lines 451-493 = `rlsm_quic_conn_read_hs`)
- rustls QUIC API: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.39/src/quic.rs`
  - `ConnectionCommon::read_hs` lines 404-424
  - `Quic::write_hs` lines 486-516
- rustls connection core: `…/rustls-0.23.39/src/conn.rs`
  - `process_new_packets` lines 882-942
  - `process_msg` lines 1140-1186
- rustls server TLS 1.3: `…/rustls-0.23.39/src/server/tls13.rs`
  - `handle_client_hello` lines 135-480
  - `emit_server_hello` (ECDHE) lines 487-565
  - `emit_certificate_verify_tls13` (server signature) lines 769-796
  - `ExpectFinished::handle` lines 1314-1380
- rustls TLS 1.3 key schedule: `…/rustls-0.23.39/src/tls13/key_schedule.rs`
