# 0-RTT Acceptance — Operator Guide

This document explains how navette handles TLS 1.3 0-RTT (early data),
why the default is rejection, the replay-attack model the
`IdempotentOnly` filter defends against, and how to opt into 0-RTT
safely.

## 1. What is 0-RTT?

TLS 1.3 (RFC 8446) introduces an optimisation called early data, also
called 0-RTT. After a successful initial handshake, the server can
issue a session ticket that the client may use on the next connection
to send application data *before* the handshake completes — saving one
network round trip.

In QUIC (RFC 9001 §4.6), 0-RTT data rides in dedicated 0-RTT packets
keyed off a PSK derived from the resumption secret. The server
decrypts the 0-RTT payload as soon as the resumed PSK is selected,
without waiting for the client Finished.

The latency win is real (one full RTT on every resumed connection),
but the price is that 0-RTT data is replayable. An attacker who
captures a 0-RTT packet can resubmit it to the same server (or a
peer behind the same session-ticket key) and the server cannot, from
the wire alone, distinguish the replay from a legitimate request.

## 2. Why navette defaults to rejection

Replay protection is not a transport-level guarantee in 0-RTT — it is
the application's responsibility (RFC 8446 §8). Many HTTP servers
historically learned this the hard way (CVE-2017-15090,
CVE-2018-12382, and others). Navette ships rejection-by-default and
makes opt-in explicit.

Concretely: `EarlyDataPolicy.off()` is the default ctor kwarg on
`QuicServerConfig`. A server that never sets `policy=...` advertises
`max_early_data_size = 0` in the issued session tickets; clients
cannot then attempt 0-RTT.

## 3. The replay-attack model

When `EarlyDataPolicy.idempotent_only()` (or `.tuned(...)`) is enabled,
navette accepts 0-RTT data subject to TWO layered defenses:

1. **Server-side anti-replay store** (transport layer).
   Per RFC 8446 §8.2, the server SHOULD reject any 0-RTT data
   accompanied by a previously-seen `ClientHello.random`. Navette
   captures the 32-byte random from the encrypted Initial CRYPTO
   bytes and consults an LRU-bounded in-memory store
   (`InMemoryEarlyDataStore`) before allowing the decrypted 0-RTT
   payload to reach the HTTP layer. A repeated random within the
   configured TTL is rejected before the request is parsed.

2. **HTTP-method filter** (application layer).
   Per RFC 8470 §5, the HTTP layer applies an `EarlyDataFilter` to
   the request method. The default `IdempotentOnlyFilter` accepts
   GET, HEAD, and OPTIONS (RFC 9110 §9.2.1 safe + §9.2.2 idempotent
   methods) and rejects everything else with status code 425
   (Too Early) per RFC 8470 §5.2. The client then retries the
   request over 1-RTT data, paying the round-trip latency.

Both layers fail closed: an anomaly in the FFI capture, the store, or
the filter results in rejection, not in an admission.

## 4. `EarlyDataPolicy.off()` — the default

```mojo
from navette.tls import EarlyDataPolicy
from navette.tls.config import QuicServerConfig

var config = QuicServerConfig(
    tls.shared(), Span(cert), Span(key),
    # policy=EarlyDataPolicy.off()   # default; omit to inherit
)
```

Behaviour:
- `max_early_data_size = 0` advertised in session tickets.
- Clients cannot attempt 0-RTT.
- No anti-replay store, no HTTP filter, no overhead.

This is the recommended posture for any deployment without a hard
latency budget that requires 0-RTT.

## 5. `EarlyDataPolicy.idempotent_only()` — safe opt-in

```mojo
from navette.tls import EarlyDataPolicy
from navette.tls.config import QuicServerConfig

var config = QuicServerConfig(
    tls.shared(), Span(cert), Span(key),
    policy=EarlyDataPolicy.idempotent_only(),
)
```

Behaviour:
- `max_early_data_size = u32::MAX` (the only non-zero value rustls
  QUIC accepts; RFC 9001 §4.6.1).
- LRU-bounded anti-replay store with default tuning
  (16384 entries, 30-minute TTL, per-key quota 3, sliding 1-second
  window at 1000 accepts/second).
- HTTP filter: GET / HEAD / OPTIONS pass; everything else gets 425
  Too Early.
- 0-RTT-accepted requests receive an `Early-Data: 1` header per
  RFC 8470 §3, transparent to user handler code.

This is the recommended posture for deployments that need 0-RTT for
short, safe, idempotent traffic (CDN edges, static-asset fetches).

## 6. `EarlyDataPolicy.tuned(config)` — custom store tuning

When the default store tuning does not fit your workload, build an
`EarlyDataStoreConfig` and pass it to `.tuned(...)`:

```mojo
from navette.tls import (
    EarlyDataPolicy,
    EarlyDataStoreConfig,
    default_early_data_store_config,
)

# Smaller capacity, shorter TTL for a constrained deployment:
var store_cfg = EarlyDataStoreConfig(
    max_entries=UInt32(4096),
    entry_ttl_ms=UInt64(300_000),       # 5 minutes
    per_key_max_attempts=UInt32(1),
    global_window_ms=UInt64(1_000),
    global_window_max_accepts=UInt32(200),
)
var config = QuicServerConfig(
    tls.shared(), Span(cert), Span(key),
    policy=EarlyDataPolicy.tuned(store_cfg),
)
```

All five tuning knobs MUST be >= 1; `.tuned(...)` raises (eager
validation) if any is zero. The error includes the offending field
name.

Tuning tradeoffs:

- **`max_entries`** — capacity ceiling for the LRU. Higher = more
  authenticators tracked = stronger replay defense over the TTL
  window. Memory cost is ~64 bytes per entry.
- **`entry_ttl_ms`** — per-authenticator freshness window. Tickets
  typically live ≤7 days on the rustls side; the TTL only needs to
  cover the ticket lifetime in practice (LRU eviction dominates at
  any production scale).
- **`per_key_max_attempts`** — bound on accept-or-duplicate
  observations per authenticator. The default of 3 allows benign
  client retries within tolerable bounds; lowering to 1 makes the
  store stricter at the cost of false rejects under aggressive
  client retransmission.
- **`global_window_ms`** + **`global_window_max_accepts`** —
  sliding-window rate limit on total 0-RTT accepts. Defends against
  amplification under burst attack. Default 1000 accepts/sec.

`Tuned` only varies STORE tuning. The HTTP filter is always
`IdempotentOnly` — there is currently no API to install a custom
filter type (see §11).

## 7. `QuicServerConfig` ctor recipes

The legacy `max_early_data: UInt32` ctor kwarg is preserved for
backward compatibility. The two kwargs may be combined as follows:

| `max_early_data` | `policy` | Result |
|---|---|---|
| `0` (default) | `EarlyDataPolicy.off()` (default) | 0-RTT disabled |
| `0` | `EarlyDataPolicy.idempotent_only()` | 0-RTT enabled (policy wins) |
| `0` | `EarlyDataPolicy.tuned(cfg)` | 0-RTT enabled (policy wins) |
| `u32::MAX` | (omitted) | 0-RTT enabled (legacy path) |
| `u32::MAX` | `EarlyDataPolicy.idempotent_only()` | 0-RTT enabled (policy wins; both agree) |
| `u32::MAX` | `EarlyDataPolicy.off()` | **raises** with `"contradictory early-data kwargs"` |

The contradictory case fails fast at construction; navette does not
silently pick one. New code should pass only `policy=...`.

## 8. Environment-variable deprecation (example server)

The bundled `examples/hello_h3_server/main.mojo` previously read
`HELLO_H3_MAX_EARLY_DATA=max` to opt into 0-RTT. The new name is
`HELLO_H3_ENABLE_EARLY_DATA=1` (or `"true"`).

The legacy name is honored for one release with a stderr deprecation
warning:

```
warning: HELLO_H3_MAX_EARLY_DATA=max is deprecated; use HELLO_H3_ENABLE_EARLY_DATA=1 instead
```

The deprecation overlap will be removed alongside the example's
legacy fallback. Conformance harness scripts already use the new
name.

## 9. Observability

Each 0-RTT request increments at most one counter in the
`AcceptProfile` accumulator (compile-time gated on `PROFILE_ACCEPT`):

- `zero_rtt_replay_accept` / `zero_rtt_replay_duplicate` /
  `zero_rtt_replay_per_key_quota` /
  `zero_rtt_replay_global_ceiling` /
  `zero_rtt_replay_no_authenticator` — transport-layer outcomes.
- `zero_rtt_filter_accept` / `zero_rtt_filter_reject_425` /
  `zero_rtt_filter_misconfig` /
  `zero_rtt_filter_skipped_for_1rtt` — HTTP-layer outcomes.

Bucket discrimination is exhaustive: every accepted 0-RTT request
increments exactly one transport counter AND exactly one HTTP-layer
counter. Counters surface in the AcceptProfile text + JSON reporters.

## 10. Security notes

- The default is `Off`. New callers who never set `policy=...` cannot
  accidentally enable 0-RTT.
- There is no API path that enables 0-RTT without an
  `IdempotentOnly`-shaped filter applied. `.idempotent_only()` and
  `.tuned(...)` both install the safe default filter automatically.
- Validation is eager. `.tuned(degenerate_config)` raises at
  policy-build time, not deferred to `QuicServerConfig` construction
  — so the failure surfaces close to the `EarlyDataStoreConfig`
  construction site.
- The public API contains no third-party type names. A
  `scripts/check_integrations.sh` invariant enforces this for the
  policy module specifically.
- Pointer-lifetime invariant: the policy is consumed once at
  `QuicServerConfig.__init__`. There is no post-construction
  mutator that could leave the rustls FFI config and the Mojo-side
  mirror in disagreement.
- Filter-reject on a request with body-in-flight (e.g., a 0-RTT POST
  with a large body) currently buffers up to the connection
  recv-flow-control limit on the kernel side before the stream
  closes. Operators sizing connection memory under POST-heavy 0-RTT
  traffic should account for this; a planned `STOP_SENDING`-on-reject
  hardening is documented as follow-up work.

## 11. Deferred: user-defined filter types

The `EarlyDataFilter` and `EarlyDataStore` traits are exposed
publicly via `from navette.tls import EarlyDataFilter, EarlyDataStore`
so future user implementations have a stable import path. However,
the current `EarlyDataPolicy` enum does NOT expose a `Custom(filter)`
variant — wiring a user-defined filter type through
`QuicServerConfig` → `QuicConnection` → the three H3 adapters
requires a trait-object plumbing refactor (~15-20 files) that is
deferred to a follow-up change. `Tuned(store_config)` is the v1
stand-in for what will become `Custom(filter, store)` later.

If you need a non-`IdempotentOnly` filter behaviour today, the
recommended path is to file an issue describing the use case
(method+path, method+header, rate-limiter, PSK-allowlist) — the
trait-object refactor will be prioritised against the operator
requests it receives.

User-defined `EarlyDataStore` types (Redis-backed, cluster-shared,
etc.) are deferred for the same reason and will land alongside the
custom-filter variant.
