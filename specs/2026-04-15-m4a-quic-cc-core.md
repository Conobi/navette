# M4a — QUIC Congestion Control Core (CUBIC + pacer + persistent congestion)

**Date:** 2026-04-15
**Status:** spec, pending planning
**Depends on:** M3c (shipped 2026-04-14). A short prerequisite plan closes M3c's integration-coverage follow-up before M4a implementation (see §0).
**Successor:** M4b — CC observability + hardening (HyStart++, delivery-rate, ECN, BLOCKED, PN skipping, FC auto-tuning). Spec written after M4a lands.
**LoC estimate:** ~2590 (prod ~1830, tests ~760), matching M3c.

---

## 0. Prerequisite — M3c integration-coverage plan

Before M4a implementation starts, a short, single-plan milestone lands the M3c integration-test gaps flagged as `required-later` in M3c's open follow-ups (`docs/project-context.md:109`):

- FC limit-violation error paths end-to-end (FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR)
- MAX_STREAM_DATA / MAX_DATA window-update cycle across two connections
- Linear MAX_STREAMS growth verified on the wire
- CID retire → reissue round-trip
- Loss + retransmit for each M3c frame kind (RESET_STREAM, STOP_SENDING, MAX_*, NEW_CONNECTION_ID)

Estimated ~300 LoC of new integration tests. No production changes. Lives as its own short plan (`plans/YYYY-MM-DD-m3c-integration-coverage.md`) so M4a starts against a known-good baseline. Not a new milestone ID — just a scoped follow-up. The BLOCKED-frame emission follow-up (`docs/project-context.md:108`) is **not** resolved here — it belongs to M4b.

## 1. Goal

Replace M3b's dummy (unlimited-cwnd) congestion controller with real CUBIC congestion control + a TQUIC-style token-bucket pacer + RFC 9002 §7.6-compliant persistent congestion detection and response. Wire everything into the existing `Recovery` + `QuicConnection` send path. Keep the interface extensible for future BBR and for M4b's observability + hardening additions.

**Explicit M4a non-goals (deferred to M4b):**
- HyStart++ — standard RFC 9438 CUBIC slow-start only in M4a.
- Delivery-rate estimator — neither required by CUBIC's cwnd/pacing logic nor by persistent-congestion detection.
- MinMax helper — only used by HyStart++ (M4b) and future BBR.
- ECN — outgoing marking, incoming validation, CE→CC signals.
- BLOCKED frame emission.
- PN skipping / optimistic-ACK defense.
- FC auto-tuning (`autotune_window`).

## 2. Architecture

### 2.1 File layout

```
src/quic/
├── cc/                              [NEW subsystem; mirrors TQUIC congestion_control/ layout]
│   ├── trait.mojo                   # Shared types + interface contract    ~180 LoC
│   ├── controller.mojo              # Variant dispatcher (nested Copyable) ~200 LoC
│   ├── cubic.mojo                   # CUBIC per RFC 9438, no HyStart++     ~450 LoC
│   ├── pacing.mojo                  # Token-bucket pacer, TQUIC-mirror     ~215 LoC
│   └── dummy.mojo                   # No-op CC for tests                   ~165 LoC
├── recovery.mojo                    [MODIFIED] CC hooks + persistent congestion   +~300 LoC
├── pn_space.mojo                    [MODIFIED] last_ae_acked_time_sent field      +~40  LoC
└── connection.mojo                  [MODIFIED] _anti_amp_ok + _can_send + pacer timer  +~280 LoC
```

Test files:
- `tests/test_cc_cubic.mojo` (~250 LoC)
- `tests/test_cc_pacing.mojo` (~150 LoC)
- `tests/test_cc_controller.mojo` (~100 LoC)
- `tests/test_recovery.mojo` extend (+~120 LoC)
- `tests/test_pn_space.mojo` extend (+~40 LoC)
- `tests/test_quic_connection.mojo` extend (+~100 LoC for CC-aware integration)

### 2.2 Mirror map (which implementation each module follows)

| mojo-net module | Source | Rationale |
|---|---|---|
| `cc/trait.mojo` | TQUIC `src/congestion_control/congestion_control.rs` | Interface discipline; TQUIC's pluggability is our end goal. |
| `cc/controller.mojo` | **mojo-net-specific** | Needed because Mojo 0.26.2 lacks ergonomic dynamic dispatch; mirrors the existing `QuicEvent` tagged-struct pattern in `src/quic/connection.mojo:172`. |
| `cc/cubic.mojo` | TQUIC `src/congestion_control/cubic.rs` | Mature CUBIC impl per RFC 9438. |
| `cc/pacing.mojo` | TQUIC `src/congestion_control/pacing.rs` | Simplest conforming pacer; generic enough for future BBR. |
| `cc/dummy.mojo` | TQUIC `src/congestion_control/dummy.rs` | Test aid. |
| `recovery.mojo` extensions | TQUIC `src/connection/recovery.rs` + RFC 9002 §7.6 | Persistent congestion calculation follows research §4 conclusions directly. |

### 2.3 Dispatch pattern — nested-Copyable variant (Mojo 0.26.2 constraint)

Mojo 0.26.2 does not support ergonomic mutable dispatch through `Optional[NonCopyable]`. M4a adopts a **tag-discriminated struct with always-resident nested Copyable variant fields**. The `kind: UInt8` tag (precedent: `QuicEvent` at `src/quic/connection.mojo:172`, which uses flat primitive fields selected by `type_id: UInt8`) is combined with nested Copyable struct fields (precedent: `PacketNumberSpace` holding `EncryptionLevel`, `TransportParams` holding `PreferredAddress`) — both patterns are used in this codebase; neither is novel on its own, but their composition here is. Unused variant state wastes ~500 bytes per `CcController` instance (one per connection) — negligible.

Both `DummyCc` and `Cubic` are declared `Copyable, Movable` (all fields are primitives — `UInt64`/`UInt8`/`Bool` — so copy is cheap and derived `Copyable` should work; verify at plan-time).

**Mandatory pre-planning spike** (~20 LoC via `mcp__mojo-mcp__execute`): construct a `CcController` of both kinds, invoke each dispatch method, copy the controller, and inspect state round-trip. If Mojo's init-tracking flags the "not-taken" variant as uninitialized on paths where only one variant is "real", fall back to the flat-primitives `QuicEvent` pattern (hoist all `Cubic`/`DummyCc` fields directly onto `CcController`, ~20 fields total — verbose but known-good).

```mojo
# src/quic/cc/controller.mojo

struct CcController(Copyable, Movable):
    """Tagged variant holding exactly one active CC implementation."""

    var kind: UInt8         # CC_KIND_DUMMY=0, CC_KIND_CUBIC=1 (reserve 2+ for BBR family)
    var dummy: DummyCc      # Active iff kind == CC_KIND_DUMMY
    var cubic: Cubic        # Active iff kind == CC_KIND_CUBIC

    # Factory methods instead of overloaded __init__ so construction intent is clear.
    @staticmethod
    def new_cubic(max_datagram_size: UInt64) -> CcController: ...
    @staticmethod
    def new_dummy() -> CcController: ...

    # Dispatch methods — match on kind, delegate to active variant.
    def cwnd(self) -> UInt64:
        if self.kind == CC_KIND_CUBIC: return self.cubic.cwnd
        return UINT64_UNLIMITED              # dummy: unlimited — constant resolved at plan-time

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        if self.kind == CC_KIND_CUBIC: return self.cubic.pacing_rate(smoothed_rtt_us)
        return UInt64(0)                    # dummy: unpaced

    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC: self.cubic.on_packet_sent(size, now)
        # dummy: no-op

    def on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC: self.cubic.on_packet_acked(packet, smoothed_rtt_us, now)
        # dummy: no-op

    def on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64, now: UInt64, persistent: Bool):
        if self.kind == CC_KIND_CUBIC: self.cubic.on_packets_lost(lost, smoothed_rtt_us, now, persistent)
        # dummy: no-op

    def name(self) -> String:
        if self.kind == CC_KIND_CUBIC: return String("cubic")
        return String("dummy")
```

This pattern is fully realized in Mojo 0.26.2 as precedented by `QuicEvent`. No speculative language features.

## 3. Interface contract (`cc/trait.mojo`)

### 3.1 Module-scope constants

Module-scope `comptime` is supported in Mojo 0.26.2 (see `src/quic/recovery.mojo:7-10` for the precedent).

```mojo
# src/quic/cc/trait.mojo

comptime CC_KIND_DUMMY: UInt8 = 0
comptime CC_KIND_CUBIC: UInt8 = 1
# Reserved: CC_KIND_BBR = 2, CC_KIND_BBR3 = 3 (M4b or later)

comptime MIN_WINDOW_PACKETS: UInt64 = 2           # RFC 9002 §7.2
comptime INITIAL_WINDOW_PACKETS: UInt64 = 10      # RFC 9002 §7.2
comptime INITIAL_WINDOW_BYTES_CAP: UInt64 = 14720 # RFC 9002 §7.2 (14720-byte cap)
comptime LOSS_REDUCTION_NUM: UInt64 = 1           # 0.5 expressed as num/den for UInt64 math
comptime LOSS_REDUCTION_DEN: UInt64 = 2
comptime PERSISTENT_CONG_THRESHOLD: UInt64 = 3    # RFC 9002 §7.6.2

# "Unlimited" sentinel for Dummy CC's cwnd. Final form resolved at plan-time:
# Mojo 0.26.2 either exposes `UInt64.MAX` (`~UInt64(0)`), `UInt64.max_finite()`,
# or a simple `comptime` constant. The spike in §2.3 selects one.
comptime UINT64_UNLIMITED: UInt64 = ~UInt64(0)    # tentative; verify via mcp_execute
```

### 3.2 Shared value types

```mojo
struct AckedPacket(Copyable, Movable):
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64      # us
    var time_acked: UInt64     # us
    var rtt_sample: UInt64     # us, the RTT sample derived from this ACK

struct LostPacket(Copyable, Movable):
    var pkt_num: UInt64
    var size: UInt64
    var time_sent: UInt64      # us
```

### 3.3 Method contract

Every CC implementation (currently `DummyCc`, `Cubic`; later `Bbr`) exposes these methods. `CcController` forwards to the active variant (§2.3).

```
cwnd(self) -> UInt64
    Current congestion window, in bytes.

pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64
    Target pacing rate in bytes/sec. Caller passes the current smoothed RTT.
    Returning 0 means "unpaced" (pacer treats it as disabled).

on_packet_sent(mut self, size: UInt64, now: UInt64)
    Called when an in-flight packet leaves the host.

on_packet_acked(mut self, packet: AckedPacket, smoothed_rtt_us: UInt64, now: UInt64)
    Called once per newly-ACKed packet with RTT sample passed in.
    Caller supplies smoothed_rtt so CC does not need a Recovery reference.

on_packets_lost(mut self, lost: List[LostPacket], smoothed_rtt_us: UInt64, now: UInt64, persistent: Bool)
    Called on loss detection. persistent=True means the "persistent congestion"
    condition of RFC 9002 §7.6 is met; CC MUST reset cwnd to min_cwnd.
    smoothed_rtt_us is passed so CUBIC can evaluate its congestion-event
    suppression window without holding a Recovery reference (§4.4).

name(self) -> String
    Used in logging / qlog.
```

**RTT ownership.** CC variants do **not** hold a reference to `Recovery`. They receive `smoothed_rtt_us` as a method parameter. This avoids the circular-reference concern from the review (Recovery owns CcController, CcController must not own Recovery) and matches TQUIC's signature (TQUIC's CC trait takes `&mut Recovery` only for `begin_ack`/`end_ack`; everything else is parametric).

## 4. CUBIC (`cc/cubic.mojo`) — RFC 9438, no HyStart++

### 4.1 Rationale

CUBIC is the Linux default, the most-common QUIC stack choice (quinn, quiche, neqo, TQUIC), and RFC-standardized (RFC 9438). M4a ships standard RFC 9438 CUBIC without HyStart++; HyStart++ lands in M4b.

### 4.2 State

```mojo
struct Cubic(Copyable, Movable):
    # --- Window state ---
    var cwnd: UInt64                   # Current congestion window (bytes)
    var ssthresh: UInt64               # Slow-start threshold (bytes); UInt64.max_finite() before first loss
    var w_max: UInt64                  # cwnd at last congestion event
    var w_last_max: UInt64             # Previous w_max (fast convergence, RFC 9438 §4.6)

    # --- Cubic curve state ---
    var k_us: UInt64                   # Time from epoch_start to reach w_max, microseconds
    var epoch_start: UInt64            # us, 0 before first congestion event
    var congestion_event_time: UInt64  # us, time of most-recent congestion event (for suppression)
    var bytes_acked_since_epoch: UInt64

    # --- Reno-friendly region (RFC 9438 §4.2) ---
    var w_est: UInt64                  # AIMD-equivalent window tracked in parallel

    # --- Config ---
    var max_datagram_size: UInt64
    var min_cwnd: UInt64               # 2 * max_datagram_size
    var initial_window: UInt64         # clamp(10*MDS, _, 14720) per RFC 9002 §7.2
```

### 4.3 Constants (module-scope in `cubic.mojo`)

```mojo
comptime CUBIC_BETA_NUM: UInt64 = 7        # beta = 0.7
comptime CUBIC_BETA_DEN: UInt64 = 10
comptime CUBIC_C_NUM: UInt64 = 4           # C = 0.4
comptime CUBIC_C_DEN: UInt64 = 10
# Congestion-event suppression: ignore losses during one RTT after an event.
comptime CUBIC_CONGESTION_SUPPRESS_RTT_MULT: UInt64 = 1
```

### 4.4 Algorithm sketch

**Slow start** (while `cwnd < ssthresh`, standard behavior — no HyStart++):
- Each ACK: `cwnd += min(acked_bytes, max_datagram_size)`

**Congestion avoidance** (`cwnd >= ssthresh`):
- Set `epoch_start = now` on first CA ACK (or after congestion event).
- Compute `t_us = now - epoch_start`.
- `w_cubic(t) = C_num/C_den * ((t - k)/1e6)^3 + w_max` in bytes. Use Newton's method for cube root of `w_max * (1 - beta) / C` (once per congestion event, not per ACK).
- `w_est` AIMD update per ACK: `w_est += (CUBIC_BETA_NUM * max_datagram_size * acked_bytes) / (CUBIC_BETA_DEN * w_est)`.
- `target = max(w_cubic, w_est)`.
- `cwnd += max_datagram_size * (target - cwnd) / cwnd` per ACK.

**Congestion event** (on `on_packets_lost(_, _, persistent=False)` AND not within suppression window):
- Fast convergence: if `cwnd < w_last_max` then `w_last_max = cwnd; w_max = cwnd * (1 + CUBIC_BETA_NUM / CUBIC_BETA_DEN) / 2` else `w_last_max = cwnd; w_max = cwnd`.
- `cwnd = max(cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN, min_cwnd)`.
- `ssthresh = cwnd`.
- `w_est = cwnd`.
- Recompute `k_us` from `w_max * (1 - beta) / C` cube root.
- `congestion_event_time = now`.
- `epoch_start = 0` (will be set on next CA ACK).

**Persistent congestion** (on `on_packets_lost(_, _, persistent=True)`):
- `cwnd = min_cwnd` (2 * max_datagram_size).
- `ssthresh = cwnd`.
- `w_max = 0`, `w_last_max = 0`, `w_est = cwnd`.
- `epoch_start = 0`, `congestion_event_time = now`.
- Per RFC 9002 §5.2 + research §4.3, Recovery (not CUBIC) resets `min_rtt = latest_rtt` when persistent congestion is declared (see §5.3 below).

**Suppression.** Multiple loss detections in one RTT count as one congestion event: if `now < congestion_event_time + CUBIC_CONGESTION_SUPPRESS_RTT_MULT * smoothed_rtt_us`, skip the congestion-event path. `smoothed_rtt_us` comes from the `on_packets_lost(lost, smoothed_rtt_us, now, persistent)` parameter (§3.3) — CUBIC does not cache RTT between calls.

### 4.5 Pacing rate

```mojo
def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
    """Bytes/sec. Slow-start gain 2.0; steady state 1.25. Never divide by zero."""
    var srtt = smoothed_rtt_us if smoothed_rtt_us > 0 else UInt64(1)
    if self.cwnd < self.ssthresh:
        return (UInt64(2) * self.cwnd * UInt64(1_000_000)) // srtt
    return (UInt64(5) * self.cwnd * UInt64(1_000_000)) // (UInt64(4) * srtt)
```

### 4.6 Fixed-point arithmetic notes

All CUBIC math is UInt64 fixed-point. The curve `w_cubic(t) = C*(t-k)^3 + w_max` overflows if `(t-k)^3` is computed unscaled (e.g., `t-k` up to 10^9 µs for a 1000-second window → `(t-k)^3 ≈ 10^27`, far above UInt64's ~1.8*10^19 ceiling).

- **Integer cube root** for `k` computation: Newton's-method helper (~50 LoC). Needed only once per congestion event, so perf is non-critical.
- **Cube evaluation for `w_cubic`**: requires 128-bit intermediate. Two candidate approaches, selected at plan-time via `mcp__mojo-mcp__search`/`lookup` to confirm Mojo 0.26.2 availability:
  - **If UInt128 (or `SIMD[DType.uint128, 1]`) is available**: use directly.
  - **Otherwise**: scale inputs — if `(t-k)` fits in 32 bits, `(t-k)^2` fits in 64 bits, and `(t-k)^3` requires one UInt64 × UInt64 → (hi, lo) multiply. Implement as a plain `fn mul_u64_hi_lo(a: UInt64, b: UInt64) -> (UInt64, UInt64)` (no `@parameter` — that's for compile-time parametric functions).
- **Output clamp** to `[min_cwnd, MAX_CWND = 1 GiB]`: this is a **safety rail against UInt64 overflow**, not a target cwnd. Hitting the clamp indicates a pathological curve evaluation and should be observable in tests; M4b / high-BDP work may loosen the ceiling. Log when hit; `test_cubic_overflow_clamp` (§9.1) asserts the clamp is NOT hit in normal-RTT scenarios.

High-BDP work (sustained cwnd near 1 GiB) is not a realistic M4a target. The plan-phase spike on UInt128 is low-risk: the codebase already uses `UInt64` for all packet-number math without issue, and cube-root/cube evaluation is structurally similar.

## 5. Recovery integration (`recovery.mojo` modifications)

### 5.1 New fields

```mojo
struct Recovery(Movable):
    # ... existing (M3b/M3c) fields ...
    var cc: CcController
    var pacer: Pacer
```

Construction:

```mojo
def __init__(out self, max_datagram_size: UInt64, use_cubic: Bool = True):
    # ... existing init ...
    self.cc = CcController.new_cubic(max_datagram_size) if use_cubic else CcController.new_dummy()
    self.pacer = Pacer.new(max_datagram_size)
```

### 5.2 Hook-point modifications

- `on_packet_sent(size, in_flight)` → after `bytes_in_flight += size`, call `self.cc.on_packet_sent(size, now)`. Token consumption is done at the send site via `self.pacer.on_sent(size)` directly by the caller (not inside Recovery).
- `on_packet_acked(size, in_flight)` — unchanged signature. The CC-notification path (construct `AckedPacket` + call `self.cc.on_packet_acked`) is done by `connection.mojo`'s `_process_ack` at step 3 (§8.2), not inside Recovery, because the caller already iterates `sent_packets` for ACKed-frame teardown.
- `on_packet_lost(size, in_flight)` — unchanged signature. The persistent-congestion check + CC fan-out happens in `connection.mojo` after `detect_lost_packets` returns (§8.2 steps 6–7).
- `on_ack_received()` → after resetting `pto_count`, refresh pacer capacity: `self.pacer.update_capacity(self.cc.cwnd(), self.smoothed_rtt)`.

### 5.3 Persistent congestion detection — RFC 9002 §7.6.2

The detection runs **after** `detect_lost_packets` returns its list and **before** that list is fanned out to streams/frames. Implemented as a method on `QuicConnection` (not `Recovery`) because it needs the peer transport params and the `PacketNumberSpace` state; `Recovery` exposes the RTT/`rttvar` getters it depends on.

```mojo
def detect_persistent_congestion(
    self,
    space_id: Int,                   # 0=Initial, 1=Handshake, 2=Data
    newly_lost_pns: List[Int],       # PN list returned by Recovery.detect_lost_packets
    peer_max_ack_delay_us: UInt64,   # passed from self.peer_params (0 if not yet negotiated)
    now: UInt64,
) -> Bool:
    """RFC 9002 §7.6.2 + §5.2. Returns True if persistent congestion is declared in `space_id`.

    The caller is responsible for:
      - Invoking `cc.on_packets_lost(..., persistent=True)` on True return.
      - Resetting `recovery.min_rtt = recovery.latest_rtt` per RFC 9002 §5.2
        (+ research quic-loss-detection-edge-cases.md §4.3).
    """
    var rec = self.recovery
    if not rec.has_rtt_sample:
        return False      # RFC 9002 §7.6.2: MUST NOT declare before first RTT sample
    if len(newly_lost_pns) < 2:
        return False

    var space = self.pn_spaces.get(space_id)
    # Filter ack-eliciting only. We look up each PN in sent_packets (the Dict)
    # and use the existing SentPacket.ack_eliciting flag added in M3b.
    var earliest: UInt64 = UINT64_UNLIMITED
    var latest: UInt64 = 0
    var ae_count: Int = 0
    for pn in newly_lost_pns:
        # NB: Dict iteration order is unspecified; we only need min/max.
        if pn not in space.sent_packets:
            continue      # already removed (shouldn't happen; defensive)
        var sp = space.sent_packets[pn]
        if not sp.ack_eliciting:
            continue
        ae_count += 1
        if sp.time_sent < earliest: earliest = sp.time_sent
        if sp.time_sent > latest:   latest   = sp.time_sent
    if ae_count < 2:
        return False

    # Congestion period — RFC 9002 §7.6.2. max_ack_delay contributes irrespective of
    # packet number space (unlike PTO §6.2.1). Research quic-loss-detection-edge-cases.md §4.2
    # is explicit: "max_ack_delay is included here even for Initial/Handshake spaces."
    var rtt_var_scaled = UInt64(4) * rec.rttvar
    if rtt_var_scaled < K_GRANULARITY:
        rtt_var_scaled = K_GRANULARITY
    var congestion_period = (rec.smoothed_rtt + rtt_var_scaled + peer_max_ack_delay_us) \
                            * PERSISTENT_CONG_THRESHOLD

    if latest - earliest < congestion_period:
        return False

    # RFC condition: no ack-eliciting packet with earliest <= time_sent <= latest
    # in THIS space was acknowledged. §5.4 describes how we track this signal.
    return not space.any_ae_acked_in_range(earliest, latest)
```

**Additional requirements:**

- **Filter is inline, not caller-supplied.** The previous revision required callers to filter ack-eliciting, coupling two layers. Inline filtering is safer (defensive against caller bugs) and costs only the Dict lookup per PN in `newly_lost_pns`.
- On `True` return, caller invokes `cc.on_packets_lost(lost, rec.smoothed_rtt, now, persistent=True)` AND `rec.min_rtt = rec.latest_rtt`.
- Per-space evaluation accepted as safe (research §4.4: cross-space is RFC-recommended but single-space is false-positive-safe and matches quinn/quiche/TQUIC).

### 5.4 `any_ae_acked_in_range` — single-UInt64 conservative tracker

The prior revision proposed a 64-entry ring buffer per space, which a reviewer correctly identified as undersized: `congestion_period` can be multiple seconds, and a connection sending hundreds of packets/sec would evict in-range evidence, producing silent false-positive persistent-congestion declarations. M4a adopts a **conservative single-UInt64 tracker** that avoids false positives at the cost of occasional false negatives.

**State addition to `PacketNumberSpace` (`pn_space.mojo`):**

```mojo
# Time_sent of the most-recently ACKed ack-eliciting packet in this space.
# Initial value 0 (sentinel: no ack-eliciting ack observed yet).
var last_ae_acked_time_sent: UInt64
```

**Update:** during `_process_ack` in `connection.mojo`, after each newly-acked `SentPacket` is processed, if `sp.ack_eliciting`:

```mojo
if sp.time_sent > space.last_ae_acked_time_sent:
    space.last_ae_acked_time_sent = sp.time_sent
```

**Query:** `any_ae_acked_in_range(earliest, latest)` returns True in any case where evidence exists or evidence might have been overwritten:

```mojo
def any_ae_acked_in_range(self, earliest: UInt64, latest: UInt64) -> Bool:
    """Conservative: True if we have any evidence an ack-eliciting packet in the
    range was ACKed, OR if the tracker has advanced past `latest` (in which case
    earlier range-ACKs may have happened but been overwritten)."""
    if self.last_ae_acked_time_sent == 0:
        return False   # no ack-eliciting ACK ever received in this space
    if self.last_ae_acked_time_sent >= earliest:
        return True    # definite (in range) OR conservative fallback (past latest)
    return False       # last AE ACK predates range → no evidence of ACK in range
```

**Correctness analysis (short):**

- `last_ae_acked_time_sent == 0`: no AE acks ever → no evidence of in-range ACK → safe to declare persistent.
- `last_ae_acked_time_sent ∈ [earliest, latest]`: directly proves an in-range AE ACK happened → do not declare persistent. ✓ RFC-compliant.
- `last_ae_acked_time_sent < earliest`: every AE ack we've seen happened before the range → no evidence of in-range ACK → declare persistent if other conditions met. ✓ RFC-compliant.
- `last_ae_acked_time_sent > latest`: there might have been in-range ACKs we no longer remember (overwritten by the later one). Conservatively return True → do not declare persistent. **This is the only case where M4a under-declares vs. the RFC.** Acceptable: CUBIC still reduces cwnd on the underlying loss event via the non-persistent code path; the only missed optimization is the "reset cwnd to min" response.

The false-negative case (under-declaration) is bounded to connections where the peer has acked at least one AE packet after the latest-lost, which usually means the path is making forward progress — a regime where aggressive persistent-congestion cwnd reset is arguably over-reaction anyway.

Memory cost: 8 bytes per space × 3 spaces = 24 bytes. No ring, no eviction logic, no pruning. ~10 LoC in `pn_space.mojo` for the field + update + query. The remaining ~30 LoC of `pn_space.mojo` delta (per §2.1) is the existing `sent_packets` iteration in `any_ae_acked_in_range` callers plus unit tests in §9.

## 6. Pacer (`cc/pacing.mojo`) — TQUIC mirror

Direct port of TQUIC's `congestion_control/pacing.rs` (215 effective LoC).

### 6.1 State

```mojo
struct Pacer(Copyable, Movable):
    var enabled: Bool              # False disables pacing (pass-through)
    var capacity: UInt64           # bytes burstable per granularity tick
    var tokens: UInt64             # current tokens (bytes)
    var last_cwnd: UInt64
    var last_sched_time: UInt64    # us; 0 before first schedule()
    var pacer_granularity_us: UInt64  # default 1000 (1ms); named distinct from recovery's K_GRANULARITY
    var max_datagram_size: UInt64
    # Constants (see §6.4)
```

Named `pacer_granularity_us` to avoid name collision with `recovery.mojo`'s `K_GRANULARITY` (also 1ms, different semantic — loss-detection granularity).

### 6.2 Constants

```mojo
comptime PACER_MIN_BURST_PACKETS: UInt64 = 10
comptime PACER_MAX_BURST_PACKETS: UInt64 = 128
comptime PACER_DEFAULT_GRANULARITY_US: UInt64 = 1000
```

### 6.3 API — split pure query + mutating refill

The pacer exposes **two send-scheduling entry points** with different mutation semantics, so that the connection timer query (called many times per event-loop tick, must be pure) doesn't collide with the actual send-decision path (mutates token state).

```mojo
@staticmethod
def new(max_datagram_size: UInt64) -> Pacer: ...

# --- Pure query, safe to call from `timeout()` ---
def next_send_time(self, pacing_rate_bps: UInt64, now: UInt64) -> Optional[UInt64]:
    """Non-mutating. Computes when the pacer would have enough tokens to send one MTU,
    WITHOUT updating self.last_sched_time or self.tokens. Uses the current token
    snapshot + projected refill from `now - self.last_sched_time`.

    If pacing_rate_bps == 0 or self.enabled is False, always returns None (unpaced).
    Idempotent; callable multiple times per tick."""

# --- Mutating refill + check, called once per actual send attempt ---
def refill_and_check(mut self, pacing_rate_bps: UInt64, now: UInt64) -> Bool:
    """Refills tokens based on elapsed time, updates last_sched_time, and returns
    True if the caller may send one MTU now. Called exactly once per send attempt
    from `_can_send`. Integer division is floor; accept up to 1-byte rounding loss."""

def on_sent(mut self, bytes: UInt64):
    """Decrement tokens. Saturating subtract (tokens never negative). Called AFTER
    `refill_and_check` returns True and the send actually occurred."""

def update_capacity(mut self, cwnd: UInt64, smoothed_rtt_us: UInt64):
    """Recompute capacity when cwnd changes.
    capacity = clamp((cwnd * pacer_granularity_us) / max(srtt, 1),
                      PACER_MIN_BURST_PACKETS * max_datagram_size,
                      PACER_MAX_BURST_PACKETS * max_datagram_size)
    Also trims self.tokens down to new capacity if it exceeds."""
```

### 6.4 Refill math (explicit, no ambiguity)

Shared between `next_send_time` (read-only projection) and `refill_and_check` (commit):

```
elapsed = saturating_sub(now, self.last_sched_time)      # 0 if now < last_sched_time
refill  = (pacing_rate_bps * elapsed) // 1_000_000       # floor; tolerance: 1-byte loss
tokens_projected = min(self.capacity, self.tokens + refill)
```

**`next_send_time(pacing_rate, now)`** (pure):
1. If `not self.enabled` or `pacing_rate == 0` → return `None`.
2. Compute `tokens_projected` as above.
3. If `tokens_projected >= self.max_datagram_size` → return `None` (can send now).
4. `deficit = self.max_datagram_size - tokens_projected`.
5. `wait_us = (deficit * 1_000_000 + pacing_rate - 1) // pacing_rate`  (ceil).
6. Return `Some(now + wait_us)`.

**`refill_and_check(pacing_rate, now)`** (mutating):
1. If `not self.enabled` or `pacing_rate == 0` → return `True` (unpaced).
2. Compute `tokens_projected` as above.
3. `self.tokens = tokens_projected; self.last_sched_time = now`.
4. Return `self.tokens >= self.max_datagram_size`.

## 7. Dummy CC (`cc/dummy.mojo`) — test aid

Mirror of TQUIC `dummy.rs`. All ops no-op; `cwnd()` returns `UINT64_UNLIMITED` (the §3.1 constant); `pacing_rate()` returns 0 (pacer disabled). Used by M3b/M3c tests that don't care about CC dynamics, plus select M4a tests that exercise non-CC paths. Default for connection construction remains CUBIC.

## 8. Connection integration (`connection.mojo` modifications)

### 8.1 Send gating — new helpers extracted from inline check

M3b's send path has an **inline** amplification check at `connection.mojo:1393` (`if self.bytes_sent + UInt64(len(datagram)) + 100 > 3 * self.bytes_received:`); there is no pre-existing `_can_send` or `_anti_amp_ok` helper. M4a introduces both, and moves the `connection.mojo:1393` inline test into the new `_anti_amp_ok`. The `+ 100` estimated-header-overhead fudge becomes a named `ANTI_AMP_HEADER_FUDGE` `comptime`, and the contract becomes explicit.

```mojo
comptime ANTI_AMP_HEADER_FUDGE: UInt64 = 100  # matches the `+ 100` at connection.mojo:1393

def _anti_amp_ok(self, datagram_size: UInt64) -> Bool:
    """Server-side 3x anti-amplification check (RFC 9000 §8.1, §21.8).
    Only applies when the connection is a server AND the peer's address has
    NOT been validated yet; after validation the cap is lifted.

    datagram_size is the unpadded datagram size the caller is about to send;
    the internal `ANTI_AMP_HEADER_FUDGE` accounts for UDP/IP overhead and
    preserves the exact numeric behavior of the original inline check at
    connection.mojo:1392-1393.

    Returns True on client, or on a server with a validated peer address."""
    if not self.is_server: return True
    if self._addr_validated(): return True
    return self.bytes_sent + datagram_size + ANTI_AMP_HEADER_FUDGE <= 3 * self.bytes_received

def _can_send(self, size: UInt64, now: UInt64) -> Bool:
    """Composite send gate: anti-amplification + CC window + pacer. Non-mutating;
    callable from timer queries and from the actual send decision. Actual token
    consumption happens via Pacer.refill_and_check at the send site, not here."""
    if not self._anti_amp_ok(size): return False
    if self.recovery.cc.cwnd() < self.recovery.bytes_in_flight + size: return False
    var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
    if self.recovery.pacer.next_send_time(rate, now):
        return False      # Optional truthiness — `if opt:` idiom matches `connection.mojo:1975`
    return True
```

**Call-site migration.** The inline check at `connection.mojo:1391-1394` becomes `if not self._anti_amp_ok(UInt64(len(datagram))): break`. The new helper preserves the exact original predicate — the `is_server AND not _addr_validated` guard moves *inside* the helper, as does the `+ 100` header fudge. The M4a plan phase audits the send path for any other inline amplification tests (grep expected to find this single one). At the **actual** send decision, the code calls `self.recovery.pacer.refill_and_check(rate, now)` (mutating) to commit a token; if True, proceed and call `self.recovery.pacer.on_sent(size)` after the send.

LoC budget for §8.1 changes: ~60 LoC (two new helpers + constant + call-site migration), included in the revised `connection.mojo` +280 LoC delta (§2.1).

### 8.2 ACK-processing sequence (modified `_process_ack` / `_on_ack_received`)

1. Validate ACK ranges (M3b existing — `largest_acked <= largest_sent_pn_in_space` check).
2. Iterate `space.sent_packets: Dict[Int, SentPacket]` (M3b existing) to find newly-acked PNs.
3. For each newly-acked `sp`:
   - **New:** if `sp.ack_eliciting` and `sp.time_sent > space.last_ae_acked_time_sent`, update `space.last_ae_acked_time_sent = sp.time_sent` (§5.4 tracker).
   - **New:** build `AckedPacket(sp.pn, sp.size, sp.time_sent, now, rtt_sample=rec.latest_rtt)` and call `rec.cc.on_packet_acked(pkt, rec.smoothed_rtt, now)`.
   - Remove `sp` from `sent_packets` (M3b existing).
4. RTT update (M3b existing).
5. Loss detection via `rec.detect_lost_packets(...)` → `List[Int]` of PNs (M3b existing).
6. **New:** Run `persistent = self.detect_persistent_congestion(space_id, lost_pns, self._peer_max_ack_delay_us(), now)` (§5.3). Note: filtering to ack-eliciting happens inside that helper, not in the caller.
7. **New:** Build `List[LostPacket]` from `lost_pns` (lookup each PN in `space.sent_packets` for size + time_sent before removal; matches the existing per-frame-teardown iteration). Then:
   - `rec.cc.on_packets_lost(lost_packets, rec.smoothed_rtt, now, persistent)`.
   - If `persistent`: `rec.min_rtt = rec.latest_rtt` (RFC 9002 §5.2).
8. **New:** `rec.pacer.update_capacity(rec.cc.cwnd(), rec.smoothed_rtt)`.
9. Reset PTO (M3b existing).

### 8.3 Pacer timer integration

`connection.mojo:1949` exposes `def timeout(self) -> Optional[UInt64]` — the deadline query for the I/O loop. It is **non-mutating** (`self`, not `mut self`) and called multiple times per tick. M4a adds one branch that queries `self.recovery.pacer.next_send_time(rate, now)` (the pure variant from §6.3) and folds its return into the existing `min(_, earliest)` composition:

**`timeout()` signature change.** M3b's `def timeout(self) -> Optional[UInt64]` (at `connection.mojo:1949`) is non-mutating and does not currently take `now`, because all existing timer sources (`pto_timeout`, `idle_timer`, `close_timer`, `drain_timer`) are absolute deadlines. The pacer's pure `next_send_time(rate, now)` needs `now` for its projection. M4a updates the signature to `def timeout(self, now: UInt64) -> Optional[UInt64]` — consistent with every other path in the file that already takes `now: UInt64` (e.g., `_check_timers(now)` at line 1379, `handle_timeout(now)` elsewhere). Call sites in `examples/` and `tests/` already have `now` in scope at the call point, so the migration is mechanical. No cached-`now` field introduced.

```mojo
# Inside timeout(now) — after existing PTO/idle/close/drain branches:
var rate = self.recovery.cc.pacing_rate(self.recovery.smoothed_rtt)
var pacer_deadline = self.recovery.pacer.next_send_time(rate, now)
if pacer_deadline:
    if earliest:
        if pacer_deadline.value() < earliest.value(): earliest = pacer_deadline
    else:
        earliest = pacer_deadline
```

`refill_and_check` (mutating) is called from `_can_send`'s callers at the actual send site, **not** from `timeout()`. On wake-up, the event loop re-runs the send path, which re-queries `_can_send` and commits the token via `refill_and_check` iff a send occurs.

If `pacing_rate` is 0 (dummy CC, or zero srtt), `next_send_time` returns None and this branch is a no-op.

### 8.4 No changes to SentPacket

**M4a does not add fields to `SentPacket`.** Delivery-rate shadow state belongs to M4b. Persistent congestion uses the existing `time_sent` and `ack_eliciting` fields only; the §5.4 `last_ae_acked_time_sent` tracker is on `PacketNumberSpace`, not on individual `SentPacket`s.

## 9. Tests

### 9.1 `tests/test_cc_cubic.mojo` (~250 LoC, ~14 tests)

- `test_cubic_init_initial_window` — `cwnd = min(10*MDS, 14720)` at construction.
- `test_cubic_slow_start_growth` — each ACK adds `min(acked, MDS)`.
- `test_cubic_enters_ca_on_ssthresh` — after loss, `cwnd < ssthresh` transitions.
- `test_cubic_congestion_event_halves_cwnd` — one loss → cwnd = cwnd * 0.7 (beta).
- `test_cubic_fast_convergence_when_cwnd_below_last_wmax` — `w_max = cwnd * (1+beta)/2` on repeat loss before recovery.
- `test_cubic_persistent_reset_to_min` — `persistent=True` → cwnd = 2*MDS.
- `test_cubic_pacing_rate_slowstart_gain_2x` — pacing rate in SS is `2*cwnd*1e6/srtt`.
- `test_cubic_pacing_rate_ca_gain_1_25x` — pacing rate in CA is `5/4 * cwnd * 1e6/srtt`.
- `test_cubic_pacing_rate_zero_srtt_guarded` — no division by zero.
- `test_cubic_suppress_double_loss_within_rtt` — loss within suppression window is ignored.
- `test_cubic_reno_friendly_w_est_tracks` — AIMD w_est updates independently of cubic curve.
- `test_cubic_copy_semantics` — `Cubic` is Copyable (regression guard for the variant dispatch).
- `test_cubic_cube_root_newton_correct` — helper test: integer cube root matches expected values for edge cases (0, 1, 8, 27, 1e12).
- `test_cubic_overflow_clamp` — with extreme `t - k`, `w_cubic` doesn't overflow past `MAX_CWND = 1 GiB`.

### 9.2 `tests/test_cc_pacing.mojo` (~150 LoC, ~9 tests)

- `test_pacer_init_disabled_returns_none` — disabled pacer always returns None.
- `test_pacer_token_refill_linear` — after `elapsed`, tokens grew by `rate * elapsed / 1e6`.
- `test_pacer_tokens_cap_at_capacity` — refill never exceeds capacity.
- `test_pacer_schedule_returns_none_when_enough_tokens` — ≥ MDS tokens → no wait.
- `test_pacer_schedule_returns_deadline_when_insufficient` — computes correct `now + wait_us`.
- `test_pacer_on_sent_decrements_saturating` — double-spend doesn't underflow.
- `test_pacer_update_capacity_clamped_to_min_burst` — small `cwnd*granularity/srtt` clamped to 10*MDS.
- `test_pacer_update_capacity_clamped_to_max_burst` — large input clamped to 128*MDS.
- `test_pacer_zero_pacing_rate_treated_as_unpaced` — `pacing_rate=0` → returns None.

### 9.3 `tests/test_cc_controller.mojo` (~100 LoC, ~6 tests)

- `test_controller_cubic_dispatch` — `new_cubic()` + `on_packet_sent` visible through controller.
- `test_controller_dummy_unlimited_cwnd` — `new_dummy().cwnd() == UINT64_UNLIMITED`.
- `test_controller_dummy_no_op_acked` — `on_packet_acked` on dummy does not mutate any observable state.
- `test_controller_copy_preserves_variant` — copied controller retains `kind` and variant state.
- `test_controller_persistent_loss_resets_cubic` — persistent=True path through controller resets cubic cwnd.
- `test_controller_name_matches_kind` — `name()` returns the right string.

### 9.4 `tests/test_recovery.mojo` extensions (+~120 LoC, 5 tests)

- `test_recovery_cc_cubic_by_default` — Recovery constructor uses CUBIC.
- `test_recovery_on_packet_acked_feeds_cc` — ACK flow fans into CC (use a recording Dummy variant + kind inspection).
- `test_persistent_congestion_declared_when_spans_period` — two ack-eliciting losses, spanning ≥ threshold × (srtt+4*rttvar+max_ack_delay), and `last_ae_acked_time_sent < earliest` → True.
- `test_persistent_congestion_rejected_when_ae_ack_in_range` — `last_ae_acked_time_sent ∈ [earliest, latest]` → False.
- `test_persistent_congestion_conservative_when_ae_ack_past_range` — `last_ae_acked_time_sent > latest` → False (conservative false-negative, as documented in §5.4).

Test scaffolding note: these tests drive the check by directly constructing `PacketNumberSpace` state + invoking `QuicConnection.detect_persistent_congestion` without going through the wire. A test-only constructor or direct field access is acceptable.

### 9.5 `tests/test_pn_space.mojo` extensions (+~40 LoC, 3 tests)

- `test_pn_space_last_ae_acked_updates_on_ae_ack` — processing an AE ACK advances the tracker.
- `test_pn_space_last_ae_acked_not_updated_on_non_ae_ack` — pure-ACK packet ACK does not advance the tracker.
- `test_pn_space_any_ae_acked_in_range_boundaries` — query returns correct answers for the three boundary cases (unset=0, in range, past range, before range).

### 9.6 `tests/test_quic_connection.mojo` extensions (+~100 LoC, 4 tests)

- `test_cubic_cwnd_gates_send_path` — connection with CUBIC CC cannot send beyond cwnd.
- `test_pacer_delays_burst` — with artificially-low pacing rate, `timeout()` returns a pacer deadline and the second packet is delayed (observed via deadline query, not mutating `refill_and_check`).
- `test_anti_amp_ok_extract_parity` — unvalidated server with `bytes_received = 0` rejects a send; after client Initial ACKed and `_addr_validated()` returns True, the 3x cap is lifted. Regression guard that `_anti_amp_ok` preserves the original `connection.mojo:1391-1394` predicate.
- `test_persistent_congestion_end_to_end` — forced loss-burst across `3 × (srtt + 4*rttvar + max_ack_delay)`; verify CUBIC cwnd resets to `2*MDS` and `recovery.min_rtt == recovery.latest_rtt`. Test-only hook `Recovery._inject_losses(pn_list)` (added as ~20 LoC test scaffolding in `recovery.mojo`; plan-phase decides exact form — module-private method vs conditional-compile guard).

### 9.7 Conformance

No new conformance vectors. Existing 33/33 must stay green. Existing handshake + stream-data integration tests must not regress.

## 10. LoC summary

| Area | Prod | Test |
|---|---|---|
| cc/trait.mojo | 180 | — |
| cc/controller.mojo | 200 | 100 |
| cc/cubic.mojo | 450 | 250 |
| cc/pacing.mojo | 215 | 150 |
| cc/dummy.mojo | 165 | — |
| recovery.mojo delta | 300 | 120 |
| pn_space.mojo delta (§5.4 tracker + tests) | 40 | 40 |
| connection.mojo delta (§8.1 anti-amp extract + send gating + pacer timer + §8.2 ACK flow) | 280 | 100 |
| **Total** | **1830** | **760** |

**M4a total: ~2590 LoC**, matching M3c (2590). Single-plan ceiling respected.

## 11. Open questions deferred to planning

Each resolved by a small `mcp__mojo-mcp__execute` or `lookup` spike at plan-phase kickoff (< 1 hour total):

- **CcController dispatch pattern compiles.** Verify Mojo 0.26.2 accepts the nested-Copyable-variant struct at §2.3 with derived `Copyable`. Fallback: flat-primitive hoist à la `QuicEvent`.
- **UInt128 availability.** If Mojo 0.26.2 exposes `UInt128` or `SIMD[DType.uint128, 1]`, use directly in §4.6 cube math. Otherwise scale-down via `mul_u64_hi_lo(a, b) -> (UInt64, UInt64)` helper.
- **"Unlimited" sentinel.** Resolve `UINT64_UNLIMITED` to the idiomatic form (`~UInt64(0)`, `UInt64.MAX`, `UInt64.max_finite()` — exact name).
- **`Optional` truthiness vs `.is_some()`.** Confirm `if opt:` works the same in 0.26.2 (existing codebase pattern at `connection.mojo:1975`).
- **`Dict[Int, SentPacket]` iteration order.** §5.3 only needs min/max time_sent across the given PN list, so order-independence is fine. But confirm iteration doesn't raise or skip entries in 0.26.2.
- **Newton's-method integer cube root** placement — inline in `cubic.mojo` or shared `src/quic/cc/intmath.mojo`. ~30 LoC either way.
- **Peer `max_ack_delay_us` passthrough** — resolved; `connection.mojo:1079, 1083, 1960` already use `self.peer_params.value().max_ack_delay * 1000` (ms → µs), matching Recovery's µs timebase. The M4a caller passes this value directly into `detect_persistent_congestion`. Listed here only as a plan-phase reminder.
- **`Recovery._inject_losses` test hook** — module-private method, `@parameter if TEST_HOOKS`, or constructed via the existing sent_packets + detect_lost_packets flow with controlled time. Plan-phase selects the least-intrusive form.

## 12. Explicit deferrals (to M4b or later)

Each recorded here with severity/trigger so project-context's open-follow-ups can be updated at M4a retrospective. M4a does **not** attempt to resolve these; picking them up is explicitly M4b's responsibility.

| Deferral | Severity | Trigger |
|---|---|---|
| HyStart++ slow-start exit | optional → required-later | Benchmarking CUBIC on typical real-network traces shows loss-induced slow-start exit over-commits by >2x. |
| Delivery-rate estimator | required-later | M4b: needed for BBR; also informs app-limited CC decisions. |
| MinMax helper | required-later | M4b: HyStart++ baseline min_rtt; reused by BBR. |
| ECN outgoing + incoming validation | required-later | Interop testing with ECN-marking middleboxes; research `quic-cve-pattern-analysis.md` flags ECN as a recurring correctness category. |
| BLOCKED frame emission (DATA/STREAM_DATA/STREAMS) | required-later | Interop testing with peers observing missing BLOCKED; currently stubbed per M3c open follow-up `docs/project-context.md:108`. |
| PN skipping / optimistic-ACK defense (CVE-2025-4820 class) | required-later | M4b: project-context key decision line 51 treats this as MUST. |
| FC auto-tuning (`autotune_window`) | optional → required-later | High-BDP throughput testing shows static windows limit goodput. |
| `on_mtu_update` wiring | optional | PMTUD milestone (likely M5 or later). |
| Connection-wide `send_window` cap | optional | Memory-pressure testing shows per-stream caps are insufficient. |

## 13. Out of scope for M4a (and likely M4b)

- Connection migration (project non-goal).
- Multipath QUIC.
- BBR v1/v2/v3, COPA (future CC milestone; the CcController trait reserves `kind` values 2+).
- HPACK/QPACK, HTTP/3 work (M5).
- 0-RTT tuning.
- qlog emission.
- ACK frequency extension (no production stack ships it; not in TQUIC/quinn/quiche; revisit only if benchmark need emerges).

## 14. References

- **RFCs:** 9002 (QUIC Loss Detection and Congestion Control), 9438 (CUBIC for TCP), 9000 §13 (transport).
- **Source:** TQUIC `src/congestion_control/{congestion_control,cubic,pacing,dummy}.rs`, `src/connection/recovery.rs`.
- **Project research:** `research/quic-loss-detection-edge-cases.md` §4 (persistent congestion), §11 (M3/M4 scope split).
- **Project code:** `src/quic/recovery.mojo` (M3b/M3c baseline), `src/quic/connection.mojo:172` (`QuicEvent` flat-tag precedent), `src/quic/pn_space.mojo:146` (`sent_packets: Dict[Int, SentPacket]` — pre-existing), `src/quic/connection.mojo:1393` (inline amplification check — extracted into `_anti_amp_ok`), `src/quic/connection.mojo:1949` (`def timeout` — pacer `next_send_time` integration point).
