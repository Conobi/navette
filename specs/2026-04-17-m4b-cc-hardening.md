# M4b — CC Hardening + Interop (HyStart++, ECN, BLOCKED)

**Date:** 2026-04-17
**Status:** spec, pending planning
**Depends on:** M4a (shipped 2026-04-17). CUBIC + pacer + persistent congestion in place.
**Successor:** M4c — transport hygiene (FC auto-tuning, PN skipping, SendBuf bare-FIN fix). Spec written after M4b lands.
**LoC estimate:** ~1050 (prod ~700, tests ~350)

---

## 0. Summary

Three independent workstreams delivered in one plan:

1. **HyStart++** — RFC 9406 slow-start hardening: `MinMax` sliding-window RTT filter + CSS (Conservative Slow Start) phase inside `Cubic`. Requires threading `pn: UInt64` through `on_packet_sent`.
2. **ECN** — RFC 9000 §13.4 + RFC 9002 §7.9: outgoing ECT(0) advisory + incoming CE counting + ACK ECN counts + congestion reaction + 3-stage path validation. Adds `ecn_mark: UInt8` to `SentPacket`.
3. **BLOCKED emission** — RFC 9000 §4.1: emit `DATA_BLOCKED` and `STREAM_DATA_BLOCKED` frames when send is stalled by flow control. Uses the existing `FlowControl.blocked_at` dedup guard.

**Non-goals for M4b:**
- Delivery-rate estimator (deferred to BBR milestone)
- BBR or BBRv3
- PN skipping (M4c)
- FC auto-tuning (M4c)
- SendBuf bare-FIN fix (M4c)
- NEW_TOKEN / address migration
- QUIC_STREAMS_BLOCKED frames (RFC 9000 §4.6, separate from flow-control BLOCKED)

---

## 1. Goal

Harden the M4a congestion-control stack against real-network conditions and close the remaining interoperability gaps: slow-start overshooting (HyStart++), ECN-capable network support, and BLOCKED frame emission for flow-control stalls.

---

## 2. File structure

| File | Responsibility | Change |
|---|---|---|
| `src/quic/cc/minmax.mojo` | Windowed-min RTT filter for HyStart++ | CREATE ~120 LoC |
| `src/quic/cc/cubic.mojo` | HyStart++ state machine | MODIFY +~180 LoC |
| `src/quic/cc/controller.mojo` | `on_packet_sent` adds `pn` param; `on_congestion_event` dispatch | MODIFY +~25 LoC |
| `src/quic/cc/dummy.mojo` | `on_packet_sent` adds `pn` param | MODIFY +~5 LoC |
| `src/quic/ecn.mojo` | `EcnCounts`, ECN state constants, `EcnValidator` | CREATE ~130 LoC |
| `src/quic/pn_space.mojo` | `recv_ecn: EcnCounts`, `last_ack_ecn: EcnCounts` | MODIFY +~40 LoC |
| `src/quic/recovery.mojo` | `on_packet_sent` adds `pn` param | MODIFY +~10 LoC |
| `src/quic/connection.mojo` | ECN wiring, BLOCKED emission, send-path `pn` threading | MODIFY +~200 LoC |
| `tests/test_cc_cubic.mojo` | HyStart++ unit tests | MODIFY +~120 LoC |
| `tests/test_cc_minmax.mojo` | MinMax unit tests | CREATE ~60 LoC |
| `tests/test_ecn.mojo` | ECN state machine unit tests | CREATE ~150 LoC |
| `tests/test_quic_connection.mojo` | ECN integration + BLOCKED integration | MODIFY +~80 LoC |
| `scripts/run_tests.sh` | Register `test_cc_minmax`, `test_ecn` | MODIFY +2 lines |

---

## 3. MinMax helper (`src/quic/cc/minmax.mojo`)

Kathleen Nichols' windowed-min filter. Tracks the minimum value seen within a rolling time window using three samples (best, second-best, worst).

```mojo
struct MinMaxSample(Copyable, Movable):
    var t: UInt64  # timestamp (microseconds)
    var v: UInt64  # value

struct MinMax(Copyable, Movable):
    """Windowed minimum filter over a time window.
    Used by HyStart++ for per-round RTT baseline tracking."""
    var window_us: UInt64
    var s: InlineArray[MinMaxSample, 3]

    def __init__(out self, window_us: UInt64):
        ...

    def running_min(mut self, win: UInt64, t: UInt64, meas: UInt64) -> UInt64:
        """Update filter with new measurement at time `t`. Returns current minimum.
        Algorithm: 3-sample sliding window per Nichols 2012."""
        ...

    def get(self) -> UInt64:
        """Return current minimum."""
        return self.s[0].v
```

The 3-sample algorithm:
1. If `t - s[2].t >= win/4`: rotate samples; old s[2] becomes s[1], old s[1] becomes s[0] (best)
2. Replace s[0] if `meas <= s[0].v`; replace s[1] if `meas <= s[1].v`; else replace s[2]
3. Always returns `s[0].v`

---

## 4. HyStart++ (RFC 9406) — `cubic.mojo` additions

HyStart++ detects signs of congestion during slow start before a packet loss occurs. It uses per-round RTT samples to identify increasing delay and transitions to Conservative Slow Start (CSS).

### 4.1 Constants

```mojo
comptime HYSTART_MIN_RTT_THRESH_US: UInt64 = 4_000    # 4 ms
comptime HYSTART_MAX_RTT_THRESH_US: UInt64 = 16_000   # 16 ms
comptime HYSTART_RTT_THRESH_DIVISOR: UInt64 = 8       # thresh = max(4ms, last_min_rtt/8)
comptime HYSTART_CSS_GROWTH_DIVISOR: UInt64 = 4       # CSS cwnd growth = acked/4
comptime HYSTART_CSS_ROUNDS: Int = 5                  # rounds in CSS before exiting SS
comptime HYSTART_MIN_SAMPLES: Int = 8                 # min RTT samples per round
comptime HS_STATE_SS: UInt8 = 0                       # in slow start
comptime HS_STATE_CSS: UInt8 = 1                      # in conservative slow start
comptime HS_STATE_DONE: UInt8 = 2                     # HyStart++ inactive (CA or disabled)
```

### 4.2 New fields on `Cubic`

```mojo
# HyStart++ state (RFC 9406). Active only when in slow start.
var hs_state: UInt8 = HS_STATE_SS
var hs_window_end_pn: UInt64 = 0       # PN marking end of current round
var hs_current_round_min_rtt: UInt64 = UINT64_UNLIMITED
var hs_last_round_min_rtt: UInt64 = UINT64_UNLIMITED
var hs_rtt_sample_count: Int = 0
var hs_css_rounds: Int = 0
```

### 4.3 `on_packet_sent` — signature change

The existing `on_packet_sent(mut self, size: UInt64, now: UInt64)` gains a `pn: UInt64` parameter:

```mojo
def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
    """Called when a packet is sent. Also advances HyStart++ round boundary in CSS."""
    if self.hs_state == HS_STATE_CSS:
        self.hs_window_end_pn = pn   # extend round boundary continuously in CSS
```

This cascades: `DummyCc.on_packet_sent` and `CcController.on_packet_sent` also add `pn`, `Recovery.on_packet_sent` adds `pn`, and `connection.mojo`'s send path passes the PN.

### 4.4 `on_packet_acked` — HyStart++ integration

In `on_packet_acked`, after the slow-start cwnd update, if `hs_state != HS_STATE_DONE`:

```mojo
# HyStart++ RTT sample collection (RFC 9406 §4)
if self.hs_state == HS_STATE_SS or self.hs_state == HS_STATE_CSS:
    # Update current-round minimum RTT using the sample
    var rtt = pkt.rtt_sample   # from AckedPacket.rtt_sample
    if rtt < self.hs_current_round_min_rtt:
        self.hs_current_round_min_rtt = rtt
    self.hs_rtt_sample_count += 1

    # Check if round ended
    if pkt.pkt_num >= self.hs_window_end_pn and self.hs_rtt_sample_count >= HYSTART_MIN_SAMPLES:
        self._hs_on_round_end()
        # Set window end for next round — caller must call on_packet_sent with next PN
        # The hs_window_end_pn is updated on next on_packet_sent call

# CSS cwnd growth REPLACES standard slow-start growth — not an addition.
# The elif ensures only one branch executes; falling through to the standard
# SS path when hs_state == HS_STATE_CSS would double-count acked bytes.
if self.hs_state == HS_STATE_CSS:
    # Grow by acked/4 instead of min(acked, MDS)
    self._cwnd_value += acked_bytes / HYSTART_CSS_GROWTH_DIVISOR
elif self._cwnd_value < self._ssthresh:
    # Standard SS growth (hs_state == HS_STATE_SS, or HS_STATE_DONE and still in SS)
    self._cwnd_value += min(acked_bytes, MDS)
```

### 4.5 `_hs_on_round_end` (private helper)

```mojo
def _hs_on_round_end(mut self):
    """End-of-round processing for HyStart++."""
    # Compute RTT threshold: clamp(last_min_rtt / 8, 4ms, 16ms)
    var thresh = HYSTART_MIN_RTT_THRESH_US
    if self.hs_last_round_min_rtt != UINT64_UNLIMITED:
        thresh = clamp(
            self.hs_last_round_min_rtt / HYSTART_RTT_THRESH_DIVISOR,
            HYSTART_MIN_RTT_THRESH_US,
            HYSTART_MAX_RTT_THRESH_US,
        )

    if self.hs_state == HS_STATE_SS:
        if (self.hs_last_round_min_rtt != UINT64_UNLIMITED
                and self.hs_current_round_min_rtt >= self.hs_last_round_min_rtt + thresh):
            # RTT increasing — enter CSS
            self.hs_state = HS_STATE_CSS
            self.hs_css_rounds = 0
    elif self.hs_state == HS_STATE_CSS:
        self.hs_css_rounds += 1
        if self.hs_css_rounds >= HYSTART_CSS_ROUNDS:
            # Exit slow start
            self._ssthresh = self._cwnd_value
            self.hs_state = HS_STATE_DONE

    # Advance round
    self.hs_last_round_min_rtt = self.hs_current_round_min_rtt
    self.hs_current_round_min_rtt = UINT64_UNLIMITED
    self.hs_rtt_sample_count = 0
    # hs_window_end_pn is updated on the next on_packet_sent call

def _hs_on_loss(mut self):
    """Disable HyStart++ when a loss occurs (we're in CA now)."""
    self.hs_state = HS_STATE_DONE
```

### 4.6 HyStart++ and congestion events

On any congestion event (`on_packets_lost`, `on_congestion_event`): call `_hs_on_loss()` to transition to `HS_STATE_DONE`. HyStart++ is only active during slow start; once a loss or CE mark occurs, standard CUBIC CA takes over.

Note: `_on_congestion_event` (§4.7) applies the same suppression window as loss — if `now < _congestion_event_time + smoothed_rtt`, the call is a no-op and neither `_hs_on_loss()` nor the cwnd reduction fires. The HyStart++ `_hs_on_loss()` call must therefore sit inside `_on_congestion_event` after the suppression guard, not before it.

### 4.7 `on_congestion_event` — new method on `CcController`

ECN CE marks trigger a congestion response that is equivalent to a single packet loss (non-persistent). New method:

```mojo
def on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
    """Congestion signal from ECN CE mark. Triggers cwnd reduction as if one packet
    were lost, but does NOT trigger persistent-congestion logic."""
    if self.kind == CC_KIND_CUBIC:
        self.cubic._on_congestion_event(smoothed_rtt, now)
    # DummyCc: no-op
```

`Cubic._on_congestion_event`:
```mojo
def _on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
    """Single congestion event (ECN CE). Same suppression window as loss."""
    if now < self._congestion_event_time + smoothed_rtt:
        return   # suppress: within 1 RTT of last event
    self._on_loss_internal(smoothed_rtt, now, persistent=False)
```

---

## 5. ECN support (`src/quic/ecn.mojo` + wiring)

### 5.1 `ecn.mojo` — types and constants

```mojo
# IP ECN codepoints (RFC 3168)
comptime ECN_NOT_ECT: UInt8 = 0   # non-ECN-capable
comptime ECN_ECT1: UInt8 = 1      # ECN-capable (ECT(1))
comptime ECN_ECT0: UInt8 = 2      # ECN-capable (ECT(0)) — we use this for sending
comptime ECN_CE: UInt8 = 3        # Congestion Experienced

# ECN path validation states (RFC 9000 §13.4.2)
comptime ECN_STATE_PROBING: UInt8 = 0   # sending ECT(0), verifying path supports ECN
comptime ECN_STATE_CAPABLE: UInt8 = 1   # ECN working
comptime ECN_STATE_DISABLED: UInt8 = 2  # ECN not working on this path

struct EcnCounts(Copyable, Movable):
    var ect0: UInt64
    var ect1: UInt64
    var ce: UInt64

    def __init__(out self): self.ect0 = 0; self.ect1 = 0; self.ce = 0

    def total(self) -> UInt64: return self.ect0 + self.ect1 + self.ce
    def is_zero(self) -> Bool: return self.ect0 == 0 and self.ect1 == 0 and self.ce == 0
```

### 5.2 `SentPacket` — `ecn_mark` field

Add to `SentPacket` (`pn_space.mojo`):
```mojo
var ecn_mark: UInt8   # ECN codepoint applied when this packet was sent (0 = NOT_ECT)
```

Default value: `0` (NOT_ECT). Set to `ECN_ECT0` when ECN is active.

This enables precise validation: count how many ECT(0) packets are currently in-flight when an ACK arrives, and compare against `ack.ecn_ect0`.

### 5.3 `PacketNumberSpace` additions

```mojo
var recv_ecn: EcnCounts     # ECN marks observed on packets received in this space
var last_ack_ecn: EcnCounts # ECN counts from the last ACK we received (for CE delta)
var ect0_in_flight: UInt64  # count of currently in-flight packets sent with ECT(0)
```

`ect0_in_flight` replaces the O(n) `sent_packets` iteration in §5.8:
- Increment when a packet is sent with `ecn_mark == ECN_ECT0`
- Decrement (saturating) on each ACK of an ECT(0)-marked packet
- Decrement (saturating) on each loss of an ECT(0)-marked packet

Updated in:
- `recv_datagram` path: when processing a received packet in space `i`, increment `spaces[i].recv_ecn.ce` if `ecn_mark == ECN_CE`, `recv_ecn.ect0` if `ECN_ECT0`, etc.
- `_handle_ack`: store the received `ack.ecn_ect0/ect1/ce` into `space.last_ack_ecn`.

### 5.4 `QuicConnection` ECN fields

```mojo
var ecn_state: UInt8 = ECN_STATE_PROBING
var ecn_probe_pkts_needed: Int = 10   # probe this many packets before checking
var ecn_probe_pkts_sent: Int = 0      # packets sent with ECT(0) during probing
var ecn_probe_first_pn: UInt64 = 0   # PN of first ECT(0) probe packet
```

`ecn_probe_first_pn` is set when `ecn_probe_pkts_sent` goes from 0 to 1. The PROBING→DISABLED check only fires when `ack.largest_acked >= ecn_probe_first_pn`, preventing a spurious disable triggered by ACKs that predate the probing phase.

### 5.5 `recv_datagram` signature change

```mojo
def recv_datagram(mut self, data: List[UInt8], ecn_mark: UInt8 = 0) raises:
    """Process incoming datagram. `ecn_mark` is the IP ECN codepoint observed by the
    caller's recvmsg. Default 0 (NOT_ECT) preserves all existing call sites."""
```

On receive: after decrypting and identifying the PN space, if `ecn_state != ECN_STATE_DISABLED`:
```mojo
match ecn_mark:
    ECN_ECT0: spaces[space_idx].recv_ecn.ect0 += 1
    ECN_ECT1: spaces[space_idx].recv_ecn.ect1 += 1
    ECN_CE:   spaces[space_idx].recv_ecn.ce += 1
    _: pass
```

### 5.6 `ecn_mark()` — outgoing advisory

```mojo
def ecn_mark(self) -> UInt8:
    """Return the ECN codepoint the caller should apply to outgoing datagrams.
    Returns ECN_ECT0 when ECN is active, ECN_NOT_ECT when disabled."""
    if self.ecn_state == ECN_STATE_DISABLED: return ECN_NOT_ECT
    return ECN_ECT0
```

At the send site in `connection.mojo`, after building a packet, set `sent.ecn_mark = self.ecn_mark()` and increment `ecn_probe_pkts_sent` if state is PROBING.

### 5.7 ACK generation with ECN counts

In `_build_ack_frame` (or wherever ACK frames are assembled):
```mojo
if not spaces[space_idx].recv_ecn.is_zero():
    ack.has_ecn = True
    ack.ecn_ect0 = spaces[space_idx].recv_ecn.ect0
    ack.ecn_ect1 = spaces[space_idx].recv_ecn.ect1
    ack.ecn_ce   = spaces[space_idx].recv_ecn.ce
```

### 5.8 ACK receipt — ECN processing

In `_handle_ack`, after extracting the ACK frame:
```mojo
if ack.has_ecn and self.ecn_state != ECN_STATE_DISABLED:
    self._process_ecn_feedback(space_idx, ack)
```

```mojo
def _process_ecn_feedback(mut self, space_idx: Int, ack: AckFrame):
    """RFC 9000 §13.4.2 + RFC 9002 §7.9 ECN feedback processing."""
    var space = self.spaces[space_idx]
    var prev = space.last_ack_ecn

    # Update last-seen ECN counts
    space.last_ack_ecn = EcnCounts(ect0=ack.ecn_ect0, ect1=ack.ecn_ect1, ce=ack.ecn_ce)

    # --- Validation (RFC 9000 §13.4.2) ---
    if self.ecn_state == ECN_STATE_PROBING:
        # Check: did the peer report any ECN counts?
        if self.ecn_probe_pkts_sent >= self.ecn_probe_pkts_needed:
            if ack.ecn_ect0 == 0 and ack.ecn_ect1 == 0 and ack.ecn_ce == 0:
                self.ecn_state = ECN_STATE_DISABLED   # path strips ECN
                return
            else:
                self.ecn_state = ECN_STATE_CAPABLE

    # Bleaching check: total ECN counts in ACK > ECT(0) packets we sent in this space
    var sent_ect0: UInt64 = 0
    for pn in space.sent_packets.values():
        if pn.ecn_mark == ECN_ECT0: sent_ect0 += 1
    if ack.ecn_ect0 + ack.ecn_ect1 + ack.ecn_ce > sent_ect0 + 1:
        # More ECN-marked ACKs than we sent with ECT(0) → validation failure
        self.ecn_state = ECN_STATE_DISABLED
        return

    # --- CE delta → congestion event (RFC 9002 §7.9) ---
    var ce_delta = ack.ecn_ce - prev.ce   # UInt64 subtraction: wraps but stays positive if CE only grows
    if ack.ecn_ce > prev.ce:              # CE increased
        self.recovery.cc.on_congestion_event(self.recovery.smoothed_rtt, now)
```

**Implementation note:** The bleaching check iterates `sent_packets` which is O(in_flight). This is acceptable since `_process_ecn_feedback` is called at most once per ACK. An alternative is to maintain a per-space `sent_ect0_count: Int` counter (increment on send, decrement on ACK/loss), but the simple iteration avoids a new field.

---

## 6. BLOCKED frame emission (`connection.mojo`)

### 6.1 `FlowControl.blocked_at` semantics

`FlowControl.blocked_at: UInt64` is already defined in `flow_control.mojo`. Semantics:
- `blocked_at == 0`: no BLOCKED sent at current limit
- `blocked_at == limit`: BLOCKED already sent at this limit; don't re-emit until limit changes

`FlowControl.ensure_limit` does **not** reset `blocked_at`. The implementation must reset it explicitly in the MAX_DATA / MAX_STREAM_DATA receive handler:
```mojo
conn_fc.ensure_limit(new_limit)
conn_fc.blocked_at = 0   # allow re-emission at the new limit
```
Same pattern for per-stream FC on MAX_STREAM_DATA.

### 6.2 Connection-level DATA_BLOCKED

In `_build_frames_for_space` (Application space, i.e., `space_idx == 2`), after STREAM frames:

```mojo
# Connection-level DATA_BLOCKED (RFC 9000 §4.1)
# Emit when the connection send window is exhausted.
var conn_limit = self.conn_fc.limit
if self.conn_fc.received >= conn_limit and self.conn_fc.blocked_at != conn_limit:
    frames.append(Frame.data_blocked(conn_limit))
    self.conn_fc.blocked_at = conn_limit
```

`FlowControl` fields: `received` = bytes sent on wire; `limit` = peer-advertised maximum; `available()` = `limit - received`.

### 6.3 Stream-level STREAM_DATA_BLOCKED

After building STREAM frames for each stream, check if there is buffered send data that couldn't be sent due to stream flow control:

```mojo
# STREAM_DATA_BLOCKED (RFC 9000 §4.1)
for sid in self.stream_map.send_blocked_streams():
    var s = self.stream_map.get_stream(sid)
    var stream_limit = s.send_fc.limit
    if s.send_fc.blocked_at != stream_limit:
        frames.append(Frame.stream_data_blocked(StreamDataBlockedFrame(sid, stream_limit)))
        s.send_fc.blocked_at = stream_limit
```

`StreamMap.send_blocked_streams()` returns stream IDs where `stream.has_pending_data() and stream.send_fc_exhausted()`. **During implementation**: check what `StreamMap` + `Stream` already expose; may need a small helper method.

`Frame.stream_data_blocked` takes a `StreamDataBlockedFrame` struct (not two positional args). `Frame.data_blocked` similarly: `Frame.data_blocked(DataBlockedFrame(conn_limit))` — verify the actual factory signature in `frame.mojo:433` during implementation.

### 6.4 Receive path — ignore DATA_BLOCKED / STREAM_DATA_BLOCKED

The existing `_on_data_blocked` and `_on_stream_data_blocked` handlers in `connection.mojo` (M3c) should already handle incoming BLOCKED frames (they are informational — no required response). **Verify these handlers exist**; if not, add no-op handlers.

---

## 7. `on_packet_sent` parameter migration

`CcController`, `DummyCc`, and `Cubic` gain `pn: UInt64` as second parameter:

```mojo
# Before:
def on_packet_sent(mut self, size: UInt64, now: UInt64)

# After:
def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64)
```

`Recovery.on_packet_sent` keeps `size: Int` (not `UInt64` — matches the existing M4a signature at `recovery.mojo:121`):

```mojo
# Before:
def on_packet_sent(mut self, size: Int, in_flight: Bool, now: UInt64 = UInt64(0))

# After:
def on_packet_sent(mut self, size: Int, in_flight: Bool, pn: UInt64, now: UInt64 = UInt64(0))
```

`connection.mojo`'s send path already has the PN when recording `SentPacket`. It passes `pn` at the call site.

`DummyCc.on_packet_sent` ignores `pn` (no HyStart++ in dummy).

`Cubic.on_packet_sent` uses `pn` to update `hs_window_end_pn` during CSS (§4.3).

Migration is mechanical — 3 structs + 1 call site in `connection.mojo`.

---

## 8. Tests

### 8.1 `tests/test_cc_minmax.mojo` (~60 LoC)

- `test_minmax_single_sample` — single measurement returns itself
- `test_minmax_tracks_minimum` — min is maintained across rising measurements
- `test_minmax_expires_old_samples` — after window expires, new minimum is adopted
- `test_minmax_constant_stream` — constant input returns constant min

### 8.2 `tests/test_cc_cubic.mojo` — HyStart++ additions (~120 LoC)

- `test_hystart_starts_in_ss` — initial state is `HS_STATE_SS`
- `test_hystart_no_exit_before_min_samples` — round with < 8 samples never triggers CSS
- `test_hystart_enters_css_on_rtt_increase` — if current_min_rtt > last_min_rtt + thresh → CSS
- `test_hystart_css_growth_is_quartered` — in CSS, acked bytes / 4
- `test_hystart_exits_after_css_rounds` — after 5 CSS rounds, ssthresh = cwnd, HS_STATE_DONE
- `test_hystart_no_reentry_after_loss` — loss → HS_STATE_DONE, stays DONE
- `test_hystart_stable_rtt_stays_in_ss` — flat RTT never triggers CSS
- `test_hystart_thresh_clamped` — very fast path (< 32ms min RTT) → thresh = 4ms; slow path (> 128ms) → thresh = 16ms

### 8.3 `tests/test_ecn.mojo` (~150 LoC)

- `test_ecn_counts_ce_mark` — `recv_datagram` with `ecn_mark=CE` increments `recv_ecn.ce`
- `test_ecn_ack_includes_ecn_counts` — generated ACK has `has_ecn=True` when `recv_ecn` non-zero
- `test_ecn_probing_to_capable` — after N probes, ACK with ECN counts → CAPABLE
- `test_ecn_probing_to_disabled_no_counts` — after N probes, ACK without ECN → DISABLED
- `test_ecn_disabled_no_ecn_mark` — `ecn_mark()` returns 0 when DISABLED
- `test_ecn_ce_triggers_congestion` — CE delta > 0 → `cc.on_congestion_event` reduces cwnd
- `test_ecn_ce_suppressed_within_rtt` — two CE events within 1 RTT → second suppressed
- `test_ecn_bleaching_disables` — ACK ECN total > sent ECT(0) → DISABLED

### 8.4 `tests/test_quic_connection.mojo` additions (~80 LoC)

- `test_blocked_frames_emitted_on_conn_fc_stall` — connection FC exhausted → DATA_BLOCKED in next `send()`
- `test_blocked_frames_not_re-emitted_at_same_limit` — BLOCKED sent once per limit; not on next `send()` at same limit
- `test_blocked_cleared_on_max_data_increase` — MAX_DATA from peer clears blocked state, allows re-emission
- `test_ecn_integration_ce_reduces_cwnd` — end-to-end: inject CE mark on recv, verify cwnd shrinks after ACK loop

---

## 9. LoC budget

| Component | Prod | Test | Total |
|---|---|---|---|
| `cc/minmax.mojo` (new) | 120 | 60 | 180 |
| `cubic.mojo` HyStart++ | 180 | 120 | 300 |
| `controller.mojo` + `dummy.mojo` migration | 30 | 0 | 30 |
| `ecn.mojo` (new) | 130 | 150 | 280 |
| `pn_space.mojo` ECN fields | 40 | 0 | 40 |
| `recovery.mojo` param migration | 10 | 0 | 10 |
| `connection.mojo` ECN + BLOCKED | 200 | 80 | 280 |
| `run_tests.sh` | 2 | — | 2 |
| **Total** | **712** | **410** | **1122** |

---

## 10. Open questions / deferred

| What | Severity | Trigger |
|---|---|---|
| Delivery-rate estimator | required-later | BBR milestone |
| BBR / BBRv3 | required-later | M5 / post-M5 CC milestone |
| FC auto-tuning | required-later | M4c |
| PN skipping (defense-in-depth) | required-later | M4c |
| SendBuf bare-FIN fix | required-later | M4c |
| QUIC_STREAMS_BLOCKED (§4.6) | optional | Interop with MAX_STREAMS-limited peers |
| ECN bleaching check optimization | optional | Replace O(in_flight) iteration with per-space counter if profiling shows cost |

---

## 11. Mojo 0.26.2 notes

- `InlineArray[T, N]` — used for MinMax's 3-sample buffer. Verify `T` must be `Copyable` (MinMaxSample is).
- `UInt64` subtraction wraps on underflow — CE delta uses `if ack.ecn_ce > prev.ce` guard before subtraction to avoid wrapping.
- Default parameter `ecn_mark: UInt8 = 0` in `recv_datagram` — Mojo 0.26.2 supports default params in `def` functions; all existing call sites that omit the argument continue to compile.
- `SentPacket` already uses `Copyable` pattern (move ctor + copy ctor); adding `ecn_mark: UInt8` field follows the existing pattern.
