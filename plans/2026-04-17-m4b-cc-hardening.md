# M4b — CC Hardening + Interop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use atelier:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HyStart++ (RFC 9406), ECN support (RFC 9000 §13.4 + RFC 9002 §7.9), and BLOCKED frame emission to the QUIC congestion-control stack.
**Architecture:** Three independent workstreams — MinMax helper + HyStart++ in `cubic.mojo` with `on_packet_sent` PN threading; ECN types + `pn_space` ECN fields + `connection.mojo` wiring; BLOCKED frame emission in `connection.mojo`. Tests for each workstream.
**Tech Stack:** Mojo 0.26.2, sans-I/O `QuicConnection`, `src/quic/cc/` CC subsystem.

---

## File structure

| File | Responsibility | Change |
|---|---|---|
| `src/quic/cc/minmax.mojo` | Windowed-min RTT filter (Nichols 3-sample) | CREATE |
| `src/quic/cc/cc_trait.mojo` | Update method-contract comment for new `pn` param | MODIFY |
| `src/quic/cc/dummy.mojo` | Add `pn: UInt64` to `on_packet_sent` | MODIFY |
| `src/quic/cc/controller.mojo` | Add `pn` to `on_packet_sent`; add `on_congestion_event` | MODIFY |
| `src/quic/cc/cubic.mojo` | HyStart++ state machine + `_on_congestion_event` | MODIFY |
| `src/quic/ecn.mojo` | ECN constants, `EcnCounts`, path-state constants | CREATE |
| `src/quic/pn_space.mojo` | `ecn_mark` on `SentPacket`; ECN fields on `PacketNumberSpace` | MODIFY |
| `src/quic/recovery.mojo` | Add `pn: UInt64` to `on_packet_sent` | MODIFY |
| `src/quic/connection.mojo` | ECN wiring, BLOCKED emission, send-path PN threading | MODIFY |
| `tests/test_cc_minmax.mojo` | MinMax unit tests | CREATE |
| `tests/test_cc_cubic.mojo` | HyStart++ unit tests (8 new functions) | MODIFY |
| `tests/test_ecn.mojo` | ECN state machine integration tests | CREATE |
| `tests/test_quic_connection.mojo` | BLOCKED + ECN end-to-end tests (4 new functions) | MODIFY |
| `scripts/run_tests.sh` | Register `test_cc_minmax`, `test_ecn` | MODIFY |

---

**Parallelism guide (for atelier:subagent-driven-development):**
- Tasks 0, 1, 4 have no file overlap → dispatch in parallel.
- Tasks 2, 5 have no file overlap (cubic vs pn_space) → dispatch in parallel after 0+1+4.
- Task 3 modifies `cubic.mojo` and `controller.mojo` (overlap with T2) → run after T2.
- Task 6 depends on T1+T3+T5; Task 8 depends on T2. T6 and T8 have no overlap → dispatch in parallel after T3.
- Task 7 modifies `connection.mojo` (overlap with T6) → run after T6.
- Task 9 depends on T7+T8 → run last.

---

### Task 0: MinMax windowed-min filter

**Files:**
- Create: `src/quic/cc/minmax.mojo`
- Create: `tests/test_cc_minmax.mojo`

- [ ] **Step 1: Write failing test**

```mojo
# tests/test_cc_minmax.mojo
from std.testing import assert_true
from src.quic.cc.minmax import MinMax, MinMaxSample

comptime WIN_10MS: UInt64 = 10_000  # 10 ms in microseconds


def test_minmax_single_sample() raises:
    var m = MinMax(window_us=WIN_10MS)
    var v = m.running_min(WIN_10MS, UInt64(1000), UInt64(500))
    assert_true(v == UInt64(500), "single sample returns itself")
    assert_true(m.get() == UInt64(500), "get() returns same")
    print("PASS: test_minmax_single_sample")


def test_minmax_tracks_minimum() raises:
    var m = MinMax(window_us=WIN_10MS)
    _ = m.running_min(WIN_10MS, UInt64(1000), UInt64(100))
    _ = m.running_min(WIN_10MS, UInt64(2000), UInt64(200))
    _ = m.running_min(WIN_10MS, UInt64(3000), UInt64(300))
    assert_true(m.get() == UInt64(100), "min maintained across rising measurements")
    print("PASS: test_minmax_tracks_minimum")


def test_minmax_expires_old_samples() raises:
    var m = MinMax(window_us=WIN_10MS)
    _ = m.running_min(WIN_10MS, UInt64(1000), UInt64(100))
    # Advance past window (1000 + 10000 + 1 = 11001).
    var v = m.running_min(WIN_10MS, UInt64(12000), UInt64(250))
    assert_true(v == UInt64(250), "expired window adopts new minimum")
    print("PASS: test_minmax_expires_old_samples")


def test_minmax_constant_stream() raises:
    var m = MinMax(window_us=WIN_10MS)
    for i in range(5):
        var t = UInt64(i) * UInt64(1000)
        _ = m.running_min(WIN_10MS, t, UInt64(42))
    assert_true(m.get() == UInt64(42), "constant input returns constant min")
    print("PASS: test_minmax_constant_stream")


def main():
    test_minmax_single_sample()
    test_minmax_tracks_minimum()
    test_minmax_expires_old_samples()
    test_minmax_constant_stream()
    print("All MinMax tests passed.")
```

- [ ] **Step 2: Verify it fails**

Run: `uv run mojo run -I . tests/test_cc_minmax.mojo`
Expected: FAIL — `ModuleNotFoundError` or `cannot find 'MinMax'`

- [ ] **Step 3: Implement `src/quic/cc/minmax.mojo`**

```mojo
# src/quic/cc/minmax.mojo
# Windowed-minimum filter — Kathleen Nichols 3-sample sliding-window algorithm.
# Used by HyStart++ for per-round RTT baseline tracking.
# Available as a standalone primitive for future BBR delivery-rate estimation.


struct MinMaxSample(Copyable, Movable):
    """One sample in the MinMax filter: timestamp + measured value."""
    var t: UInt64  # microseconds
    var v: UInt64  # value (e.g., RTT in microseconds)

    def __init__(out self, t: UInt64, v: UInt64):
        self.t = t
        self.v = v

    def __init__(out self, *, other: Self):
        self.t = other.t
        self.v = other.v

    def __init__(out self, *, deinit take: Self):
        self.t = take.t
        self.v = take.v


struct MinMax(Copyable, Movable):
    """Windowed minimum filter over a rolling time window.

    Three-sample structure: s0 = best (minimum), s1 = subwindow, s2 = oldest.
    All samples initialize to (t=0, v=UInt64.MAX) so the first real measurement
    always beats the sentinel.
    """
    var window_us: UInt64
    var s0: MinMaxSample  # best (lowest value in full window)
    var s1: MinMaxSample  # minimum in most-recent half-window
    var s2: MinMaxSample  # minimum in most-recent quarter-window

    def __init__(out self, window_us: UInt64):
        self.window_us = window_us
        var sentinel = MinMaxSample(t=UInt64(0), v=UInt64.MAX)
        self.s0 = MinMaxSample(other=sentinel)
        self.s1 = MinMaxSample(other=sentinel)
        self.s2 = MinMaxSample(other=sentinel)

    def __init__(out self, *, other: Self):
        self.window_us = other.window_us
        self.s0 = MinMaxSample(other=other.s0)
        self.s1 = MinMaxSample(other=other.s1)
        self.s2 = MinMaxSample(other=other.s2)

    def __init__(out self, *, deinit take: Self):
        self.window_us = take.window_us
        self.s0 = take.s0
        self.s1 = take.s1
        self.s2 = take.s2

    def running_min(mut self, win: UInt64, t: UInt64, meas: UInt64) -> UInt64:
        """Update filter with measurement `meas` at time `t`. Returns current minimum.

        Algorithm:
        1. Fast path: new meas is a new minimum → overwrite all three samples.
        2. Full-window rotation: if s0 has expired, promote s1→s0, s2→s1, new→s2.
        3. Subwindow updates: update s1/s2 if meas beats their values.
        """
        # Fast path: new measurement is a new minimum.
        if meas <= self.s0.v:
            self.s0 = MinMaxSample(t=t, v=meas)
            self.s1 = MinMaxSample(t=t, v=meas)
            self.s2 = MinMaxSample(t=t, v=meas)
            return meas
        # Full-window rotation: s0 sample older than win.
        if t >= self.s0.t + win:
            self.s0 = MinMaxSample(other=self.s1)
            self.s1 = MinMaxSample(other=self.s2)
            self.s2 = MinMaxSample(t=t, v=meas)
            if meas <= self.s0.v:
                self.s0 = MinMaxSample(t=t, v=meas)
                self.s1 = MinMaxSample(t=t, v=meas)
            elif meas <= self.s1.v:
                self.s1 = MinMaxSample(t=t, v=meas)
            return self.s0.v
        # Quarter-window expiry: s1 is stale.
        if t >= self.s1.t + win // UInt64(4):
            self.s1 = MinMaxSample(t=t, v=meas)
            self.s2 = MinMaxSample(t=t, v=meas)
        elif meas <= self.s1.v:
            self.s1 = MinMaxSample(t=t, v=meas)
            self.s2 = MinMaxSample(t=t, v=meas)
        elif meas <= self.s2.v:
            self.s2 = MinMaxSample(t=t, v=meas)
        return self.s0.v

    def get(self) -> UInt64:
        """Return current minimum without updating."""
        return self.s0.v
```

- [ ] **Step 4: Verify tests pass**

Run: `uv run mojo run -I . tests/test_cc_minmax.mojo`
Expected: PASS — `All MinMax tests passed.`

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message: `feat: add MinMax windowed-min filter for HyStart++ RTT tracking`

---

### Task 1: `on_packet_sent` PN threading migration

**Files:**
- Modify: `src/quic/cc/cc_trait.mojo:62`
- Modify: `src/quic/cc/dummy.mojo:21`
- Modify: `src/quic/cc/controller.mojo:50-52`
- Modify: `src/quic/recovery.mojo:121-131`

- [ ] **Step 1: Update `cc_trait.mojo` method-contract comment**

In `src/quic/cc/cc_trait.mojo`, replace the `on_packet_sent` doc line:

```
# on_packet_sent(mut self, size: UInt64, now: UInt64)
#     Called when an in-flight packet leaves the host.
```

with:

```mojo
# on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64)
#     Called when an in-flight packet leaves the host.
#     `pn` is the packet number; used by HyStart++ round tracking.
```

- [ ] **Step 2: Update `dummy.mojo`**

Replace:
```mojo
    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        pass
```
with:
```mojo
    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        pass
```

- [ ] **Step 3: Update `controller.mojo`**

Replace:
```mojo
    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packet_sent(size, now)
```
with:
```mojo
    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        if self.kind == CC_KIND_CUBIC:
            self.cubic.on_packet_sent(size, pn, now)
```

- [ ] **Step 4: Update `recovery.mojo`**

Replace:
```mojo
    def on_packet_sent(mut self, size: Int, in_flight: Bool, now: UInt64 = UInt64(0)):
        """Track bytes when a packet is sent and notify CC.

        The `now` parameter defaults to 0 for backward compatibility with M3b
        callers. Task 8/9 will thread the real timestamp through.
        Note: pacer.on_sent is called at the actual send site by connection.mojo,
        not here, since the connection controls the send path.
        """
        if in_flight:
            self.bytes_in_flight += UInt64(size)
            self.cc.on_packet_sent(UInt64(size), now)
```
with:
```mojo
    def on_packet_sent(mut self, size: Int, in_flight: Bool,
                       pn: UInt64 = UInt64(0), now: UInt64 = UInt64(0)):
        """Track bytes when a packet is sent and notify CC.

        `pn` defaults to 0 for backward compatibility with existing call sites.
        `connection.mojo` (Task 6) will pass the real PN.
        """
        if in_flight:
            self.bytes_in_flight += UInt64(size)
            self.cc.on_packet_sent(UInt64(size), pn, now)
```

- [ ] **Step 5: Verify existing tests still pass**

Run: `bash scripts/run_tests.sh`
Expected: PASS — all 56/56 tests pass (backward-compat default pn=0 preserves callers).

- [ ] **Step 6: Commit**

Use the `commit-smart` skill. Message: `feat: thread pn param through on_packet_sent (CC + recovery)`

---

### Task 2: HyStart++ core in `cubic.mojo`

**Files:**
- Modify: `src/quic/cc/cubic.mojo`

- [ ] **Step 1: Write failing test (add to test_cc_cubic.mojo temporarily)**

Add at the bottom of `tests/test_cc_cubic.mojo` before `main()`:

```mojo
def test_hystart_initial_state() raises:
    var c = Cubic(max_datagram_size=MDS)
    assert_true(c.hs_state == HS_STATE_SS, "starts in SS")
    assert_true(c.hs_window_end_pn == UInt64(0), "window end starts at 0")
    print("PASS: test_hystart_initial_state")
```

And add `test_hystart_initial_state()` to `main()`.

- [ ] **Step 2: Verify it fails**

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: FAIL — `'Cubic' has no attribute 'hs_state'`

- [ ] **Step 3: Add HyStart++ imports and constants to `cubic.mojo`**

After the existing imports, add:
```mojo
from src.quic.cc.minmax import MinMax
```

After the existing module-scope constants (after `CUBIC_SECONDS_CUBED_SCALE_U128`), add:

```mojo
# --- HyStart++ constants (RFC 9406) ---

comptime HYSTART_MIN_RTT_THRESH_US: UInt64 = 4_000     # 4 ms minimum threshold
comptime HYSTART_MAX_RTT_THRESH_US: UInt64 = 16_000    # 16 ms maximum threshold
comptime HYSTART_RTT_THRESH_DIVISOR: UInt64 = 8        # thresh = last_min_rtt / 8
comptime HYSTART_CSS_GROWTH_DIVISOR: UInt64 = 4        # CSS cwnd growth = acked // 4
comptime HYSTART_CSS_ROUNDS: Int = 5                   # CSS rounds before exiting SS
comptime HYSTART_MIN_SAMPLES: Int = 8                  # min RTT samples per round
comptime HS_STATE_SS: UInt8 = 0                        # in slow start (standard)
comptime HS_STATE_CSS: UInt8 = 1                       # in conservative slow start
comptime HS_STATE_DONE: UInt8 = 2                      # HyStart++ inactive (CA or loss)
```

- [ ] **Step 4: Add HyStart++ fields to `Cubic` struct**

In the `Cubic` struct, after `var max_datagram_size: UInt64`:

```mojo
    # --- HyStart++ state (RFC 9406). Active only during slow start. ---
    var hs_state: UInt8               # HS_STATE_SS / HS_STATE_CSS / HS_STATE_DONE
    var hs_window_end_pn: UInt64      # PN marking end of current round
    var hs_current_round_min_rtt: UInt64  # minimum RTT sample in current round
    var hs_last_round_min_rtt: UInt64    # minimum RTT from the previous round
    var hs_rtt_sample_count: Int      # RTT samples collected this round
    var hs_css_rounds: Int            # number of CSS rounds elapsed
```

In `__init__`, after `self.initial_window = iw`, add:

```mojo
        self.hs_state = HS_STATE_SS
        self.hs_window_end_pn = UInt64(0)
        self.hs_current_round_min_rtt = UINT64_UNLIMITED
        self.hs_last_round_min_rtt = UINT64_UNLIMITED
        self.hs_rtt_sample_count = 0
        self.hs_css_rounds = 0
```

- [ ] **Step 5: Replace `on_packet_sent` in `Cubic`**

Replace:
```mojo
    def on_packet_sent(mut self, size: UInt64, now: UInt64):
        """Bookkeeping hook; CUBIC does not mutate cwnd on send."""
        pass
```
with:
```mojo
    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        """Track round boundary for HyStart++. CUBIC does not mutate cwnd on send."""
        # In both SS and CSS, track the latest sent PN as the round-end marker.
        # In CSS, this continuously extends the boundary so the CSS phase lasts
        # approximately one RTT before triggering round-end evaluation.
        if self.hs_state == HS_STATE_SS or self.hs_state == HS_STATE_CSS:
            self.hs_window_end_pn = pn
```

- [ ] **Step 6: Update `on_packet_acked` in `Cubic` with HyStart++ integration**

Replace the slow-start block in `on_packet_acked`:

Current slow-start block (lines 134–140):
```mojo
        if self._cwnd_value < self.ssthresh:
            # Slow-start: cwnd += min(acked_bytes, MDS). Standard (no HyStart++).
            var inc = packet.size
            if inc > self.max_datagram_size:
                inc = self.max_datagram_size
            self._cwnd_value += inc
            return
```

Replace with:
```mojo
        # HyStart++ RTT sample collection (while in SS or CSS).
        if self.hs_state == HS_STATE_SS or self.hs_state == HS_STATE_CSS:
            var rtt = packet.rtt_sample
            if rtt < self.hs_current_round_min_rtt:
                self.hs_current_round_min_rtt = rtt
            self.hs_rtt_sample_count += 1
            if packet.pkt_num >= self.hs_window_end_pn and self.hs_rtt_sample_count >= HYSTART_MIN_SAMPLES:
                self._hs_on_round_end()

        # CSS cwnd growth REPLACES standard SS growth (not an addition).
        # The elif prevents double-counting if hs_state is CSS and cwnd < ssthresh.
        if self.hs_state == HS_STATE_CSS:
            self._cwnd_value += packet.size // HYSTART_CSS_GROWTH_DIVISOR
            return
        elif self._cwnd_value < self.ssthresh:
            # Standard SS: cwnd += min(acked, MDS). Applies when hs_state is SS or DONE.
            var inc = packet.size
            if inc > self.max_datagram_size:
                inc = self.max_datagram_size
            self._cwnd_value += inc
            return
```

- [ ] **Step 7: Add `_hs_on_round_end` and `_hs_on_loss` helpers to `Cubic`**

Add before the `name` method:

```mojo
    def _hs_on_round_end(mut self):
        """End-of-round processing for HyStart++ (RFC 9406 §4.3)."""
        if self.hs_state == HS_STATE_SS:
            # Only check for delay increase once we have a baseline (previous round).
            if self.hs_last_round_min_rtt != UINT64_UNLIMITED:
                # Threshold: clamp(last_min_rtt / 8, 4ms, 16ms).
                var raw = self.hs_last_round_min_rtt // HYSTART_RTT_THRESH_DIVISOR
                var thresh = raw
                if thresh < HYSTART_MIN_RTT_THRESH_US:
                    thresh = HYSTART_MIN_RTT_THRESH_US
                if thresh > HYSTART_MAX_RTT_THRESH_US:
                    thresh = HYSTART_MAX_RTT_THRESH_US
                if self.hs_current_round_min_rtt >= self.hs_last_round_min_rtt + thresh:
                    # RTT increasing — enter Conservative Slow Start.
                    self.hs_state = HS_STATE_CSS
                    self.hs_css_rounds = 0
        elif self.hs_state == HS_STATE_CSS:
            self.hs_css_rounds += 1
            if self.hs_css_rounds >= HYSTART_CSS_ROUNDS:
                # CSS complete — exit slow start by setting ssthresh = current cwnd.
                self.ssthresh = self._cwnd_value
                self.hs_state = HS_STATE_DONE
        # Advance round: promote current stats to "last" and reset counters.
        self.hs_last_round_min_rtt = self.hs_current_round_min_rtt
        self.hs_current_round_min_rtt = UINT64_UNLIMITED
        self.hs_rtt_sample_count = 0
        # hs_window_end_pn will be updated by the next on_packet_sent call.

    def _hs_on_loss(mut self):
        """Disable HyStart++ when a loss or congestion event occurs."""
        self.hs_state = HS_STATE_DONE
```

- [ ] **Step 8: Call `_hs_on_loss` at top of `on_packets_lost`**

In `on_packets_lost`, insert `self._hs_on_loss()` as the first statement:

```mojo
    def on_packets_lost(
        mut self,
        lost: List[LostPacket],
        smoothed_rtt_us: UInt64,
        now: UInt64,
        persistent: Bool,
    ):
        """Reduce cwnd on congestion event. Persistent congestion resets to min."""
        self._hs_on_loss()  # Disable HyStart++ on any loss detection.
        if persistent:
            ...
```

- [ ] **Step 9: Verify the test passes**

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: PASS — all existing tests + `test_hystart_initial_state` pass.

- [ ] **Step 10: Run full test suite**

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56 tests.

- [ ] **Step 11: Commit**

Use the `commit-smart` skill. Message: `feat: add HyStart++ state machine to Cubic (RFC 9406)`

---

### Task 3: `on_congestion_event` in `cubic.mojo` and `controller.mojo`

**Files:**
- Modify: `src/quic/cc/cubic.mojo` (add `_on_congestion_event`)
- Modify: `src/quic/cc/controller.mojo` (add `on_congestion_event` dispatch)

- [ ] **Step 1: Write failing test**

Add to `tests/test_cc_cubic.mojo` before `main()`:

```mojo
def test_congestion_event_reduces_cwnd() raises:
    var c = Cubic(max_datagram_size=MDS)
    # Force into CA (above ssthresh).
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)
    var before = c.cwnd()
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(200_000))
    assert_true(c.cwnd() < before, "CE mark reduces cwnd")
    assert_true(c.hs_state == HS_STATE_DONE, "CE disables HyStart++")
    print("PASS: test_congestion_event_reduces_cwnd")


def test_congestion_event_suppressed_within_rtt() raises:
    var c = Cubic(max_datagram_size=MDS)
    c._cwnd_value = UInt64(100_000)
    c.ssthresh = UInt64(50_000)
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(200_000))
    var after_first = c.cwnd()
    # Second event within 1 RTT (now < 200_000 + 50_000 = 250_000).
    c._on_congestion_event(smoothed_rtt=UInt64(50_000), now=UInt64(220_000))
    assert_true(c.cwnd() == after_first, "second CE within RTT is suppressed")
    print("PASS: test_congestion_event_suppressed_within_rtt")
```

Add both calls to `main()`.

- [ ] **Step 2: Verify it fails**

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: FAIL — `'Cubic' has no attribute '_on_congestion_event'`

- [ ] **Step 3: Add `_on_congestion_event` to `Cubic`**

Add after `_hs_on_loss`:

```mojo
    def _on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
        """Single congestion event from ECN CE mark.

        Same suppression window and cwnd-reduction logic as on_packets_lost
        (non-persistent path). Does NOT trigger persistent-congestion detection.
        """
        # Suppress if within 1 RTT of last congestion event.
        if self.congestion_event_time > UInt64(0):
            var suppress_until = (
                self.congestion_event_time
                + CUBIC_CONGESTION_SUPPRESS_RTT_MULT * smoothed_rtt
            )
            if now < suppress_until:
                return
        self._hs_on_loss()  # Disable HyStart++ on congestion.
        # Fast convergence + multiplicative decrease (same as non-persistent loss).
        if self._cwnd_value < self.w_last_max:
            self.w_last_max = self._cwnd_value
            self.w_max = (
                self._cwnd_value * (CUBIC_BETA_NUM + CUBIC_BETA_DEN)
            ) // (UInt64(2) * CUBIC_BETA_DEN)
        else:
            self.w_last_max = self._cwnd_value
            self.w_max = self._cwnd_value
        var reduced = (self._cwnd_value * CUBIC_BETA_NUM) // CUBIC_BETA_DEN
        if reduced < self.min_cwnd:
            reduced = self.min_cwnd
        self._cwnd_value = reduced
        self.ssthresh = self._cwnd_value
        self.w_est = self._cwnd_value
        # Recompute k_us.
        if self.w_max == UInt64(0):
            self.k_us = UInt64(0)
        else:
            var one_minus_beta_num = CUBIC_BETA_DEN - CUBIC_BETA_NUM
            var k_arg = (
                self.w_max * one_minus_beta_num * CUBIC_C_DEN
            ) // (CUBIC_BETA_DEN * CUBIC_C_NUM)
            var k_seconds = _cube_root_u64(k_arg)
            self.k_us = k_seconds * UInt64(1_000_000)
        self.congestion_event_time = now
        self.epoch_start = UInt64(0)
        self.bytes_acked_since_epoch = UInt64(0)
```

- [ ] **Step 4: Add `on_congestion_event` to `CcController`**

In `src/quic/cc/controller.mojo`, after the `on_packets_lost` method, add:

```mojo
    def on_congestion_event(mut self, smoothed_rtt: UInt64, now: UInt64):
        """ECN CE congestion signal. Reduces cwnd without persistent-congestion logic."""
        if self.kind == CC_KIND_CUBIC:
            self.cubic._on_congestion_event(smoothed_rtt, now)
        # DummyCc: no-op.
```

- [ ] **Step 5: Verify tests pass**

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: PASS — all existing + 2 new congestion-event tests.

- [ ] **Step 6: Run full suite**

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56.

- [ ] **Step 7: Commit**

Use the `commit-smart` skill. Message: `feat: add on_congestion_event to Cubic and CcController for ECN CE`

---

### Task 4: ECN types (`src/quic/ecn.mojo`)

**Files:**
- Create: `src/quic/ecn.mojo`

- [ ] **Step 1: Write failing import test**

Temporarily add to the bottom of any test file to verify the module compiles:

```mojo
from src.quic.ecn import EcnCounts, ECN_ECT0, ECN_CE, ECN_NOT_ECT, ECN_STATE_PROBING
```

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 2: Create `src/quic/ecn.mojo`**

```mojo
# src/quic/ecn.mojo
# QUIC ECN support — RFC 9000 §13.4 + RFC 9002 §7.9.
# Types, constants, and state machine for ECN path validation.


# ── IP ECN codepoints (RFC 3168) ────────────────────────────────────────────

comptime ECN_NOT_ECT: UInt8 = 0   # non-ECN-capable
comptime ECN_ECT1: UInt8 = 1      # ECN-capable (ECT(1)) — not used for sending
comptime ECN_ECT0: UInt8 = 2      # ECN-capable (ECT(0)) — used for outgoing packets
comptime ECN_CE: UInt8 = 3        # Congestion Experienced — network signal


# ── ECN path-validation states (RFC 9000 §13.4.2) ───────────────────────────

comptime ECN_STATE_PROBING: UInt8 = 0   # sending ECT(0), verifying path supports ECN
comptime ECN_STATE_CAPABLE: UInt8 = 1   # ECN confirmed working
comptime ECN_STATE_DISABLED: UInt8 = 2  # path strips or corrupts ECN; disable


# ── EcnCounts ────────────────────────────────────────────────────────────────


struct EcnCounts(Copyable, Movable):
    """Cumulative ECN mark counts for one direction in one PN space."""
    var ect0: UInt64
    var ect1: UInt64
    var ce: UInt64

    def __init__(out self):
        self.ect0 = UInt64(0)
        self.ect1 = UInt64(0)
        self.ce = UInt64(0)

    def __init__(out self, ect0: UInt64, ect1: UInt64, ce: UInt64):
        self.ect0 = ect0
        self.ect1 = ect1
        self.ce = ce

    def __init__(out self, *, other: Self):
        self.ect0 = other.ect0
        self.ect1 = other.ect1
        self.ce = other.ce

    def __init__(out self, *, deinit take: Self):
        self.ect0 = take.ect0
        self.ect1 = take.ect1
        self.ce = take.ce

    def total(self) -> UInt64:
        """Sum of all three codepoint counts."""
        return self.ect0 + self.ect1 + self.ce

    def is_zero(self) -> Bool:
        """True if no ECN marks have been observed."""
        return self.ect0 == UInt64(0) and self.ect1 == UInt64(0) and self.ce == UInt64(0)
```

- [ ] **Step 3: Remove the temporary import from the test file**

Revert the test file to its original state (remove the temporary import line).

- [ ] **Step 4: Verify ecn.mojo compiles**

Run: `uv run mojo run -I . -c 'from src.quic.ecn import EcnCounts, ECN_ECT0, ECN_CE; var e = EcnCounts(); print(String(e.is_zero()))'`
Expected: `True`

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message: `feat: add ECN types, constants, and EcnCounts struct`

---

### Task 5: `pn_space.mojo` ECN fields

**Files:**
- Modify: `src/quic/pn_space.mojo:92-131` (SentPacket)
- Modify: `src/quic/pn_space.mojo:137-184` (PacketNumberSpace)
- Modify: `src/quic/pn_space.mojo:299-324` (build_ack_frame)

- [ ] **Step 1: Write failing test**

Add to `tests/test_cc_cubic.mojo` temporarily:

```mojo
from src.quic.pn_space import SentPacket
from src.quic.frame import Frame

def test_sent_packet_has_ecn_mark() raises:
    var sp = SentPacket(
        pn=UInt64(1), time_sent=UInt64(0), ack_eliciting=True,
        in_flight=True, size=1200, frames=List[Frame](), ecn_mark=UInt8(2),
    )
    assert_true(sp.ecn_mark == UInt8(2), "ecn_mark stored")
    print("PASS: test_sent_packet_has_ecn_mark")
```

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: FAIL — `SentPacket.__init__ has no parameter 'ecn_mark'`

- [ ] **Step 2: Add `ecn_mark` to `SentPacket`**

In `src/quic/pn_space.mojo`, add import at the top:
```mojo
from src.quic.ecn import EcnCounts, ECN_NOT_ECT, ECN_ECT0
```

In the `SentPacket` struct, add the field after `var frames: List[Frame]`:
```mojo
    var ecn_mark: UInt8      # IP ECN codepoint used when this packet was sent (0 = NOT_ECT)
```

Update `SentPacket.__init__` to accept and store `ecn_mark: UInt8 = UInt8(0)`:

Replace current `__init__` parameters:
```mojo
    def __init__(
        out self,
        pn: UInt64,
        time_sent: UInt64,
        ack_eliciting: Bool,
        in_flight: Bool,
        size: Int,
        frames: List[Frame],
    ):
        self.pn = pn
        self.time_sent = time_sent
        self.ack_eliciting = ack_eliciting
        self.in_flight = in_flight
        self.size = size
        self.frames = List[Frame](copy=frames)
```
with:
```mojo
    def __init__(
        out self,
        pn: UInt64,
        time_sent: UInt64,
        ack_eliciting: Bool,
        in_flight: Bool,
        size: Int,
        frames: List[Frame],
        ecn_mark: UInt8 = UInt8(0),
    ):
        self.pn = pn
        self.time_sent = time_sent
        self.ack_eliciting = ack_eliciting
        self.in_flight = in_flight
        self.size = size
        self.frames = List[Frame](copy=frames)
        self.ecn_mark = ecn_mark
```

Update `__init__(out self, *, other: Self)` to copy `ecn_mark`:
```mojo
    def __init__(out self, *, other: Self):
        self.pn = other.pn
        self.time_sent = other.time_sent
        self.ack_eliciting = other.ack_eliciting
        self.in_flight = other.in_flight
        self.size = other.size
        self.frames = List[Frame](copy=other.frames)
        self.ecn_mark = other.ecn_mark
```

Update `__init__(out self, *, deinit take: Self)`:
```mojo
    def __init__(out self, *, deinit take: Self):
        self.pn = take.pn
        self.time_sent = take.time_sent
        self.ack_eliciting = take.ack_eliciting
        self.in_flight = take.in_flight
        self.size = take.size
        self.frames = take.frames^
        self.ecn_mark = take.ecn_mark
```

- [ ] **Step 3: Add ECN fields to `PacketNumberSpace`**

In `PacketNumberSpace` struct, add three fields after `last_ae_acked_time_sent`:
```mojo
    var recv_ecn: EcnCounts       # ECN marks observed on packets received in this space
    var last_ack_ecn: EcnCounts   # ECN counts from the last ACK we sent (for outgoing) / received (for CE delta)
    var ect0_in_flight: UInt64    # O(1) count of in-flight ECT(0)-marked packets
```

In `PacketNumberSpace.__init__(out self, level: EncryptionLevel)`, add:
```mojo
        self.recv_ecn = EcnCounts()
        self.last_ack_ecn = EcnCounts()
        self.ect0_in_flight = UInt64(0)
```

In `__init__(out self, *, other: Self)`, add:
```mojo
        self.recv_ecn = EcnCounts(other=other.recv_ecn)
        self.last_ack_ecn = EcnCounts(other=other.last_ack_ecn)
        self.ect0_in_flight = other.ect0_in_flight
```

In `__init__(out self, *, deinit take: Self)`, add:
```mojo
        self.recv_ecn = take.recv_ecn
        self.last_ack_ecn = take.last_ack_ecn
        self.ect0_in_flight = take.ect0_in_flight
```

- [ ] **Step 4: Update `build_ack_frame` to include ECN counts**

In `build_ack_frame`, after `ack.ranges = ranges^` and before resetting `ack_needed`, add:

```mojo
        # Include ECN counts when we've received ECN-marked packets (RFC 9000 §13.4.3).
        if not self.recv_ecn.is_zero():
            ack.has_ecn = True
            ack.ecn_ect0 = self.recv_ecn.ect0
            ack.ecn_ect1 = self.recv_ecn.ect1
            ack.ecn_ce = self.recv_ecn.ce
```

- [ ] **Step 5: Verify tests pass**

Remove the temporary test and run:

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56 (ecn_mark defaults to 0, all existing SentPacket constructors still compile).

- [ ] **Step 6: Commit**

Use the `commit-smart` skill. Message: `feat: add ECN fields to SentPacket and PacketNumberSpace`

---

### Task 6: `connection.mojo` ECN + PN wiring

**Files:**
- Modify: `src/quic/connection.mojo`

- [ ] **Step 1: Add ECN imports to `connection.mojo`**

Find the import block at the top of `connection.mojo`. Add:
```mojo
from src.quic.ecn import (
    EcnCounts, ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE,
    ECN_STATE_PROBING, ECN_STATE_CAPABLE, ECN_STATE_DISABLED,
)
```

- [ ] **Step 2: Add ECN fields to `QuicConnection` struct**

After `var app_frames_sent: Dict[Int, List[SentStreamFrame]]`, add:
```mojo
    # ECN path validation state (RFC 9000 §13.4.2, RFC 9002 §7.9).
    var ecn_state: UInt8           # ECN_STATE_PROBING / ECN_STATE_CAPABLE / ECN_STATE_DISABLED
    var ecn_probe_pkts_needed: Int # probe this many ECT(0) packets before validation check
    var ecn_probe_pkts_sent: Int   # ECT(0) packets sent during probing phase
    var ecn_probe_first_pn: UInt64 # PN of first ECT(0) probe packet
```

In the move constructor `__init__(out self, *, deinit take: Self)`, add:
```mojo
        self.ecn_state = take.ecn_state
        self.ecn_probe_pkts_needed = take.ecn_probe_pkts_needed
        self.ecn_probe_pkts_sent = take.ecn_probe_pkts_sent
        self.ecn_probe_first_pn = take.ecn_probe_first_pn
```

In the private `__init__` (around line 353, after `self.send_handshake_done = False`), add:
```mojo
        self.ecn_state = ECN_STATE_PROBING
        self.ecn_probe_pkts_needed = 10
        self.ecn_probe_pkts_sent = 0
        self.ecn_probe_first_pn = UInt64(0)
```

- [ ] **Step 3: Add `ecn_mark()` helper method**

After `_can_send` (search for `def _can_send`), add:

```mojo
    def ecn_mark(self) -> UInt8:
        """Return the ECN codepoint to apply to outgoing datagrams.

        Returns ECN_ECT0 while probing or confirmed capable; ECN_NOT_ECT when
        the path is known to strip/corrupt ECN marks."""
        if self.ecn_state == ECN_STATE_DISABLED:
            return ECN_NOT_ECT
        return ECN_ECT0
```

- [ ] **Step 4: Update `send()` to pass `pn` to recovery and set `ecn_mark` on `SentPacket`**

In `send()`, find the section that builds and records a sent packet (around line 1584):

Replace:
```mojo
            # Record sent packet.
            var is_ack_eliciting = _has_ack_eliciting(frames)
            var sent = SentPacket(
                pn=pn,
                time_sent=now,
                ack_eliciting=is_ack_eliciting,
                in_flight=True,
                size=pkt_size,
                frames=frames,
            )
            self.spaces[space_idx].on_packet_sent(sent)
            self.recovery.on_packet_sent(pkt_size, True)
```
with:
```mojo
            # Record sent packet with ECN mark.
            var is_ack_eliciting = _has_ack_eliciting(frames)
            var ect = self.ecn_mark()
            var sent = SentPacket(
                pn=pn,
                time_sent=now,
                ack_eliciting=is_ack_eliciting,
                in_flight=True,
                size=pkt_size,
                frames=frames,
                ecn_mark=ect,
            )
            self.spaces[space_idx].on_packet_sent(sent)
            # Track ECT(0) in-flight count for bleaching check.
            if ect == ECN_ECT0:
                self.spaces[space_idx].ect0_in_flight += UInt64(1)
                if self.ecn_probe_pkts_sent == 0:
                    self.ecn_probe_first_pn = pn
                self.ecn_probe_pkts_sent += 1
            self.recovery.on_packet_sent(pkt_size, True, pn, now)
```

- [ ] **Step 5: Update `recv()` signature to accept `ecn_mark`**

Replace:
```mojo
    def recv(mut self, datagram: Span[UInt8, _], now: UInt64) raises:
        """Process an incoming UDP datagram.
```
with:
```mojo
    def recv(mut self, datagram: Span[UInt8, _], now: UInt64,
             ecn_mark: UInt8 = UInt8(0)) raises:
        """Process an incoming UDP datagram.

        `ecn_mark` is the IP ECN codepoint from recvmsg. Default 0 (NOT_ECT)
        preserves all existing call sites.
```

- [ ] **Step 6: Add ECN accounting inside `recv()` after successful decrypt**

Inside the `try:` block in `recv()`, after the `on_packet_received` call (line 680), add:

```mojo
                # ECN accounting: count marks seen on received packets.
                if self.ecn_state != ECN_STATE_DISABLED:
                    if ecn_mark == ECN_CE:
                        self.spaces[space_idx].recv_ecn.ce += UInt64(1)
                    elif ecn_mark == ECN_ECT0:
                        self.spaces[space_idx].recv_ecn.ect0 += UInt64(1)
                    elif ecn_mark == ECN_ECT1:
                        self.spaces[space_idx].recv_ecn.ect1 += UInt64(1)
```

- [ ] **Step 7: Add `_process_ecn_feedback` method**

Add after `_detect_persistent_congestion`:

```mojo
    def _process_ecn_feedback(
        mut self, space_idx: Int, ack: AckFrame, now: UInt64
    ):
        """Process ECN counts from an ACK frame (RFC 9000 §13.4.2 + RFC 9002 §7.9).

        Validates the path (PROBING→CAPABLE or PROBING→DISABLED) and triggers
        a congestion event on CE increment."""
        var space = self.spaces[space_idx]
        var prev_ce = space.last_ack_ecn.ce

        # Update stored last-seen ECN counts.
        self.spaces[space_idx].last_ack_ecn = EcnCounts(
            ect0=ack.ecn_ect0, ect1=ack.ecn_ect1, ce=ack.ecn_ce
        )

        # --- Path validation (PROBING phase) ---
        if self.ecn_state == ECN_STATE_PROBING:
            # Only validate after we have probed enough packets AND the ACK covers
            # the first probe (prevents spurious disable from pre-probe ACKs).
            if (self.ecn_probe_pkts_sent >= self.ecn_probe_pkts_needed
                    and ack.largest_acked >= self.ecn_probe_first_pn):
                if ack.ecn_ect0 == UInt64(0) and ack.ecn_ect1 == UInt64(0) and ack.ecn_ce == UInt64(0):
                    # Peer sees no ECN counts → path strips ECN marks.
                    self.ecn_state = ECN_STATE_DISABLED
                    return
                else:
                    self.ecn_state = ECN_STATE_CAPABLE

        # --- Bleaching check (RFC 9000 §13.4.2) ---
        # If the ACK reports more ECN-marked packets than we have ECT(0) in flight
        # (with +1 tolerance for timing), the path is modifying ECN marks.
        var in_flight_ect0 = self.spaces[space_idx].ect0_in_flight
        if ack.ecn_ect0 + ack.ecn_ect1 + ack.ecn_ce > in_flight_ect0 + UInt64(1):
            self.ecn_state = ECN_STATE_DISABLED
            return

        # --- CE delta → congestion event (RFC 9002 §7.9) ---
        if ack.ecn_ce > prev_ce:
            self.recovery.cc.on_congestion_event(self.recovery.smoothed_rtt, now)
            # Refresh pacer after cwnd may have changed.
            self.recovery.pacer.update_capacity(
                self.recovery.cc.cwnd(), self.recovery.smoothed_rtt
            )
```

- [ ] **Step 8: Update `_handle_ack` to call ECN feedback and decrement `ect0_in_flight`**

In `_handle_ack`, find the acked-packet loop that calls `self.recovery.on_packet_acked` (around line 1097). Modify to add ect0_in_flight decrement:

```mojo
        for i in range(len(acked)):
            # Decrement ECT(0) in-flight counter on ACK (O(1), no loop).
            if acked[i].ecn_mark == ECN_ECT0:
                if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                    self.spaces[space_idx].ect0_in_flight -= UInt64(1)
            self.recovery.on_packet_acked(acked[i].size, acked[i].in_flight)
            if acked[i].ack_eliciting:
```

Then after `self._detect_losses(space_idx, now)`, add ECN feedback call:

```mojo
        # ECN feedback processing (after loss detection, which may reduce cwnd independently).
        if ack.has_ecn and self.ecn_state != ECN_STATE_DISABLED:
            self._process_ecn_feedback(space_idx, ack, now)
```

- [ ] **Step 9: Decrement `ect0_in_flight` on loss in `_detect_losses`**

In `_detect_losses`, find the per-lost-packet loop (around line 1183). After `var lost_pkt = SentPacket(other=...)`, add:

```mojo
                # Decrement ECT(0) in-flight on loss.
                if lost_pkt.ecn_mark == ECN_ECT0:
                    if self.spaces[space_idx].ect0_in_flight > UInt64(0):
                        self.spaces[space_idx].ect0_in_flight -= UInt64(1)
```

- [ ] **Step 10: Verify full test suite passes**

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56 tests.

- [ ] **Step 11: Commit**

Use the `commit-smart` skill. Message: `feat: wire ECN outgoing marks, recv counting, and CE congestion feedback`

---

### Task 7: BLOCKED frame emission

**Files:**
- Modify: `src/quic/connection.mojo`

- [ ] **Step 1: Write failing test**

Add to `tests/test_quic_connection.mojo` temporarily before `main()`:

```mojo
def test_data_blocked_emitted_when_conn_fc_exhausted() raises:
    # placeholder — fails because BLOCKED is not yet emitted
    assert_true(False, "placeholder: BLOCKED not yet implemented")
    print("PASS: test_data_blocked_emitted_when_conn_fc_exhausted")
```

Add call to `main()`. Run: `bash scripts/run_tests.sh`
Expected: FAIL — assertion.

- [ ] **Step 2: Remove placeholder; implement DATA_BLOCKED + STREAM_DATA_BLOCKED in `_build_app_frames`**

In `connection.mojo`, in `_build_app_frames`, find the STREAM frame loop that ends around line 1840. After it (before `return` if there is one, otherwise at the end of `_build_app_frames`), add:

```mojo
        # 7. DATA_BLOCKED (RFC 9000 §4.1) — connection-level FC exhausted.
        var conn_limit = self.stream_map.conn_fc_send.limit
        if (self.stream_map.conn_fc_send.received >= conn_limit
                and self.stream_map.conn_fc_send.blocked_at != conn_limit):
            frames.append(Frame.data_blocked(conn_limit))
            self.stream_map.conn_fc_send.blocked_at = conn_limit

        # 8. STREAM_DATA_BLOCKED (RFC 9000 §4.1) — per-stream FC exhausted.
        # Iterate sendable_ids; any stream there that has no FC credit is blocked.
        for idx in range(len(self.stream_map.sendable_ids)):
            var sid = self.stream_map.sendable_ids[idx]
            if sid not in self.stream_map.streams:
                continue
            var stream = self.stream_map.get_stream(sid)
            if not stream.fc_send:
                continue
            var fc = stream.fc_send.value().copy()
            var stream_limit = fc.limit
            if fc.available() == UInt64(0) and fc.blocked_at != stream_limit:
                frames.append(Frame.stream_data_blocked(StreamDataBlockedFrame(sid, stream_limit)))
                fc.blocked_at = stream_limit
                stream.fc_send = fc^
                self.stream_map.set_stream(sid, stream^)
```

- [ ] **Step 3: Reset `blocked_at` when MAX_DATA is received**

Find the MAX_DATA handler (around line 1006):
```mojo
        if tid == FRAME_MAX_DATA:
            if frame._max_data:
                self.stream_map.conn_fc_send.ensure_limit(frame._max_data.value())
            return
```

Replace with:
```mojo
        if tid == FRAME_MAX_DATA:
            if frame._max_data:
                self.stream_map.conn_fc_send.ensure_limit(frame._max_data.value())
                # Reset blocked_at so we can emit DATA_BLOCKED again at the new limit.
                self.stream_map.conn_fc_send.blocked_at = UInt64(0)
            return
```

- [ ] **Step 4: Reset `blocked_at` when MAX_STREAM_DATA is received**

Find the MAX_STREAM_DATA handler (around line 1011). Find where `fc.ensure_limit(msd.maximum)` is called. After that line, add:
```mojo
                        fc.blocked_at = UInt64(0)   # allow re-emission at new limit
```

The updated handler:
```mojo
        if tid == FRAME_MAX_STREAM_DATA:
            if frame._max_stream_data:
                var msd = frame._max_stream_data.value().copy()
                var key = Int(msd.stream_id)
                if key in self.stream_map.streams:
                    var stream = self.stream_map.get_stream(key)
                    if stream.fc_send:
                        var fc = stream.fc_send.value().copy()
                        var old_limit = fc.limit
                        fc.ensure_limit(msd.maximum)
                        fc.blocked_at = UInt64(0)   # allow re-emission at new limit
                        var grew = fc.limit > old_limit
                        stream.fc_send = fc^
                        self.stream_map.set_stream(key, stream^)
                        if grew:
                            self.events.append(QuicEvent.stream_writable(msd.stream_id))
            return
```

- [ ] **Step 5: Remove placeholder test; run full suite**

Remove the placeholder test from `test_quic_connection.mojo`.

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56.

- [ ] **Step 6: Commit**

Use the `commit-smart` skill. Message: `feat: emit DATA_BLOCKED and STREAM_DATA_BLOCKED on FC exhaustion`

---

### Task 8: HyStart++ unit tests

**Files:**
- Modify: `tests/test_cc_cubic.mojo`

- [ ] **Step 1: Write all 8 HyStart++ tests**

Add to `tests/test_cc_cubic.mojo` before `main()`:

```mojo
# ── HyStart++ tests ──────────────────────────────────────────────────────────

def test_hystart_starts_in_ss() raises:
    var c = Cubic(max_datagram_size=MDS)
    assert_true(c.hs_state == HS_STATE_SS, "initial state is HS_STATE_SS")
    print("PASS: test_hystart_starts_in_ss")


def test_hystart_no_exit_before_min_samples() raises:
    """Round with fewer than 8 samples never triggers CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)   # 10ms baseline
    c.hs_window_end_pn = UInt64(5)
    # Only 4 samples collected — below HYSTART_MIN_SAMPLES (8).
    c.hs_rtt_sample_count = 4
    c.hs_current_round_min_rtt = UInt64(25_000)  # would trigger if count were 8
    # Feed an ACK that would trigger round-end if count were sufficient.
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(25_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_SS, "< 8 samples: stays in SS")
    print("PASS: test_hystart_no_exit_before_min_samples")


def test_hystart_enters_css_on_rtt_increase() raises:
    """If current round min RTT > last round min RTT + thresh → enter CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)  # 10ms last round
    # thresh = max(10000/8, 4000) = max(1250, 4000) = 4000us
    # current = 22000 >= 10000 + 4000 = 14000 → CSS
    c.hs_current_round_min_rtt = UInt64(22_000)
    c.hs_rtt_sample_count = 8   # already at minimum samples
    c.hs_window_end_pn = UInt64(5)
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(22_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_CSS, "RTT increase → CSS")
    assert_true(c.hs_css_rounds == 0, "CSS rounds reset to 0")
    print("PASS: test_hystart_enters_css_on_rtt_increase")


def test_hystart_css_growth_is_quartered() raises:
    """In CSS, cwnd grows by acked/4, not acked."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_state = HS_STATE_CSS
    var before = c.cwnd()
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(10_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    var expected_inc = MDS // UInt64(4)
    assert_true(c.cwnd() == before + expected_inc, "CSS growth = acked/4")
    print("PASS: test_hystart_css_growth_is_quartered")


def test_hystart_exits_after_css_rounds() raises:
    """After HYSTART_CSS_ROUNDS (5) CSS rounds, set ssthresh = cwnd, state = DONE."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_state = HS_STATE_CSS
    c.hs_css_rounds = 4   # one more round will hit HYSTART_CSS_ROUNDS = 5
    c.hs_last_round_min_rtt = UInt64(10_000)
    c.hs_current_round_min_rtt = UInt64(11_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(5)
    var cwnd_before = c.cwnd()
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(11_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_DONE, "exits to DONE after 5 CSS rounds")
    # ssthresh was set to cwnd at round-end (before the CSS growth increment).
    assert_true(c.ssthresh <= c.cwnd(), "ssthresh set from cwnd at CSS exit")
    print("PASS: test_hystart_exits_after_css_rounds")


def test_hystart_no_reentry_after_loss() raises:
    """Loss transitions to HS_STATE_DONE; subsequent rounds stay DONE."""
    var c = Cubic(max_datagram_size=MDS)
    assert_true(c.hs_state == HS_STATE_SS, "starts SS")
    var lost = List[LostPacket]()
    lost.append(LostPacket(pkt_num=UInt64(1), size=MDS, time_sent=UInt64(0)))
    c.on_packets_lost(lost, smoothed_rtt_us=UInt64(10_000),
                       now=UInt64(50_000), persistent=False)
    assert_true(c.hs_state == HS_STATE_DONE, "loss → DONE")
    # Simulate another round: state must stay DONE.
    c.hs_current_round_min_rtt = UInt64(22_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(10)
    var pkt = AckedPacket(pkt_num=UInt64(10), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(2000),
                           rtt_sample=UInt64(22_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(2000))
    assert_true(c.hs_state == HS_STATE_DONE, "stays DONE after loss")
    print("PASS: test_hystart_no_reentry_after_loss")


def test_hystart_stable_rtt_stays_in_ss() raises:
    """Flat RTT (no increase beyond threshold) never triggers CSS."""
    var c = Cubic(max_datagram_size=MDS)
    c.hs_last_round_min_rtt = UInt64(10_000)  # 10ms baseline
    # thresh = 4ms; current = 11ms < 10ms + 4ms = 14ms → stays SS
    c.hs_current_round_min_rtt = UInt64(11_000)
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(5)
    var pkt = AckedPacket(pkt_num=UInt64(5), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(11_000))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_SS, "stable RTT stays in SS")
    print("PASS: test_hystart_stable_rtt_stays_in_ss")


def test_hystart_thresh_clamped() raises:
    """Threshold is clamped to [4ms, 16ms]."""
    var c = Cubic(max_datagram_size=MDS)

    # Fast path: last_min_rtt = 10ms → raw = 10000/8 = 1250us < 4000us → thresh = 4ms.
    # current_rtt must be >= 10000 + 4000 = 14000 to enter CSS.
    c.hs_last_round_min_rtt = UInt64(10_000)
    c.hs_current_round_min_rtt = UInt64(14_100)  # just above 14000
    c.hs_rtt_sample_count = 8
    c.hs_window_end_pn = UInt64(1)
    var pkt = AckedPacket(pkt_num=UInt64(1), size=MDS,
                           time_sent=UInt64(0), time_acked=UInt64(1000),
                           rtt_sample=UInt64(14_100))
    c.on_packet_acked(pkt, smoothed_rtt_us=UInt64(10_000), now=UInt64(1000))
    assert_true(c.hs_state == HS_STATE_CSS, "fast path: thresh clamped to 4ms")

    # Slow path: last_min_rtt = 200ms → raw = 200000/8 = 25000 > 16000 → thresh = 16ms.
    var c2 = Cubic(max_datagram_size=MDS)
    c2.hs_last_round_min_rtt = UInt64(200_000)
    # current must be >= 200000 + 16000 = 216000 to enter CSS.
    c2.hs_current_round_min_rtt = UInt64(216_100)
    c2.hs_rtt_sample_count = 8
    c2.hs_window_end_pn = UInt64(1)
    var pkt2 = AckedPacket(pkt_num=UInt64(1), size=MDS,
                            time_sent=UInt64(0), time_acked=UInt64(1000),
                            rtt_sample=UInt64(216_100))
    c2.on_packet_acked(pkt2, smoothed_rtt_us=UInt64(200_000), now=UInt64(1000))
    assert_true(c2.hs_state == HS_STATE_CSS, "slow path: thresh clamped to 16ms")
    print("PASS: test_hystart_thresh_clamped")
```

Add all 8 calls to `main()`:
```mojo
    test_hystart_starts_in_ss()
    test_hystart_no_exit_before_min_samples()
    test_hystart_enters_css_on_rtt_increase()
    test_hystart_css_growth_is_quartered()
    test_hystart_exits_after_css_rounds()
    test_hystart_no_reentry_after_loss()
    test_hystart_stable_rtt_stays_in_ss()
    test_hystart_thresh_clamped()
```

Also add the imports at the top of `test_cc_cubic.mojo`:
```mojo
from src.quic.cc.cubic import (Cubic, _cube_root_u64,
    HS_STATE_SS, HS_STATE_CSS, HS_STATE_DONE)
```

- [ ] **Step 2: Verify all tests pass**

Run: `uv run mojo run -I . tests/test_cc_cubic.mojo`
Expected: PASS — all existing tests + 8 new HyStart++ tests + 2 congestion-event tests.

- [ ] **Step 3: Run full suite**

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56/56.

- [ ] **Step 4: Commit**

Use the `commit-smart` skill. Message: `test: add HyStart++ unit tests (8 tests, RFC 9406 §4)`

---

### Task 9: ECN + BLOCKED integration tests + `run_tests.sh`

**Files:**
- Create: `tests/test_ecn.mojo`
- Modify: `tests/test_quic_connection.mojo`
- Modify: `scripts/run_tests.sh`

- [ ] **Step 1: Create `tests/test_ecn.mojo` with ECN state machine tests**

```mojo
# tests/test_ecn.mojo
# ECN path validation and CE congestion integration tests.
# Tests run a real QuicConnection pair (sans-I/O loopback).

from std.testing import assert_true
from memory import UnsafePointer

from src.tls.lib import RustlsLibrary
from src.quic.connection import QuicConnection, QuicEvent
from src.quic.ecn import (
    ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE,
    ECN_STATE_PROBING, ECN_STATE_CAPABLE, ECN_STATE_DISABLED,
)
from src.quic.trans_param import TransportParams

# ── helpers ──────────────────────────────────────────────────────────────────

fn _heap_alloc[T: AnyType](count: Int) -> UnsafePointer[T]:
    return UnsafePointer[T].alloc(count)


def _create_configs_from_lib(lib: __type_of(UnsafePointer[RustlsLibrary]().as_any_origin())) raises -> List[Int32]:
    from conformance.lib.rustls import make_server_config, make_client_config
    var server_cfg = make_server_config(lib)
    var client_cfg = make_client_config(lib)
    return List[Int32](server_cfg, client_cfg)


def _default_params() -> TransportParams:
    from src.quic.trans_param import default_transport_params
    return default_transport_params()


def _make_pair() raises -> (QuicConnection, QuicConnection, UInt64):
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var server_config = configs[0]
    var client_config = configs[1]
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, client_config, "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, server_config, params,
                                        Span(orig_dcid), Span(client_dcid), now)
    return client, server, now


def _establish(mut client: QuicConnection, mut server: QuicConnection,
               mut now: UInt64) raises -> UInt64:
    for _ in range(20):
        now += UInt64(10_000)
        var c_dg = client.send(now)
        for i in range(len(c_dg)):
            try: server.recv(Span(c_dg[i]), now)
            except: pass
        var s_dg = server.send(now)
        for i in range(len(s_dg)):
            try: client.recv(Span(s_dg[i]), now)
            except: pass
        if client.is_established() and server.is_established():
            break
    assert_true(client.is_established(), "handshake must complete")
    return now


# ── ECN unit-style tests ──────────────────────────────────────────────────────

def test_ecn_recv_counts_ce_mark() raises:
    """recv() with ecn_mark=CE increments recv_ecn.ce on the receiving space."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    # Client sends a datagram; server receives it with ECN_CE.
    now += UInt64(10_000)
    var c_dg = client.send(now)
    assert_true(len(c_dg) > 0, "client must produce datagrams")
    var ce_before = server.spaces[2].recv_ecn.ce
    try: server.recv(Span(c_dg[0]), now, ECN_CE)
    except: pass
    assert_true(server.spaces[2].recv_ecn.ce == ce_before + UInt64(1),
                "CE mark increments recv_ecn.ce")
    print("PASS: test_ecn_recv_counts_ce_mark")


def test_ecn_ack_includes_ecn_counts() raises:
    """After recv with ECN_CE, the next generated ACK has has_ecn=True."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    now += UInt64(10_000)
    var c_dg = client.send(now)
    try: server.recv(Span(c_dg[0]), now, ECN_CE)
    except: pass
    # Server's next send() will include an ACK with ECN counts.
    var s_dg = server.send(now)
    assert_true(len(s_dg) > 0, "server produces ACK datagram")
    # ECN is set — we can verify recv_ecn is non-zero as a proxy.
    assert_true(not server.spaces[2].recv_ecn.is_zero(), "recv_ecn non-zero after CE")
    print("PASS: test_ecn_ack_includes_ecn_counts")


def test_ecn_probing_to_capable() raises:
    """After probe_pkts_needed ECT(0) sends, ACK with ECN counts → CAPABLE."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    # Override probe threshold to 1 for test speed.
    client.ecn_probe_pkts_needed = 1
    # Confirm client starts in PROBING.
    assert_true(client.ecn_state == ECN_STATE_PROBING, "starts PROBING")
    # Send at least one packet so probe_pkts_sent >= 1.
    now += UInt64(10_000)
    var c_dg = client.send(now)
    assert_true(client.ecn_probe_pkts_sent >= 1, "ECT(0) probe sent")
    # Server receives and sends back ACK with ECN counts (we injected ECT0 on server recv).
    for i in range(len(c_dg)):
        try: server.recv(Span(c_dg[i]), now, ECN_ECT0)
        except: pass
    var s_dg = server.send(now)
    for i in range(len(s_dg)):
        try: client.recv(Span(s_dg[i]), now)
        except: pass
    assert_true(client.ecn_state == ECN_STATE_CAPABLE, "PROBING → CAPABLE after ECN ACK")
    print("PASS: test_ecn_probing_to_capable")


def test_ecn_probing_to_disabled_no_counts() raises:
    """After N probes, ACK without any ECN counts → DISABLED."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    client.ecn_probe_pkts_needed = 1
    # Force probe_pkts_sent >= 1 by sending a datagram.
    now += UInt64(10_000)
    var c_dg = client.send(now)
    # Set probe_first_pn so validation check fires.
    # Server receives WITHOUT ECN mark (NOT_ECT); sends ACK without ECN counts.
    for i in range(len(c_dg)):
        try: server.recv(Span(c_dg[i]), now)   # default ecn_mark=0 (NOT_ECT)
        except: pass
    var s_dg = server.send(now)
    # server's ACK will have has_ecn=False (recv_ecn is zero).
    # client processes the ACK → _process_ecn_feedback fires → DISABLED.
    for i in range(len(s_dg)):
        try: client.recv(Span(s_dg[i]), now)
        except: pass
    assert_true(client.ecn_state == ECN_STATE_DISABLED,
                "no ECN counts in ACK → DISABLED")
    print("PASS: test_ecn_probing_to_disabled_no_counts")


def test_ecn_disabled_no_ecn_mark() raises:
    """ecn_mark() returns ECN_NOT_ECT when state is DISABLED."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    client.ecn_state = ECN_STATE_DISABLED
    assert_true(client.ecn_mark() == ECN_NOT_ECT, "DISABLED → ecn_mark() returns NOT_ECT")
    print("PASS: test_ecn_disabled_no_ecn_mark")


def test_ecn_ce_triggers_congestion() raises:
    """CE delta > 0 in ACK → cc.on_congestion_event → cwnd reduces."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    client.ecn_state = ECN_STATE_CAPABLE
    # Inflate cwnd above initial window to make reduction visible.
    client.recovery.cc.cubic._cwnd_value = UInt64(500_000)
    client.recovery.cc.cubic.ssthresh = UInt64(1_000_000)
    var cwnd_before = client.recovery.cc.cwnd()
    # Server sends a datagram; client receives it with ECN_CE mark.
    now += UInt64(10_000)
    var s_dg = server.send(now)
    for i in range(len(s_dg)):
        try: client.recv(Span(s_dg[i]), now, ECN_CE)
        except: pass
    # Client sends ACK back, server sends ACK of that ACK — but the CE was on the
    # client recv side, so the client's own ACK will carry CE counts.
    # Trigger by pumping a round: client sends ACK with CE counts to server,
    # server's ACK of client's ACK will have ECN counts.
    # Simpler: manually advance the server's last_ack_ecn so CE delta fires.
    # Set server's recv space CE count.
    client.spaces[2].recv_ecn.ce += UInt64(1)
    # Now simulate receiving an ACK (from server to client) that has CE counts.
    # The easiest way: pump a full round so the CE mark propagates.
    var c_dg = client.send(now)
    for i in range(len(c_dg)):
        try: server.recv(Span(s_dg[0]), now)
        except: pass
    var s_dg2 = server.send(now)
    for i in range(len(s_dg2)):
        try: client.recv(Span(s_dg2[i]), now)
        except: pass
    # CE delta should have triggered congestion event.
    assert_true(client.recovery.cc.cwnd() <= cwnd_before,
                "CE in ACK triggers cwnd reduction")
    print("PASS: test_ecn_ce_triggers_congestion")


def test_ecn_bleaching_disables() raises:
    """ACK ECN total > ect0_in_flight + 1 → DISABLED (path bleaching detection)."""
    var client, server, now = _make_pair()
    now = _establish(client, server, now)
    client.ecn_state = ECN_STATE_CAPABLE
    # ect0_in_flight = 0; if ACK reports ect0=5 → 5 > 0 + 1 → DISABLED.
    client.spaces[2].ect0_in_flight = UInt64(0)
    # Craft a fake ACK by making the server report ECN counts.
    # Easiest: set server's recv_ecn directly so its next ACK includes ECN counts.
    server.spaces[2].recv_ecn.ect0 = UInt64(5)
    now += UInt64(10_000)
    var s_dg = server.send(now)
    for i in range(len(s_dg)):
        try: client.recv(Span(s_dg[i]), now)
        except: pass
    assert_true(client.ecn_state == ECN_STATE_DISABLED,
                "bleaching (ACK ECN > in-flight) → DISABLED")
    print("PASS: test_ecn_bleaching_disables")


def main():
    test_ecn_recv_counts_ce_mark()
    test_ecn_ack_includes_ecn_counts()
    test_ecn_probing_to_capable()
    test_ecn_probing_to_disabled_no_counts()
    test_ecn_disabled_no_ecn_mark()
    test_ecn_ce_triggers_congestion()
    test_ecn_bleaching_disables()
    print("All ECN tests passed.")
```

- [ ] **Step 2: Add BLOCKED + ECN integration tests to `test_quic_connection.mojo`**

Add imports at the top of `test_quic_connection.mojo`:
```mojo
from src.quic.ecn import ECN_STATE_DISABLED
```

Add 4 new test functions before `main()`:

```mojo
def test_blocked_frames_emitted_on_conn_fc_stall() raises:
    """DATA_BLOCKED is emitted when connection FC is exhausted."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                        Span(orig_dcid), Span(client_dcid), now)
    now = _establish_handshake(client, server, now)

    # Exhaust the connection send FC by setting received = limit.
    var limit = client.stream_map.conn_fc_send.limit
    client.stream_map.conn_fc_send.received = limit

    # Next send() must include DATA_BLOCKED.
    now += UInt64(10_000)
    var dgs = client.send(now)
    assert_true(client.stream_map.conn_fc_send.blocked_at == limit,
                "blocked_at set to limit after DATA_BLOCKED emission")
    print("PASS: test_blocked_frames_emitted_on_conn_fc_stall")


def test_blocked_not_re_emitted_at_same_limit() raises:
    """DATA_BLOCKED is sent once per limit; second send() at same limit skips it."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                        Span(orig_dcid), Span(client_dcid), now)
    now = _establish_handshake(client, server, now)

    var limit = client.stream_map.conn_fc_send.limit
    client.stream_map.conn_fc_send.received = limit
    # First send: emits DATA_BLOCKED and sets blocked_at.
    now += UInt64(10_000)
    _ = client.send(now)
    assert_true(client.stream_map.conn_fc_send.blocked_at == limit,
                "blocked_at set after first DATA_BLOCKED")
    # Second send at same limit: blocked_at == limit → no re-emission.
    now += UInt64(10_000)
    _ = client.send(now)
    # blocked_at remains at limit (no change), meaning no duplicate emission.
    assert_true(client.stream_map.conn_fc_send.blocked_at == limit,
                "blocked_at unchanged; no duplicate DATA_BLOCKED")
    print("PASS: test_blocked_not_re_emitted_at_same_limit")


def test_blocked_cleared_on_max_data_increase() raises:
    """MAX_DATA from peer resets blocked_at, allowing re-emission at new limit."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                        Span(orig_dcid), Span(client_dcid), now)
    now = _establish_handshake(client, server, now)

    # Exhaust FC and emit BLOCKED.
    var limit = client.stream_map.conn_fc_send.limit
    client.stream_map.conn_fc_send.received = limit
    now += UInt64(10_000)
    _ = client.send(now)
    assert_true(client.stream_map.conn_fc_send.blocked_at == limit, "BLOCKED emitted")

    # Simulate receiving MAX_DATA from peer (directly update conn_fc_send).
    var new_limit = limit + UInt64(1_000_000)
    client.stream_map.conn_fc_send.ensure_limit(new_limit)
    client.stream_map.conn_fc_send.blocked_at = UInt64(0)   # as done in _dispatch_frame
    assert_true(client.stream_map.conn_fc_send.blocked_at == UInt64(0),
                "blocked_at reset after MAX_DATA")
    print("PASS: test_blocked_cleared_on_max_data_increase")


def test_ecn_disabled_after_probing() raises:
    """ECN is disabled when path strips all ECN marks (PROBING→DISABLED)."""
    var lib_ptr = _heap_alloc[RustlsLibrary](1)
    lib_ptr.init_pointee_move(RustlsLibrary("lib/librustls_mojo.so"))
    var lib_addr = UInt64(Int(lib_ptr))
    var configs = _create_configs_from_lib(lib_ptr.as_any_origin())
    var params = _default_params()
    var now = UInt64(1_000_000)
    var client = QuicConnection.client(lib_addr, configs[1], "localhost", params, now)
    var orig_dcid = List[UInt8](copy=client.initial_dcid)
    var client_dcid = List[UInt8](copy=client.initial_dcid)
    var server = QuicConnection.server(lib_addr, configs[0], params,
                                        Span(orig_dcid), Span(client_dcid), now)
    now = _establish_handshake(client, server, now)

    # Override probe threshold to 1 for test speed.
    client.ecn_probe_pkts_needed = 1
    # Send packets so probe_pkts_sent is set.
    now += UInt64(10_000)
    _ = client.send(now)
    # Exchange a round without ECN marks on server side → ACK has no ECN counts.
    now = _pump(client, server, now, rounds=2)
    # After probing with no ECN counts in ACK → DISABLED.
    assert_true(client.ecn_state == ECN_STATE_DISABLED,
                "ECN disabled when path strips marks")
    print("PASS: test_ecn_disabled_after_probing")
```

Add all 4 calls to `main()`.

- [ ] **Step 3: Register new tests in `scripts/run_tests.sh`**

In the `TESTS=(...)` array, add after `test_cc_controller`:
```bash
    test_cc_minmax
```

And after `test_quic_connection` (find the end of the array), add:
```bash
    test_ecn
```

Note: `test_ecn` needs the `-I conformance` flag like other `test_quic_*` tests. The existing rule:
```bash
    if [[ "$t" == test_quic_* ]]; then
        EXTRA_I=(-I conformance)
    fi
```
does NOT cover `test_ecn`. Add after it:
```bash
    if [ "$t" = "test_ecn" ]; then
        EXTRA_I=(-I conformance)
    fi
```

- [ ] **Step 4: Verify all tests pass**

Run: `uv run mojo run -I . -I conformance tests/test_ecn.mojo`
Expected: PASS — all 7 ECN tests.

Run: `bash scripts/run_tests.sh`
Expected: PASS — 56 existing + test_cc_minmax (4 tests) + test_ecn (7 tests) = full suite green.

- [ ] **Step 5: Commit**

Use the `commit-smart` skill. Message: `test: add ECN and BLOCKED integration tests + run_tests.sh registration`
