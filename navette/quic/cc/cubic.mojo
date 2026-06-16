# src/quic/cc/cubic.mojo
# CUBIC congestion controller per RFC 9438 with HyStart++ (RFC 9406).
# Implements the QUIC congestion-control core per RFC 9002.

from std.bit import bit_width

from navette.quic.cc.cc_trait import (
    AckedPacket,
    INITIAL_WINDOW_BYTES_CAP,
    LostPacket,
    UINT64_UNLIMITED,
)

# --- Module-scope constants (§4.3) ---

comptime CUBIC_BETA_NUM: UInt64 = 7         # beta = 0.7
comptime CUBIC_BETA_DEN: UInt64 = 10
comptime CUBIC_C_NUM: UInt64 = 4            # C = 0.4
comptime CUBIC_C_DEN: UInt64 = 10
# Congestion-event suppression: ignore losses during one RTT after an event.
comptime CUBIC_CONGESTION_SUPPRESS_RTT_MULT: UInt64 = 1
# Safety rail against UInt64 overflow in the cubic curve evaluation (§4.6).
comptime CUBIC_MAX_CWND: UInt64 = UInt64(1) << UInt64(30)  # 1 GiB
# (t-k)^3 is computed in us^3; dividing by 10^18 converts to s^3.
comptime CUBIC_SECONDS_CUBED_SCALE_U128: UInt128 = UInt128(1_000_000_000_000_000_000)

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


# --- Integer cube-root helper (§4.6) ---


def _cube_root_u64(x: UInt64) -> UInt64:
    """Integer cube root via Newton's method. Returns floor(x ** (1/3)).

    Used once per congestion event to recompute the cubic curve's k constant
    (RFC 9438 §4.5). Perf non-critical; correctness via post-hoc fix-up
    ensures floor-semantics even when Newton over/undershoots on small x.
    """
    if x == UInt64(0):
        return UInt64(0)
    if x < UInt64(8):
        return UInt64(1)
    # Initial guess: 2^ceil(bit_width(x) / 3) bounds the true cube root from above.
    var bw = UInt64(bit_width(x))
    var shift = (bw + UInt64(2)) // UInt64(3)
    var r: UInt64 = UInt64(1) << shift
    # Newton: r_new = (2*r + x // (r*r)) // 3. Converges quickly; cap iterations.
    for _ in range(40):
        if r == UInt64(0):
            break
        var rr = r * r
        if rr == UInt64(0):
            break
        var next_r = (UInt64(2) * r + x // rr) // UInt64(3)
        if next_r >= r:
            break
        r = next_r
    # Post-hoc fix-up guarantees floor semantics even after oscillation.
    while r > UInt64(0) and r * r * r > x:
        r -= UInt64(1)
    while (r + UInt64(1)) * (r + UInt64(1)) * (r + UInt64(1)) <= x:
        r += UInt64(1)
    return r


# --- Cubic struct (§4.2) ---


struct Cubic(ImplicitlyCopyable, Movable):
    """RFC 9438 CUBIC congestion controller with HyStart++ (RFC 9406)."""

    # --- Window state ---
    var _cwnd_value: UInt64            # Current congestion window (bytes)
    var ssthresh: UInt64               # Slow-start threshold; UINT64_UNLIMITED before first loss
    var w_max: UInt64                  # cwnd at last congestion event
    var w_last_max: UInt64             # Previous w_max (fast convergence; RFC 9438 §4.6)

    # --- Cubic curve state ---
    var k_us: UInt64                   # Time from epoch_start to reach w_max, microseconds
    var epoch_start: UInt64            # us, 0 before first CA epoch starts
    var congestion_event_time: UInt64  # us, time of most-recent congestion event (for suppression)
    var bytes_acked_since_epoch: UInt64

    # --- Reno-friendly region (RFC 9438 §4.2) ---
    var w_est: UInt64                  # AIMD-equivalent window tracked in parallel

    # --- Config ---
    var max_datagram_size: UInt64
    var min_cwnd: UInt64               # 2 * max_datagram_size
    var initial_window: UInt64         # min(10*MDS, 14720) per RFC 9002 §7.2

    # --- HyStart++ state (RFC 9406). Active only during slow start. ---
    var hs_state: UInt8               # HS_STATE_SS / HS_STATE_CSS / HS_STATE_DONE
    var hs_window_end_pn: UInt64      # PN marking end of current round
    var hs_current_round_min_rtt: UInt64  # minimum RTT sample in current round
    var hs_last_round_min_rtt: UInt64    # minimum RTT from the previous round
    var hs_rtt_sample_count: Int      # RTT samples collected this round
    var hs_css_rounds: Int            # number of CSS rounds elapsed

    def __init__(out self, max_datagram_size: UInt64):
        """Construct at RFC 9002 §7.2 initial window; slow-start (ssthresh unlimited)."""
        self.max_datagram_size = max_datagram_size
        self.min_cwnd = UInt64(2) * max_datagram_size
        var iw = UInt64(10) * max_datagram_size
        if iw > INITIAL_WINDOW_BYTES_CAP:
            iw = INITIAL_WINDOW_BYTES_CAP
        self.initial_window = iw
        self._cwnd_value = iw
        self.ssthresh = UINT64_UNLIMITED
        self.w_max = UInt64(0)
        self.w_last_max = UInt64(0)
        self.k_us = UInt64(0)
        self.epoch_start = UInt64(0)
        self.congestion_event_time = UInt64(0)
        self.bytes_acked_since_epoch = UInt64(0)
        self.w_est = UInt64(0)
        self.hs_state = HS_STATE_SS
        self.hs_window_end_pn = UInt64(0)
        self.hs_current_round_min_rtt = UINT64_UNLIMITED
        self.hs_last_round_min_rtt = UINT64_UNLIMITED
        self.hs_rtt_sample_count = 0
        self.hs_css_rounds = 0

    # --- Trait methods (§3.3) ---

    def cwnd(self) -> UInt64:
        """Current congestion window, in bytes."""
        return self._cwnd_value

    def pacing_rate(self, smoothed_rtt_us: UInt64) -> UInt64:
        """Bytes/sec. Slow-start gain 2.0; steady state 1.25. Never divide by zero."""
        var srtt = smoothed_rtt_us if smoothed_rtt_us > UInt64(0) else UInt64(1)
        if self._cwnd_value < self.ssthresh:
            return (UInt64(2) * self._cwnd_value * UInt64(1_000_000)) // srtt
        return (UInt64(5) * self._cwnd_value * UInt64(1_000_000)) // (UInt64(4) * srtt)

    def on_packet_sent(mut self, size: UInt64, pn: UInt64, now: UInt64):
        """Track round boundary for HyStart++. CUBIC does not mutate cwnd on send."""
        # In both SS and CSS, track the latest sent PN as the round-end marker.
        if self.hs_state == HS_STATE_SS or self.hs_state == HS_STATE_CSS:
            self.hs_window_end_pn = pn

    def on_packet_acked(
        mut self,
        packet: AckedPacket,
        smoothed_rtt_us: UInt64,
        now: UInt64,
    ):
        """Slow-start or congestion-avoidance update per RFC 9438 + HyStart++ (RFC 9406)."""
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

        # Congestion avoidance path.
        if self.epoch_start == UInt64(0):
            # First ACK in a new CA epoch: reset epoch markers. k_us was
            # recomputed in the previous congestion event (or is 0 on cold start).
            self.epoch_start = now
            self.bytes_acked_since_epoch = UInt64(0)
            if self.w_est == UInt64(0):
                self.w_est = self._cwnd_value

        # Compute w_cubic(t) = C * ((t - k) / 1e6)^3 + w_max, all UInt128 for headroom.
        var t: UInt64
        if now >= self.epoch_start:
            t = now - self.epoch_start
        else:
            t = UInt64(0)

        var diff_us: UInt128
        var below_inflection: Bool
        if t >= self.k_us:
            diff_us = UInt128(t - self.k_us)
            below_inflection = False
        else:
            diff_us = UInt128(self.k_us - t)
            below_inflection = True
        var cube_us = diff_us * diff_us * diff_us  # us^3
        var w_cubic_delta_u128 = (UInt128(CUBIC_C_NUM) * cube_us) // (
            UInt128(CUBIC_C_DEN) * CUBIC_SECONDS_CUBED_SCALE_U128
        )
        # Cap delta at CUBIC_MAX_CWND before UInt64 conversion to avoid truncation surprises.
        var delta_cap = UInt128(CUBIC_MAX_CWND)
        if w_cubic_delta_u128 > delta_cap:
            w_cubic_delta_u128 = delta_cap
        var w_cubic_delta = UInt64(w_cubic_delta_u128)

        var w_cubic: UInt64
        if below_inflection:
            # Below the inflection point the curve is under w_max.
            if self.w_max > w_cubic_delta:
                w_cubic = self.w_max - w_cubic_delta
            else:
                w_cubic = self.min_cwnd
        else:
            w_cubic = self.w_max + w_cubic_delta

        # Safety rails.
        if w_cubic > CUBIC_MAX_CWND:
            w_cubic = CUBIC_MAX_CWND
        if w_cubic < self.min_cwnd:
            w_cubic = self.min_cwnd

        # Reno-friendly AIMD update of w_est per RFC 9438.
        if self.w_est == UInt64(0):
            self.w_est = self._cwnd_value
        if self.w_est > UInt64(0):
            var w_est_inc = (
                CUBIC_BETA_NUM * self.max_datagram_size * packet.size
            ) // (CUBIC_BETA_DEN * self.w_est)
            self.w_est += w_est_inc

        # target = max(w_cubic, w_est).
        var target = w_cubic
        if self.w_est > target:
            target = self.w_est

        # cwnd += MDS * (target - cwnd) / cwnd per ACK. Careful with UInt underflow.
        if target > self._cwnd_value and self._cwnd_value > UInt64(0):
            var incr = (self.max_datagram_size * (target - self._cwnd_value)) // self._cwnd_value
            self._cwnd_value += incr
            if self._cwnd_value > CUBIC_MAX_CWND:
                self._cwnd_value = CUBIC_MAX_CWND
        # If target <= cwnd, don't shrink; w_est will catch up next ACK.

        self.bytes_acked_since_epoch += packet.size

    def on_packets_lost(
        mut self,
        lost: List[LostPacket],
        smoothed_rtt_us: UInt64,
        now: UInt64,
        persistent: Bool,
    ):
        """Reduce cwnd on congestion event. Persistent congestion resets to min."""
        if persistent:
            # RFC 9002 §7.6.2: persistent congestion → back to minimum window.
            self._cwnd_value = self.min_cwnd
            self.ssthresh = self._cwnd_value
            self.w_max = UInt64(0)
            self.w_last_max = UInt64(0)
            self.w_est = self._cwnd_value
            self.epoch_start = UInt64(0)
            self.congestion_event_time = now
            self.k_us = UInt64(0)
            return

        # Suppression: collapse multi-packet loss bursts within one RTT into a single event.
        # Only suppress if there has been a prior congestion event (congestion_event_time > 0).
        if self.congestion_event_time > UInt64(0):
            var suppress_until = (
                self.congestion_event_time
                + CUBIC_CONGESTION_SUPPRESS_RTT_MULT * smoothed_rtt_us
            )
            if now < suppress_until:
                return

        self._hs_on_loss()  # Disable HyStart++ AFTER suppression guard.

        # Fast convergence (RFC 9438 §4.6): when cwnd < w_last_max, bias w_max low.
        if self._cwnd_value < self.w_last_max:
            self.w_last_max = self._cwnd_value
            # w_max = cwnd * (1 + beta) / 2
            # With beta = CUBIC_BETA_NUM/CUBIC_BETA_DEN (= 0.7):
            #   (1 + 0.7) / 2 = 0.85 = 17/20
            # Compute as cwnd * (CUBIC_BETA_NUM + CUBIC_BETA_DEN) / (2 * CUBIC_BETA_DEN).
            self.w_max = (
                self._cwnd_value * (CUBIC_BETA_NUM + CUBIC_BETA_DEN)
            ) // (UInt64(2) * CUBIC_BETA_DEN)
        else:
            self.w_last_max = self._cwnd_value
            self.w_max = self._cwnd_value

        # Multiplicative decrease.
        var reduced = (self._cwnd_value * CUBIC_BETA_NUM) // CUBIC_BETA_DEN
        if reduced < self.min_cwnd:
            reduced = self.min_cwnd
        self._cwnd_value = reduced
        self.ssthresh = self._cwnd_value
        self.w_est = self._cwnd_value

        # Recompute k_us = cube_root(w_max * (1 - beta) / C), in seconds → µs.
        # Rearranged for UInt64 integer math:
        #   k_seconds = cube_root(w_max * (CUBIC_BETA_DEN - CUBIC_BETA_NUM) / CUBIC_BETA_DEN
        #                         * CUBIC_C_DEN / CUBIC_C_NUM)
        if self.w_max == UInt64(0):
            self.k_us = UInt64(0)
        else:
            var one_minus_beta_num = CUBIC_BETA_DEN - CUBIC_BETA_NUM
            # k_arg is in "bytes" since w_max is in bytes; cube-root yields bytes^(1/3),
            # which RFC 9438 then interprets as seconds once scaled by C. We convert to µs.
            var k_arg = (
                self.w_max * one_minus_beta_num * CUBIC_C_DEN
            ) // (CUBIC_BETA_DEN * CUBIC_C_NUM)
            var k_seconds = _cube_root_u64(k_arg)
            self.k_us = k_seconds * UInt64(1_000_000)

        self.congestion_event_time = now
        # epoch_start reset; next CA ACK starts a fresh epoch.
        self.epoch_start = UInt64(0)
        self.bytes_acked_since_epoch = UInt64(0)

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

    def _hs_on_loss(mut self):
        """Disable HyStart++ when a loss or congestion event occurs."""
        self.hs_state = HS_STATE_DONE

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
        self._hs_on_loss()  # Disable HyStart++ on congestion (after suppression guard).
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

    def name(self) -> String:
        """Human-readable name for logging / qlog."""
        return String("cubic")
