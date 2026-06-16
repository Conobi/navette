# src/quic/cc/pacing.mojo
# Token-bucket pacer — TQUIC-style, mirrors TQUIC src/congestion_control/pacing.rs.
# Implements the QUIC congestion-control core per RFC 9002.

# --- Module-scope constants ---

comptime PACER_MIN_BURST_PACKETS: UInt64 = 10
comptime PACER_MAX_BURST_PACKETS: UInt64 = 128
comptime PACER_DEFAULT_GRANULARITY_US: UInt64 = 1000   # 1 ms; distinct from K_GRANULARITY in recovery.mojo


# --- Pacer struct (§6.1) ---

struct Pacer(ImplicitlyCopyable, Movable):
    """Token-bucket pacer.

    All time values are in microseconds (us).
    Rate values are in bytes per second (bps).
    """

    var enabled: Bool
    var capacity: UInt64          # max bytes burstable per granularity tick
    var tokens: UInt64            # current token count (bytes)
    var last_cwnd: UInt64         # last cwnd seen (informational)
    var last_sched_time: UInt64   # us; 0 before first call
    var pacer_granularity_us: UInt64
    var max_datagram_size: UInt64

    # --- Factory (§6.3) ---

    @staticmethod
    def new(max_datagram_size: UInt64) -> Pacer:
        """Create a new Pacer with default settings."""
        var p = Pacer(
            enabled=True,
            capacity=PACER_MIN_BURST_PACKETS * max_datagram_size,
            tokens=UInt64(0),
            last_cwnd=UInt64(0),
            last_sched_time=UInt64(0),
            pacer_granularity_us=PACER_DEFAULT_GRANULARITY_US,
            max_datagram_size=max_datagram_size,
        )
        return p

    def __init__(
        out self,
        enabled: Bool,
        capacity: UInt64,
        tokens: UInt64,
        last_cwnd: UInt64,
        last_sched_time: UInt64,
        pacer_granularity_us: UInt64,
        max_datagram_size: UInt64,
    ):
        self.enabled = enabled
        self.capacity = capacity
        self.tokens = tokens
        self.last_cwnd = last_cwnd
        self.last_sched_time = last_sched_time
        self.pacer_granularity_us = pacer_granularity_us
        self.max_datagram_size = max_datagram_size

    # --- Pure method (§6.3): projects refill without mutating state ---

    def next_send_time(self, pacing_rate_bps: UInt64, now: UInt64) -> Optional[UInt64]:
        """Return the earliest time a packet may be sent, or None if unpaced.

        PURE — does NOT mutate self. Callers may call freely to query schedule.
        Returns None if disabled, rate==0, or tokens already cover one MDS.
        Returns Some(deadline_us) if a wait is needed.
        """
        if not self.enabled or pacing_rate_bps == UInt64(0):
            return Optional[UInt64](None)

        # Compute projected tokens after refill (without mutating state).
        var elapsed: UInt64
        if now >= self.last_sched_time:
            elapsed = now - self.last_sched_time
        else:
            elapsed = UInt64(0)
        var refill = (pacing_rate_bps * elapsed) // UInt64(1_000_000)
        var tokens_projected = self.tokens + refill
        if tokens_projected > self.capacity:
            tokens_projected = self.capacity

        if tokens_projected >= self.max_datagram_size:
            return Optional[UInt64](None)

        # Compute wait time (ceiling division).
        var deficit = self.max_datagram_size - tokens_projected
        var wait_us = (deficit * UInt64(1_000_000) + pacing_rate_bps - UInt64(1)) // pacing_rate_bps
        return Optional[UInt64](now + wait_us)

    # --- Mutating method (§6.3): refill tokens, update last_sched_time ---

    def refill_and_check(mut self, pacing_rate_bps: UInt64, now: UInt64) -> Bool:
        """Refill token bucket and return True if a packet may be sent now.

        MUTATING — updates self.tokens and self.last_sched_time.
        Returns True if unpaced (disabled or rate==0) or if tokens >= MDS.
        """
        if not self.enabled or pacing_rate_bps == UInt64(0):
            return True

        var elapsed: UInt64
        if now >= self.last_sched_time:
            elapsed = now - self.last_sched_time
        else:
            elapsed = UInt64(0)
        var refill = (pacing_rate_bps * elapsed) // UInt64(1_000_000)
        var tokens_projected = self.tokens + refill
        if tokens_projected > self.capacity:
            tokens_projected = self.capacity

        self.tokens = tokens_projected
        self.last_sched_time = now
        return self.tokens >= self.max_datagram_size

    # --- Token consumption (§6.3) ---

    def on_sent(mut self, bytes: UInt64):
        """Saturating subtract: consume bytes from token bucket, floor at 0."""
        if bytes >= self.tokens:
            self.tokens = UInt64(0)
        else:
            self.tokens -= bytes

    # --- Capacity update (§6.3 + §6.4) ---

    def update_capacity(mut self, cwnd: UInt64, smoothed_rtt_us: UInt64):
        """Recompute burst capacity from current cwnd and smoothed RTT.

        capacity = (cwnd * pacer_granularity_us) / max(srtt, 1)
        Clamped to [PACER_MIN_BURST_PACKETS * MDS, PACER_MAX_BURST_PACKETS * MDS].
        Trims tokens to new capacity if needed.
        """
        var srtt = smoothed_rtt_us if smoothed_rtt_us > UInt64(0) else UInt64(1)
        var raw_capacity = (cwnd * self.pacer_granularity_us) // srtt

        var min_cap = PACER_MIN_BURST_PACKETS * self.max_datagram_size
        var max_cap = PACER_MAX_BURST_PACKETS * self.max_datagram_size

        var new_capacity: UInt64
        if raw_capacity < min_cap:
            new_capacity = min_cap
        elif raw_capacity > max_cap:
            new_capacity = max_cap
        else:
            new_capacity = raw_capacity

        self.capacity = new_capacity
        self.last_cwnd = cwnd

        # Trim tokens to new capacity.
        if self.tokens > self.capacity:
            self.tokens = self.capacity
