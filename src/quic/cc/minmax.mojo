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
        self.s0 = take.s0^
        self.s1 = take.s1^
        self.s2 = take.s2^

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
            # If new s0 is also expired, reset all to current measurement.
            if t >= self.s0.t + win:
                self.s0 = MinMaxSample(t=t, v=meas)
                self.s1 = MinMaxSample(t=t, v=meas)
                self.s2 = MinMaxSample(t=t, v=meas)
                return meas
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
