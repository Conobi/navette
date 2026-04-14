# src/quic/flow_control.mojo
# QUIC flow control tracker — RFC 9000 §4.
# Used at both connection and per-stream levels.
# Two-counter design: `received` for enforcement, `consumed` for window updates.


struct FlowControl(Copyable, Movable):
    """Dual-counter flow control state for a QUIC connection or stream.

    - `received`:   total bytes received/sent on wire (enforcement via check_limit).
    - `consumed`:   total bytes consumed by app or accounted via RESET (window updates).
    - `limit`:      current limit advertised to/by peer.
    - `window`:     static window size (M3c).
    - `blocked_at`: limit at which we last sent BLOCKED (0 = not blocked).
    """

    var received: UInt64
    var consumed: UInt64
    var limit: UInt64
    var window: UInt64
    var blocked_at: UInt64

    def __init__(out self, limit: UInt64, window: UInt64):
        self.received = UInt64(0)
        self.consumed = UInt64(0)
        self.limit = limit
        self.window = window
        self.blocked_at = UInt64(0)

    def __init__(out self, *, other: Self):
        self.received = other.received
        self.consumed = other.consumed
        self.limit = other.limit
        self.window = other.window
        self.blocked_at = other.blocked_at

    def __init__(out self, *, deinit take: Self):
        self.received = take.received
        self.consumed = take.consumed
        self.limit = take.limit
        self.window = take.window
        self.blocked_at = take.blocked_at

    def should_update(self) -> Bool:
        """True when remaining credit (limit - consumed) < window/2."""
        return (self.limit - self.consumed) < (self.window // 2)

    def next_limit(self) -> UInt64:
        """Compute what the new limit would be after a window update."""
        return self.consumed + self.window

    def update_limit(mut self) -> UInt64:
        """Advance limit to next_limit() and return the new value."""
        self.limit = self.next_limit()
        return self.limit

    def add_received(mut self, bytes: UInt64):
        """Account for bytes received/sent on the wire."""
        self.received += bytes

    def add_consumed(mut self, bytes: UInt64):
        """Account for bytes consumed by the application."""
        self.consumed += bytes

    def check_limit(self, new_bytes: UInt64) -> Bool:
        """Return True if receiving new_bytes stays within the current limit."""
        return self.received + new_bytes <= self.limit

    def available(self) -> UInt64:
        """Remaining credit under the current limit (saturates at 0)."""
        if self.limit > self.received:
            return self.limit - self.received
        return UInt64(0)

    def ensure_limit(mut self, new_limit: UInt64):
        """Monotonically raise the limit; never lower it."""
        if new_limit > self.limit:
            self.limit = new_limit
