"""`ProtectionConfig`, the H3 server's protection knobs, and the `ProtectionStats` counters its ingress guard fills.

Only the fields below are configurable; every other limit is a
`comptime` constant next to the mechanism it bounds.
"""

comptime DEFAULT_CONN_CAP: Int = 4096
comptime MIN_CONN_CAP: Int = 64
comptime MAX_CONN_CAP: Int = 1 << 24
"""16.7 M connections: far above any descriptor limit, low enough that sizing tables from it cannot wrap."""
comptime DEFAULT_MAX_QUEUE_DELAY_US: UInt64 = 5_000


struct ProtectionConfig(Copyable, Movable):
    """The protection limits a server takes as one defaulted keyword argument; `validate` rejects values that disable a protection."""

    var conn_cap: Int
    var max_queue_delay_us: UInt64
    """Under overload, how long a request may wait in line before the server starts refusing (503 with Retry-After).

    Lower means faster answers under load and more refusals; `0` turns the
    overload governor off. Keep handler run time about 10x below it.
    """

    def __init__(out self, *, conn_cap: Int = DEFAULT_CONN_CAP, max_queue_delay_us: UInt64 = DEFAULT_MAX_QUEUE_DELAY_US):
        self.conn_cap = conn_cap
        self.max_queue_delay_us = max_queue_delay_us

    def validate(self) raises:
        """Reject a `conn_cap` outside `[MIN_CONN_CAP, MAX_CONN_CAP]` and a non-zero `max_queue_delay_us` outside 1 ms .. 10 s."""
        if self.conn_cap < MIN_CONN_CAP or self.conn_cap > MAX_CONN_CAP:
            raise "ProtectionConfig: conn_cap must be in " + String(MIN_CONN_CAP) + ".." + String(MAX_CONN_CAP)
        var t = self.max_queue_delay_us
        if t != 0 and (t < 1_000 or t > 10_000_000):
            raise "ProtectionConfig: max_queue_delay_us must be 0 or in 1000..10000000"


struct ProtectionStats(Copyable, Movable):
    """Door counters of the H3 server: what its ingress guard dropped, answered statelessly or admitted."""

    # Ingress drops.
    var dropped_initial_size: UInt64
    var dropped_initial_dcid_len: UInt64
    var dropped_unknown_dcid: UInt64
    var dropped_undecodable: UInt64
    # Stateless responses.
    var retry_sent: UInt64
    var invalid_token_closes: UInt64
    var refused_closes: UInt64
    var stateless_dropped_egress: UInt64
    # Tokens.
    var tokens_none: UInt64
    var tokens_valid: UInt64
    var tokens_invalid: UInt64
    # Admission.
    var unvalidated_handshaking_peak: UInt64
    var cap_rejections: UInt64
    var dropped_overload: UInt64

    def __init__(out self):
        self.dropped_initial_size = 0
        self.dropped_initial_dcid_len = 0
        self.dropped_unknown_dcid = 0
        self.dropped_undecodable = 0
        self.retry_sent = 0
        self.invalid_token_closes = 0
        self.refused_closes = 0
        self.stateless_dropped_egress = 0
        self.tokens_none = 0
        self.tokens_valid = 0
        self.tokens_invalid = 0
        self.unvalidated_handshaking_peak = 0
        self.cap_rejections = 0
        self.dropped_overload = 0
