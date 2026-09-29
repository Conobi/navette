"""`ProtectionConfig`, the protection knob set, and the `ProtectionStats` counters.

Both are plain data: no server accepts or fills them yet. Only the
fields below are meant to be configurable; every other limit is a
`comptime` constant next to the mechanism it bounds. `fd_budget` and
`mem_budget` are designed to be process-wide, one of each shared as the
same `ArcPointer` by every server of the process.
"""

from std.collections import Optional
from std.memory import ArcPointer

from navette.protect.descriptor_budget import (
    DescriptorBudget,
    MIN_CONN_CAP,
    MAX_CONN_CAP,
    MAX_CLOSING_CAP,
    default_closing_cap,
)
from navette.protect.memory_budget import MemoryBudget
from navette.protect.source_key import DEFAULT_IPV6_SOURCE_PREFIX

comptime DEFAULT_CONN_CAP: Int = 4096
comptime DEFAULT_HEADER_TIMEOUT_S: Int = 10
comptime DEFAULT_BODY_READ_TIMEOUT_S: Int = 30
comptime DEFAULT_REQUEST_WALL_S: Int = 60
comptime DEFAULT_SEND_TIMEOUT_S: Int = 30
comptime MAX_TIMEOUT_S: Int = 86_400
"""Upper bound on every timeout knob (one day): seconds are scaled to microseconds, so an unbounded value would wrap."""


struct ProtectionConfig(Copyable, Movable):
    """The protection limits a server will take as one defaulted keyword argument; `validate` rejects values that disable a protection."""

    var conn_cap: Int
    var closing_cap: Optional[Int]
    var header_timeout_s: Int
    var body_read_timeout_s: Int
    var request_wall_s: Int
    var send_timeout_s: Int
    var ipv6_source_prefix: Int
    var fd_budget: Optional[ArcPointer[DescriptorBudget]]
    var mem_budget: Optional[ArcPointer[MemoryBudget]]

    def __init__(
        out self,
        *,
        conn_cap: Int = DEFAULT_CONN_CAP,
        closing_cap: Optional[Int] = None,
        header_timeout_s: Int = DEFAULT_HEADER_TIMEOUT_S,
        body_read_timeout_s: Int = DEFAULT_BODY_READ_TIMEOUT_S,
        request_wall_s: Int = DEFAULT_REQUEST_WALL_S,
        send_timeout_s: Int = DEFAULT_SEND_TIMEOUT_S,
        ipv6_source_prefix: Int = DEFAULT_IPV6_SOURCE_PREFIX,
        fd_budget: Optional[ArcPointer[DescriptorBudget]] = None,
        mem_budget: Optional[ArcPointer[MemoryBudget]] = None,
    ):
        self.conn_cap = conn_cap
        self.closing_cap = closing_cap
        self.header_timeout_s = header_timeout_s
        self.body_read_timeout_s = body_read_timeout_s
        self.request_wall_s = request_wall_s
        self.send_timeout_s = send_timeout_s
        self.ipv6_source_prefix = ipv6_source_prefix
        self.fd_budget = fd_budget
        self.mem_budget = mem_budget

    def validate(self) raises:
        """Reject values that would disable a protection or overflow table sizing: `conn_cap` outside `[64, MAX_CONN_CAP]`, an explicit `closing_cap` outside `[1, MAX_CLOSING_CAP]`, timeouts outside `[1, MAX_TIMEOUT_S]`, prefixes outside 1..128."""
        if self.conn_cap < MIN_CONN_CAP or self.conn_cap > MAX_CONN_CAP:
            raise "ProtectionConfig: conn_cap must be in " + String(MIN_CONN_CAP) + ".." + String(MAX_CONN_CAP)
        if self.closing_cap and (self.closing_cap.value() < 1 or self.closing_cap.value() > MAX_CLOSING_CAP):
            raise "ProtectionConfig: closing_cap must be in 1.." + String(MAX_CLOSING_CAP)
        for t in [self.header_timeout_s, self.body_read_timeout_s, self.request_wall_s, self.send_timeout_s]:
            if t < 1 or t > MAX_TIMEOUT_S:
                raise "ProtectionConfig: every timeout must be in 1.." + String(MAX_TIMEOUT_S) + " s"
        if self.ipv6_source_prefix < 1 or self.ipv6_source_prefix > 128:
            raise "ProtectionConfig: ipv6_source_prefix must be in 1..128"

    def effective_closing_cap(self) -> Int:
        """The explicit `closing_cap`, else `default_closing_cap(conn_cap)` (a quarter of it); pass this one value to both `register_tcp` and `ConnPool`."""
        if self.closing_cap:
            return self.closing_cap.value()
        return default_closing_cap(self.conn_cap)


struct ProtectionStats(Copyable, Movable):
    """Plain protection counters, all zero until a server is wired to fill the ones its protocol has."""

    # Ingress drops.
    var dropped_initial_size: UInt64
    var dropped_initial_dcid_len: UInt64
    var dropped_unknown_dcid: UInt64
    var dropped_undecodable: UInt64
    var dropped_truncated: UInt64
    var dropped_vn_small: UInt64
    # Stateless responses.
    var retry_sent: UInt64
    var invalid_token_closes: UInt64
    var refused_closes: UInt64
    var vn_sent: UInt64
    var stateless_bucket_empty_close: UInt64
    var stateless_bucket_empty_vn: UInt64
    var stateless_dropped_egress: UInt64
    # Tokens.
    var tokens_none: UInt64
    var tokens_valid: UInt64
    var tokens_invalid: UInt64
    # Handshakes and sources.
    var handshaking_peak: UInt64
    var unvalidated_handshaking_peak: UInt64
    var unvalidated_evictions: UInt64
    var admitted_by_largest_source: UInt64
    var sources_active: UInt64
    # Connections.
    var fair_share_evictions: UInt64
    var graceful_drains: UInt64
    var memory_evictions: UInt64
    var cap_rejections: UInt64
    var closing_forced: UInt64
    var closing_refused: UInt64  # copied from the `ConnPool` counter of the same name
    var busy_victims_killed: UInt64  # likewise
    var accept_fd_exhausted: UInt64
    # Dispatch.
    var passes: UInt64
    var dispatch_passes: UInt64
    var dispatches: UInt64
    var handler_calls: UInt64
    # Timeouts.
    var timeouts_first_request: UInt64
    var timeouts_header: UInt64
    var timeouts_body: UInt64
    var timeouts_wall: UInt64
    var timeouts_send: UInt64
    var timeouts_idle: UInt64
    # H1 responses.
    var bad_request_400: UInt64
    var internal_500: UInt64
    var rejections_503: UInt64
    # H2.
    var refused_streams: UInt64
    var ignored_frames_locally_closed: UInt64
    var window_credited_back_bytes: UInt64
    var enhance_your_calm_peer_reset: UInt64
    var enhance_your_calm_induced: UInt64
    var enhance_your_calm_continuation: UInt64
    var enhance_your_calm_overhead: UInt64
    var enhance_your_calm_control_queue: UInt64
    var enhance_your_calm_send: UInt64
    var refused_lifetime_closes: UInt64
    var purged_before_dispatch: UInt64
    # H3.
    var h3_churn_closes: UInt64
    var regrant_holds: UInt64
    # Egress.
    var egress_fallback_datagrams: UInt64

    def __init__(out self):
        self.dropped_initial_size = 0
        self.dropped_initial_dcid_len = 0
        self.dropped_unknown_dcid = 0
        self.dropped_undecodable = 0
        self.dropped_truncated = 0
        self.dropped_vn_small = 0
        self.retry_sent = 0
        self.invalid_token_closes = 0
        self.refused_closes = 0
        self.vn_sent = 0
        self.stateless_bucket_empty_close = 0
        self.stateless_bucket_empty_vn = 0
        self.stateless_dropped_egress = 0
        self.tokens_none = 0
        self.tokens_valid = 0
        self.tokens_invalid = 0
        self.handshaking_peak = 0
        self.unvalidated_handshaking_peak = 0
        self.unvalidated_evictions = 0
        self.admitted_by_largest_source = 0
        self.sources_active = 0
        self.fair_share_evictions = 0
        self.graceful_drains = 0
        self.memory_evictions = 0
        self.cap_rejections = 0
        self.closing_forced = 0
        self.closing_refused = 0
        self.busy_victims_killed = 0
        self.accept_fd_exhausted = 0
        self.passes = 0
        self.dispatch_passes = 0
        self.dispatches = 0
        self.handler_calls = 0
        self.timeouts_first_request = 0
        self.timeouts_header = 0
        self.timeouts_body = 0
        self.timeouts_wall = 0
        self.timeouts_send = 0
        self.timeouts_idle = 0
        self.bad_request_400 = 0
        self.internal_500 = 0
        self.rejections_503 = 0
        self.refused_streams = 0
        self.ignored_frames_locally_closed = 0
        self.window_credited_back_bytes = 0
        self.enhance_your_calm_peer_reset = 0
        self.enhance_your_calm_induced = 0
        self.enhance_your_calm_continuation = 0
        self.enhance_your_calm_overhead = 0
        self.enhance_your_calm_control_queue = 0
        self.enhance_your_calm_send = 0
        self.refused_lifetime_closes = 0
        self.purged_before_dispatch = 0
        self.h3_churn_closes = 0
        self.regrant_holds = 0
        self.egress_fallback_datagrams = 0
