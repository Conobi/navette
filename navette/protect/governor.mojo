"""Overload governor core: queue-wait sensor arithmetic, the server-wide stream budget, per-connection windows.

Pure (`std` only, no clock reads, no allocation, no floats, no wrap; one rate-limited warning print): the server shell
passes time and counters in.
Every time constant derives from the one dial `t = max_queue_delay_us`.
"""

from std.bit import bit_width

comptime _BUCKETS = 32
comptime MIN_SAMPLES = 20
"""Fewer samples in an interval read as idle: p90 then rests on at least 2 of them."""


def interval_us(t: UInt64) -> UInt64:
    """Sensing interval `I = 20 t` (CoDel's 5 ms / 100 ms ratio)."""
    return 20 * t


def retry_after_s(t: UInt64) -> UInt64:
    """`Retry-After` of a refusal: the calm time `200 t` rounded up to whole seconds, at least 1."""
    return max(UInt64(1), (200 * t + 999_999) // 1_000_000)


comptime DATAGRAM_TRUESIZE: UInt64 = 2_304
"""Receive-queue bytes per queued QUIC datagram: `SO_MEMINFO` counts skb truesize, measured at 2,304 B for 1,200 to
1,472 B UDP payloads on Linux (a 2 KiB data slab plus the sk_buff); NIC page-fragment buffers land in the same range."""


def kwait_us(rmem: UInt64, deliveries_prev: UInt64, interval: UInt64) -> UInt64:
    """Kernel socket-queue wait: the datagrams in `rmem` bytes drain at the last interval's read rate, capped at `interval`.

    0 when the queue is empty or the rate is unknown (fewer than `MIN_SAMPLES` reads last interval).
    """
    if rmem == 0 or deliveries_prev < MIN_SAMPLES:
        return 0
    var w = UInt128(rmem) * UInt128(interval) // (UInt128(DATAGRAM_TRUESIZE) * UInt128(deliveries_prev))
    return UInt64(min(w, UInt128(interval)))


struct DelayHist(Copyable, Movable):
    """Per-interval wait samples in µs, log2 buckets: bucket `b` holds `[2^(b-1), 2^b - 1]`, the top one everything above."""

    var buckets: InlineArray[UInt32, _BUCKETS]
    var total: UInt64

    def __init__(out self):
        self.buckets = InlineArray[UInt32, _BUCKETS](fill=0)
        self.total = 0

    def insert(mut self, us: UInt64):
        self.buckets[Int(min(bit_width(us), UInt64(_BUCKETS - 1)))] += 1
        self.total += 1

    def insert_pass(mut self, kwait: UInt64, n: UInt64, span: UInt64):
        """Insert the waits of a pass's `n` requests: `kwait` plus the `k`-th request's share `k * span / n` of the pass."""
        for k in range(n):
            self.insert(kwait + UInt64((UInt128(k) * UInt128(span)) // UInt128(n)))

    def p90(self) -> UInt64:
        """90th percentile (rank `ceil(0.9 total)`), linearly interpolated inside its bucket; 0 when empty."""
        var rank = (9 * self.total + 9) // 10
        var seen = UInt64(0)
        for b in range(_BUCKETS):
            var count = UInt64(self.buckets[b])
            if count != 0 and seen + count >= rank:
                var lo = (UInt64(1) << UInt64(b)) >> 1
                return lo + lo * (rank - seen) // (count + 1)
            seen += count
        return 0

    def close_delay(mut self) -> UInt64:
        """The closing interval's p90, then reset; 0 (idle) below `MIN_SAMPLES`."""
        var d = UInt64(0) if self.total < MIN_SAMPLES else self.p90()
        self = Self()
        return d


comptime UNLIMITED = UInt64.MAX
"""Budget value meaning released: no window below the configured stream credit, no refusals."""
comptime FLOOR: UInt64 = 32
"""Budget floor, server-wide; `cap` when lower."""
comptime MIN_CREDIT: UInt64 = 2
"""Least stream credit a connection keeps under pressure; `cap` when lower. Credit returns only once the client
acknowledges a response (completions count fully closed streams), so with 1 each request would also wait out the
client's ACK delay; 2 overlaps the next request with it."""
comptime RELEASE = 10
"""Consecutive clear closes (`200 t`) before the budget returns to unlimited: the metastability guard."""
comptime PENDING_MAX = 10
"""Closes after which a cut counts as taken effect even if open work is still above the budget."""
comptime MEASURED: UInt64 = 2
"""Closes after a cut before another: the interval in which a cut lands ran partly under the old budget, so a cut is
judged only on the next one, measured whole under it (CoDel waits an interval after acting)."""
comptime REFUSE_AFTER: UInt64 = 3
"""Consecutive closes above `4 t`, with nothing left to cut, before new connections are refused: one slow pass of
handshakes must not refuse (dropped clients retransmit together and would re-trigger it)."""


@fieldwise_init
struct Mode(Equatable, ImplicitlyCopyable, Writable):
    """Controller state after the last interval close; `step` lists the transitions."""

    var _v: UInt8
    comptime NORMAL = Mode(0)
    """Budget unlimited: today's behaviour."""
    comptime CUTTING = Mode(1)
    """Over target; this close cut the budget."""
    comptime HOLDING = Mode(2)
    """Over target, but the last cut has not taken effect or been measured for a whole interval, so no second cut."""
    comptime RECOVERING = Mode(3)
    """Clear after a cut: the budget grows while used, then is released."""


struct GovState(ImplicitlyCopyable, Movable):
    """`mode` plus what its transitions read; `since_cut`, `clear_streak`, `hot_streak` saturate at `PENDING_MAX`, `RELEASE`, `REFUSE_AFTER`."""

    var mode: Mode
    var budget: UInt64
    var refuse_new: Bool
    var since_cut: UInt64
    var clear_streak: UInt64
    var hot_streak: UInt64
    var cuts: UInt64
    var grows: UInt64
    var releases: UInt64

    def __init__(out self):
        self.mode, self.budget, self.refuse_new, self.since_cut, self.clear_streak, self.hot_streak = Mode.NORMAL, UNLIMITED, False, PENDING_MAX, 0, 0
        self.cuts, self.grows, self.releases = 0, 0, 0


@fieldwise_init
struct Sample(ImplicitlyCopyable, Movable):
    """One closed interval: p90 wait (µs) and completions, open work at close, connections holding some."""

    var delay_us: UInt64
    var done: UInt64
    var work: UInt64
    var active: UInt64


@fieldwise_init
struct Decision(ImplicitlyCopyable, Movable):
    """What the enforcing layers apply until the next close: `budget` bounds open streams server-wide; `conn_limit`
    turns it into stream-credit windows and `share` is a new connection's credit, both down to the even split
    `shed_above` but at least `MIN_CREDIT` (below RFC 9114's recommended 100, only under overload). Credit binds
    first; a new request on a connection already holding as many open streams as the larger of its window and
    `shed_above` (opened on credit granted before the window came down) gets 503 with `retry_after_s`.
    `refuse_new` refuses new connections. `UNLIMITED` enforces nothing."""

    var budget: UInt64
    var share: UInt64
    var shed_above: UInt64
    var refuse_new: Bool
    var retry_after_s: UInt64


def step(mut s: GovState, x: Sample, t: UInt64, cap: UInt64) -> Decision:
    """Advance the controller by one interval close; `t > 0`, `cap` = the per-connection stream credit.

    `over` is `x.delay_us > t`; the last cut has taken effect once `MEASURED` closes passed and either
    `x.work <= budget` (always in NORMAL) or `PENDING_MAX` closes passed.
    - any, over, cut taken effect -> CUTTING: budget cut from usage `min(budget, work)` towards
      `work - done (delay - t) / I`, by at most half, never below the floor. Only the excess server queue is
      cut: `work` spans whole stream lifetimes, including the RTT, ACK delay and client turnaround that hold credit
      outside the server, so Little's `done t / I` would cut that credit too and starve throughput.
    - any, over, cut not taken effect -> HOLDING: budget kept (MAX_STREAMS credit is irrevocable and the
      sensor lags an interval, so stacked cuts undershoot).
    - CUTTING, HOLDING or RECOVERING, clear -> RECOVERING: budget grows by `active` while at least
      half used; -> NORMAL (unlimited) instead on the `RELEASE`-th clear close in a row or once the
      budget covers every active connection's full credit.
    - NORMAL, clear -> NORMAL.
    `refuse_new` is set by the `REFUSE_AFTER`-th consecutive close above `4 t` once the budget is already at
    `max(floor, target)` (no cut left to make), cleared by a clear close. Under pressure
    (CUTTING, HOLDING) `shed_above` is the even split `max(1, budget / active)` and the share is the same, at least
    `MIN_CREDIT` (overshoot at most `MIN_CREDIT x active` streams; refusing new connections covers the rest)."""
    var floor = min(FLOOR, cap)
    s.since_cut = min(s.since_cut + 1, PENDING_MAX)
    if x.delay_us > t:
        var excess = UInt128(x.done) * UInt128(x.delay_us - t) // UInt128(interval_us(t))
        var target = UInt128(x.work) - min(UInt128(x.work), excess)
        s.clear_streak = 0
        s.hot_streak = min(s.hot_streak + 1, REFUSE_AFTER) if x.delay_us > 4 * t else 0
        s.refuse_new = s.refuse_new or (s.hot_streak >= REFUSE_AFTER and UInt128(s.budget) <= max(UInt128(floor), target))
        s.mode = Mode.HOLDING
        if s.since_cut >= MEASURED and (x.work <= s.budget or s.since_cut >= PENDING_MAX):
            var base = UInt128(min(s.budget, x.work))
            s.budget = max(floor, UInt64(min(max(target, base // 2), base)))
            s.mode, s.since_cut, s.cuts = Mode.CUTTING, 0, s.cuts + 1
    else:
        s.refuse_new, s.hot_streak = False, 0
        s.clear_streak = min(s.clear_streak + 1, RELEASE)
        if s.mode != Mode.NORMAL:
            s.mode = Mode.RECOVERING
            if s.clear_streak < RELEASE and x.work >= s.budget // 2:
                s.budget, s.grows = UInt64(min(UInt128(s.budget) + UInt128(max(UInt64(1), x.active)), UInt128(UNLIMITED))), s.grows + 1
            if s.clear_streak >= RELEASE or UInt128(s.budget) >= min(UInt128(x.active) * UInt128(cap), UInt128(UNLIMITED)):
                s.mode, s.budget, s.releases = Mode.NORMAL, UNLIMITED, s.releases + 1
    var pressure = s.mode == Mode.CUTTING or s.mode == Mode.HOLDING
    var even = s.budget // max(UInt64(1), x.active)
    var share, shed_above = (max(min(MIN_CREDIT, cap), even), max(UInt64(1), even)) if pressure else (UNLIMITED, UNLIMITED)
    return Decision(budget=s.budget, share=share, shed_above=shed_above, refuse_new=s.refuse_new, retry_after_s=retry_after_s(t))


def conn_limit(l: UInt64, open_c: UInt64, budget: UInt64, work: UInt64, n: UInt64, cap: UInt64) -> UInt64:
    """A connection's next re-grant window from its current one `l` (gRPC C-core's per-connection limits); `n` connections share `budget`.

    With spare budget, windows below the mean share grow towards it and the rest may borrow up to twice it. Without,
    a window halves towards the share, once: not again while `open_c > l` (the last cut has not taken effect, credit
    being irrevocable). Clamped to `[min(MIN_CREDIT, cap), cap]`.
    """
    if budget == UNLIMITED:
        return cap
    var mean = max(UInt64(1), budget // max(UInt64(1), n))
    var spare = budget - min(budget, work)
    var w = l
    if spare > 0:
        if l < mean:
            w = l + min(max(UInt64(1), spare // max(UInt64(1), n)), mean - l)
        elif l - mean < mean:
            w = l + 1
        else:
            w = max(2 * mean, l // 2)
    elif open_c <= l:
        w = max(mean, l // 2)
    return min(max(w, min(MIN_CREDIT, cap)), cap)


comptime MEMINFO_EVERY = 16
"""Passes between forced `SO_MEMINFO` reads while ingest keeps draining the socket."""
comptime FEW_ACTIVE: UInt64 = 4
"""A cut over at most this many active connections reads as handlers slower than the dial, not overload."""
comptime WARN_EVERY: UInt64 = 100
"""Interval closes between two slow-handler warnings (10 s at the default dial)."""


@fieldwise_init
struct OverloadStats(Copyable, Movable):
    """The overload governor as of its last interval close: p90 and kernel wait (µs), controller state and decision;
    `slow_handler_warnings` counts the reported cuts over at most `FEW_ACTIVE` connections (one per `WARN_EVERY` closes)."""

    var queue_delay_us: UInt64
    var kernel_wait_us: UInt64
    var intervals: UInt64
    var state: GovState
    var decision: Decision
    var refused_streams_503: UInt64
    var slow_handler_warnings: UInt64


struct Governor(Movable):
    """Per-server sensor state around `step`, driven by the shell's clock; always built, inert at a 0 dial (the shell
    then skips every hook and `close_due` is always true, so a stale decision never applies).

    Per pass: `want_rmem`, `on_ingest`, `on_pass`; when `close_due`, `close`, whose `decision` the enforcing
    layers read. The shell adds to `requests` and `refused_503`."""

    var t: UInt64
    var state: GovState
    var decision: Decision
    var hist: DelayHist
    var kwait: UInt64
    var drained: Bool
    var passes: UInt64
    var last_pass_us: UInt64
    var last_close_us: UInt64
    var deliveries: UInt64
    var deliveries_prev: UInt64
    var stats: OverloadStats
    var requests: UInt64
    var refused_503: UInt64
    var warned_at: UInt64

    def __init__(out self, t: UInt64, now_us: UInt64):
        self.t, self.state = t, GovState()
        self.hist = DelayHist()
        self.decision = Decision(budget=UNLIMITED, share=UNLIMITED, shed_above=UNLIMITED, refuse_new=False, retry_after_s=retry_after_s(t))
        self.kwait, self.drained, self.passes = 0, True, 0
        self.last_pass_us, self.last_close_us, self.deliveries, self.deliveries_prev = now_us, now_us, 0, 0
        self.stats = OverloadStats(0, 0, 0, GovState(), self.decision, 0, 0)
        self.requests, self.refused_503, self.warned_at = 0, 0, 0

    def want_rmem(self) -> Bool:
        """Read `SO_MEMINFO` this pass: after an ingest that left datagrams queued, and every `MEMINFO_EVERY`-th pass."""
        return not self.drained or self.passes % MEMINFO_EVERY == 0

    def on_ingest(mut self, rmem: Optional[UInt64], deliveries: UInt64, drained: Bool):
        """`rmem`: queued bytes before ingest (None: not read or failed, no kernel wait)."""
        self.kwait = kwait_us(rmem.or_else(0), self.deliveries_prev, interval_us(self.t))
        self.deliveries += deliveries
        self.drained = drained

    def on_pass(mut self, now_us: UInt64, ingress_us: UInt64):
        """Record the `requests` this pass ran (each waited `kwait` plus its position in the pass); an idle gap of an interval drops older ones."""
        if now_us - min(now_us, self.last_pass_us) >= interval_us(self.t):
            self.hist = DelayHist()
        self.hist.insert_pass(self.kwait, self.requests, now_us - min(now_us, ingress_us))
        self.requests = 0
        self.passes += 1
        self.last_pass_us = now_us

    def close_due(self, now_us: UInt64) -> Bool:
        """An interval has passed since the last close: the current `decision` is stale until `close` runs."""
        return now_us - min(now_us, self.last_close_us) >= interval_us(self.t)

    def close(mut self, now_us: UInt64, done: UInt64, work: UInt64, active: UInt64, cap: UInt64):
        """Close the interval: step the controller on its p90 wait and the shell's counts (as in `Sample`), refresh `stats`; warn (print) on a slow-handler cut."""
        var delay = self.hist.close_delay()
        self.decision = step(self.state, Sample(delay_us=delay, done=done, work=work, active=active), self.t, cap)
        self.deliveries_prev, self.deliveries, self.last_close_us = self.deliveries, 0, now_us
        var n, warnings = self.stats.intervals + 1, self.stats.slow_handler_warnings
        if self.state.mode == Mode.CUTTING and active <= FEW_ACTIVE and (warnings == 0 or n - self.warned_at >= WARN_EVERY):
            self.warned_at, warnings = n, warnings + 1
            print("navette: overload cut with", active, "active connections: handlers may be slower than max_queue_delay_us")
        self.stats = OverloadStats(
            queue_delay_us=delay, kernel_wait_us=self.kwait, intervals=n, state=self.state,
            decision=self.decision, refused_streams_503=self.refused_503, slow_handler_warnings=warnings,
        )
