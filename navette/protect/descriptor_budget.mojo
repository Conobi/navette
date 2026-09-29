"""Process-wide file-descriptor budget, split deterministically between servers.

Every server of a process registers with one `DescriptorBudget` before
the first `start()`. H3 reserves only its UDP socket(s) plus slack (its
connections use no descriptors). When every TCP server's
`conn_cap + closing_cap + FD_SLACK` fits the remainder, each keeps its
request; otherwise each server's minimum (64 connections) and overhead
are reserved first and the rest is split in proportion to what each
requested beyond its minimum.
The first `tcp_conn_cap` call freezes the budget, so the split never
depends on which server started first.

Every input is range-checked on entry (caps within
`[MIN_CONN_CAP, MAX_CONN_CAP]` and `[1, MAX_CLOSING_CAP]`, limits within
`[0, MAX_FD_LIMIT]`), so no sum or product in the split can overflow `Int`.
"""

from std.collections import InlineArray
from std.ffi import external_call
from std.os import listdir

comptime FD_SLACK: Int = 16
comptime MIN_CONN_CAP: Int = 64
comptime MAX_CONN_CAP: Int = 1 << 24
"""16.7 M connections: far above any descriptor limit, low enough that sizing tables from it cannot wrap."""
comptime MAX_CLOSING_CAP: Int = 1 << 16
comptime CLOSING_CAP_DIVISOR: Int = 4
"""The default `closing_cap` is `conn_cap / 4`: drains and flushes scale with the connections that produce them."""
comptime MAX_UDP_SOCKETS: Int = 1024
comptime MAX_FD_LIMIT: Int = 1 << 30
comptime _RLIMIT_NOFILE: Int32 = 7


struct DescriptorBudget(Movable):
    """`limit` is the soft RLIMIT_NOFILE after raising it; `base` the descriptors open at creation."""

    var limit: Int
    var base: Int
    var _udp_reserved: Int
    var _tcp_caps: List[Int]
    var _tcp_closing: List[Int]
    var _frozen: Bool

    def __init__(out self, *, limit: Int, base: Int) raises:
        """Explicit limits, for tests and for applications that manage rlimits themselves; each must be in `0..MAX_FD_LIMIT`."""
        if limit < 0 or limit > MAX_FD_LIMIT or base < 0 or base > MAX_FD_LIMIT:
            raise (
                "DescriptorBudget: limit and base must be in 0.."
                + String(MAX_FD_LIMIT)
                + ", got "
                + String(limit)
                + " and "
                + String(base)
            )
        self.limit = limit
        self.base = base
        self._udp_reserved = 0
        self._tcp_caps = List[Int]()
        self._tcp_closing = List[Int]()
        self._frozen = False

    @staticmethod
    def from_process() raises -> Self:
        """Raise the soft RLIMIT_NOFILE to the hard limit, then count the descriptors already open.

        A refused `setrlimit` keeps the current soft limit; an unreadable
        `/proc/self/fd` assumes 16 open descriptors. Raises when
        `getrlimit` itself fails.
        """
        return _from_process_with[_getrlimit]()

    def reserve_udp(mut self, sockets: Int) raises:
        """An H3 server's UDP socket(s) plus `FD_SLACK`; `sockets` must be in `1..MAX_UDP_SOCKETS`."""
        if self._frozen:
            raise "DescriptorBudget: register every server before the first start()"
        if sockets < 1 or sockets > MAX_UDP_SOCKETS:
            raise "DescriptorBudget: UDP sockets must be in 1.." + String(MAX_UDP_SOCKETS) + ", got " + String(sockets)
        self._udp_reserved += sockets + FD_SLACK

    def register_tcp(mut self, conn_cap: Int, closing_cap: Int) raises -> Int:
        """Register a TCP server's requested caps; returns its token for `tcp_conn_cap`.

        Raises unless `conn_cap` is in `[MIN_CONN_CAP, MAX_CONN_CAP]` and
        `closing_cap` in `[1, MAX_CLOSING_CAP]`: a negative cap would hand
        its descriptors to the other servers (overshooting the limit), and a
        huge one would overflow the split.
        """
        if self._frozen:
            raise "DescriptorBudget: register every server before the first start()"
        check_pool_caps(conn_cap, closing_cap, MIN_CONN_CAP)
        self._tcp_caps.append(conn_cap)
        self._tcp_closing.append(closing_cap)
        return len(self._tcp_caps) - 1

    def tcp_conn_cap(mut self, token: Int) raises -> Int:
        """The server's effective `conn_cap`; freezes the budget.

        When every server's `conn_cap + closing_cap + FD_SLACK` fits the
        remainder, each keeps its request. Otherwise every server first
        gets `64 + closing_cap + FD_SLACK`, and what is left is split in
        proportion to `conn_cap - 64`, capped at
        the request, so no server is starved below its minimum while the
        minimums fit. Raises when even the minimums do not fit, or on a
        token this budget never issued.
        """
        if token < 0 or token >= len(self._tcp_caps):
            raise "DescriptorBudget: unknown server token " + String(token)
        self._frozen = True
        var remainder = self.limit - self.base - self._udp_reserved
        var full_need = 0
        var min_need = 0
        var weights = 0
        for i in range(len(self._tcp_caps)):
            var req = self._tcp_caps[i]
            var overhead = self._tcp_closing[i] + FD_SLACK
            full_need += req + overhead
            min_need += MIN_CONN_CAP + overhead
            weights += req - MIN_CONN_CAP
        var requested = self._tcp_caps[token]
        if full_need <= remainder:
            return requested
        if min_need > remainder:
            raise (
                "DescriptorBudget: the servers of this process need "
                + String(min_need)
                + " descriptors for their minimum of "
                + String(MIN_CONN_CAP)
                + " connections each, but only "
                + String(max(remainder, 0))
                + " are available; raise RLIMIT_NOFILE, or run fewer"
                + " servers or lower their conn_cap"
            )
        # Here 0 <= remainder - min_need <= limit <= MAX_FD_LIMIT (2^30) and
        # requested - MIN_CONN_CAP < MAX_CONN_CAP (2^24), so the product stays below 2^54.
        var cap = MIN_CONN_CAP
        if weights > 0:
            cap += (remainder - min_need) * (requested - MIN_CONN_CAP) // weights
        return min(cap, requested)


comptime _GetrlimitFn = def (Int32, Pointer[UInt64, MutAnyOrigin]) thin -> Int
"""Fills `{soft, hard}` for the resource; returns 0 or `-errno`."""


def _getrlimit(resource: Int32, rl: Pointer[UInt64, MutAnyOrigin]) -> Int:
    """getrlimit(2) with errno folded into the result."""
    if external_call["getrlimit", Int32](resource, rl) != 0:
        return -Int(external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()[])
    return 0


def _from_process_with[getrlimit: _GetrlimitFn]() raises -> DescriptorBudget:
    """The testable core of `DescriptorBudget.from_process`."""
    var rl = InlineArray[UInt64, 2](fill=UInt64(0))
    var r = getrlimit(_RLIMIT_NOFILE, rl.unsafe_ptr().as_unsafe_any_origin())
    if r != 0:
        raise Error("DescriptorBudget: getrlimit(RLIMIT_NOFILE) failed: errno " + String(-r))
    if rl[0] < rl[1]:
        var want = InlineArray[UInt64, 2](fill=rl[1])
        if external_call["setrlimit", Int32](_RLIMIT_NOFILE, want.unsafe_ptr()) == 0:
            rl[0] = rl[1]
    var base = 16
    try:
        base = len(listdir("/proc/self/fd"))
    except:
        pass
    return DescriptorBudget(limit=Int(min(rl[0], UInt64(MAX_FD_LIMIT))), base=base)


def default_closing_cap(conn_cap: Int) -> Int:
    """`conn_cap / CLOSING_CAP_DIVISOR` clamped to `[1, MAX_CLOSING_CAP]`, the closing cap when none is configured.

    Register the same value with `register_tcp` as the `ConnPool` is
    built with: the descriptor split reserves exactly what it is told.
    """
    return min(max(conn_cap // CLOSING_CAP_DIVISOR, 1), MAX_CLOSING_CAP)


def check_pool_caps(conn_cap: Int, closing_cap: Int, min_conn_cap: Int) raises:
    """Raise unless `conn_cap` is in `[min_conn_cap, MAX_CONN_CAP]` and `closing_cap` in `[1, MAX_CLOSING_CAP]`."""
    if conn_cap < min_conn_cap or conn_cap > MAX_CONN_CAP:
        raise (
            "conn_cap must be in "
            + String(min_conn_cap)
            + ".."
            + String(MAX_CONN_CAP)
            + ", got "
            + String(conn_cap)
        )
    if closing_cap < 1 or closing_cap > MAX_CLOSING_CAP:
        raise "closing_cap must be in 1.." + String(MAX_CLOSING_CAP) + ", got " + String(closing_cap)
