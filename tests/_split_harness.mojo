# tests/_split_harness.mojo
"""Seeded split plans, payloads and byte comparison for the boundary suites.

Every helper is deterministic for a given seed, so a failing case can be
replayed from the plan label printed in the assertion message.
"""
from std.os import getenv

# Iteration cap for every drive loop in the boundary tests: exhausting it is
# an assertion failure, never a hang.
comptime MAX_DRIVE_ITERS = 200_000

# Record layout (plaintext bytes per TLS record, fed whole) that the probe in
# crates/librustls-mojo/tests/probe_plaintext_full.rs found failing on main
# with "received plaintext buffer full". The failure depends on the layout,
# not the total: 18 432 bytes sealed as [16384, 2048] passes on main.
def tls_probe_layout() -> List[Int]:
    """Failing record layout pinned by the probe (a function: Mojo cannot
    materialize a comptime List at runtime)."""
    return [16384, 512, 512, 512, 512]

# Total of tls_probe_layout(); kept as a size-sweep entry, not a red trigger.
comptime TLS_PROBE_MIN_A = 18432


struct SplitRng(Movable):
    """xorshift64* generator; a zero seed is remapped so the stream never sticks."""

    var _state: UInt64

    def __init__(out self, seed: UInt64):
        self._state = seed if seed != 0 else UInt64(0x9E3779B97F4A7C15)

    def next(mut self) -> UInt64:
        var x = self._state
        x ^= x >> 12
        x ^= x << 25
        x ^= x >> 27
        self._state = x
        return x * UInt64(0x2545F4914F6CDD1D)

    def below(mut self, bound: Int) -> Int:
        """Integer in [0, bound); `bound` must be positive."""
        return Int(self.next() % UInt64(bound))


@fieldwise_init
struct SplitPlan(Copyable, Movable):
    """Chunk sizes summing to a transcript length; `label` replays the plan."""

    var chunks: List[Int]
    var label: String


def payload(n: Int, seed: UInt64) -> List[Byte]:
    """`n` pseudo-random (incompressible) bytes."""
    var rng = SplitRng(seed)
    var out = List[Byte](capacity=n)
    for _ in range(n):
        out.append(Byte(rng.next() >> 56))
    return out^


def compressible_payload(n: Int) -> List[Byte]:
    """`n` bytes of repeating ASCII text."""
    var src = String("the quick brown fox jumps over the lazy dog 0123456789\n").as_bytes()
    var out = List[Byte](capacity=n)
    for i in range(n):
        out.append(src[i % len(src)])
    return out^


def large_cases_enabled() -> Bool:
    """10 MiB cases run only with NAVETTE_TEST_LARGE=1 (never in CI)."""
    return getenv("NAVETTE_TEST_LARGE") == "1"


def boundary_sizes() -> List[Int]:
    """Sizes around every limit the boundaries know about (16 KiB, 64 KiB, 256 KiB)."""
    var s: List[Int] = [
        0, 1, 16383, 16384, 16385, TLS_PROBE_MIN_A, 16384 + 4097, 32768,
        65535, 65536, 65537, 262143, 262144, 262145, 1 << 20,
    ]
    if large_cases_enabled():
        s.append(10 << 20)
    return s^


def _fixed(total: Int, size: Int) -> SplitPlan:
    var c = List[Int]()
    var left = total
    while left > 0:
        var n = min(size, left)
        c.append(n)
        left -= n
    return SplitPlan(chunks=c^, label="fixed(" + String(size) + ")")


def split_plans(
    total: Int, seed: UInt64, sampled: Int = 64, randoms: Int = 8,
    exhaustive_max: Int = 4096,
) -> List[SplitPlan]:
    """Whole, 1/7-byte (totals <= 64 KiB only), fixed sizes, two-chunk cuts
    (all when total <= `exhaustive_max`, else `sampled`), and `randoms`
    random splits. Lower `exhaustive_max` when one case is expensive (a
    small compressed body that inflates to megabytes)."""
    var plans = List[SplitPlan]()
    var whole = List[Int]()
    if total > 0:
        whole.append(total)
    plans.append(SplitPlan(chunks=whole^, label="whole"))
    if total < 2:
        return plans^
    if total <= 65536:
        plans.append(_fixed(total, 1))
        plans.append(_fixed(total, 7))
    var fixed: List[Int] = [4095, 4096, 4097, 16383, 16384, 16385, 65535, 65536, 65537]
    for i in range(len(fixed)):
        if fixed[i] < total:
            plans.append(_fixed(total, fixed[i]))
    var rng = SplitRng(seed)
    var exhaustive = total <= exhaustive_max
    var cuts = total - 1 if exhaustive else sampled
    for k in range(cuts):
        var cut = k + 1 if exhaustive else 1 + rng.below(total - 1)
        var c: List[Int] = [cut, total - cut]
        plans.append(SplitPlan(chunks=c^, label="cut@" + String(cut)))
    for r in range(randoms):
        var c = List[Int]()
        var left = total
        while left > 0:
            var n = 1 + rng.below(min(left, 70000))
            c.append(n)
            left -= n
        plans.append(SplitPlan(
            chunks=c^, label="random#" + String(r) + " seed=" + String(seed),
        ))
    return plans^


def assert_bytes_equal(got: List[Byte], want: List[Byte], context: String) raises:
    """Raise with the first differing offset, or the length mismatch."""
    var n = min(len(got), len(want))
    for i in range(n):
        if got[i] != want[i]:
            raise Error(
                context + ": first difference at offset " + String(i)
                + " (got " + String(Int(got[i])) + ", want "
                + String(Int(want[i])) + ")"
            )
    if len(got) != len(want):
        raise Error(
            context + ": length " + String(len(got)) + " != expected "
            + String(len(want))
        )
