# tests/fuzz/lib/prng.mojo
#
# SplitMix64 deterministic PRNG.
#
# Reference: https://prng.di.unimi.it/splitmix64.c (public domain).
# No `random` stdlib dependency — seed reproducibility is load-bearing per
# specs/2026-05-21-fuzz-harnesses-critical-parsers.md AC2.


struct SplitMix64(Copyable, Movable):
    """SplitMix64 PRNG. Produces a deterministic byte stream from a UInt64 seed."""

    var state: UInt64

    def __init__(out self, seed: UInt64):
        self.state = seed

    def __init__(out self, *, deinit take: Self):
        self.state = take.state

    def next_u64(mut self) -> UInt64:
        self.state = self.state + UInt64(0x9E3779B97F4A7C15)
        var z = self.state
        z = (z ^ (z >> UInt64(30))) * UInt64(0xBF58476D1CE4E5B9)
        z = (z ^ (z >> UInt64(27))) * UInt64(0x94D049BB133111EB)
        return z ^ (z >> UInt64(31))

    def next_u32(mut self) -> UInt32:
        return UInt32(self.next_u64() & UInt64(0xFFFFFFFF))

    def next_u8(mut self) -> UInt8:
        return UInt8(self.next_u64() & UInt64(0xFF))

    def next_below(mut self, n: UInt64) -> UInt64:
        # Returns a value in [0, n). If n == 0, returns 0.
        if n == 0:
            return UInt64(0)
        return self.next_u64() % n

    def next_bool(mut self) -> Bool:
        return (self.next_u64() & UInt64(1)) != 0
