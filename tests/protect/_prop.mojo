"""Deterministic generator for the property tests under `tests/protect/`.

Mojo has no property-testing framework. `Rng` is SplitMix64: seeded, so a
failing case replays exactly. Property tests loop over many generated
cases and put the seed and case index in every assertion message, so a
failure names the case to replay. The sockaddr builders produce the
exact Linux layouts the servers read.
"""


struct Rng(Movable):
    """SplitMix64 stream; `seed` fixes the whole sequence."""

    var state: UInt64

    def __init__(out self, seed: UInt64):
        self.state = seed

    def next(mut self) -> UInt64:
        self.state += 0x9E3779B97F4A7C15
        var z = self.state
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        return z ^ (z >> 31)

    def below(mut self, n: Int) -> Int:
        """Integer in [0, n); n must be > 0.

        Plain modulo, so values are biased towards small results by up to
        n / 2^64: negligible for test sizes, not for cryptographic use.
        """
        return Int(self.next() % UInt64(n))

    def chance(mut self, percent: Int) -> Bool:
        return self.below(100) < percent

    def bytes(mut self, n: Int) -> List[Byte]:
        var out = List[Byte](capacity=n)
        for _ in range(n):
            out.append(Byte(self.next() & 0xFF))
        return out^


def sockaddr_in(a: UInt8, b: UInt8, c: UInt8, d: UInt8, port: Int) -> List[Byte]:
    """16-byte `sockaddr_in`: family LE, port BE, address, zero pad."""
    var s = List[Byte](length=16, fill=Byte(0))
    s[0] = 2
    s[2] = UInt8((port >> 8) & 0xFF)
    s[3] = UInt8(port & 0xFF)
    s[4] = a
    s[5] = b
    s[6] = c
    s[7] = d
    return s^


def sockaddr_in6(addr: List[Byte], port: Int, flowinfo: UInt32, scope_id: UInt32) -> List[Byte]:
    """28-byte `sockaddr_in6`: family LE, port BE, flowinfo BE, 16-byte address, scope_id LE.

    Linux declares `sin6_flowinfo` as `__be32` (network order) and
    `sin6_scope_id` as a host-order `__u32` (little-endian on x86-64).
    """
    var s = List[Byte](length=28, fill=Byte(0))
    s[0] = 10
    s[2] = UInt8((port >> 8) & 0xFF)
    s[3] = UInt8(port & 0xFF)
    for i in range(4):
        s[4 + i] = UInt8((flowinfo >> UInt32(8 * (3 - i))) & 0xFF)
        s[24 + i] = UInt8((scope_id >> UInt32(8 * i)) & 0xFF)
    for i in range(16):
        s[8 + i] = addr[i]
    return s^


def mapped_v6(a: UInt8, b: UInt8, c: UInt8, d: UInt8) -> List[Byte]:
    """The 16 address bytes of `::ffff:a.b.c.d`."""
    var addr = List[Byte](length=16, fill=Byte(0))
    addr[10] = 0xFF
    addr[11] = 0xFF
    addr[12] = a
    addr[13] = b
    addr[14] = c
    addr[15] = d
    return addr^
