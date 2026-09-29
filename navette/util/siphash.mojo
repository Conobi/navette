"""SipHash-c-d keyed hashing (Aumasson & Bernstein, 2012).

Used wherever a client-chosen value selects a hash-table bucket (source
keys, long QUIC DCIDs): with a per-process random key an attacker cannot
precompute colliding inputs. SipHash-1-3 is the variant Rust's std
`HashMap` ships; SipHash-2-4 is kept reachable for the reference vectors.
"""

from std.bit import rotate_bits_left
from std.collections import Span

from navette.util.secure_random import fill_random


@fieldwise_init
struct SipKey(Copyable, Movable):
    """128-bit SipHash key as two little-endian words.

    Draw it with `SipKey.random()` once per process (or per server) and
    never expose it: never log it, and never copy it into long-lived
    structures beyond the table that owns it. The collision resistance of
    every table keyed with it rests on the key staying secret.
    """

    var k0: UInt64
    var k1: UInt64

    @staticmethod
    def random() raises -> Self:
        """16 bytes from the kernel CSPRNG.

        Raises when getrandom(2) fails (ENOSYS, a seccomp filter): a key
        silently left zero would be public, letting a client precompute
        colliding inputs.
        """
        var buf = InlineArray[UInt8, 16](fill=UInt8(0))
        fill_random(Span(buf))
        var k0 = UInt64(0)
        var k1 = UInt64(0)
        for i in range(8):
            k0 |= UInt64(buf[i]) << UInt64(8 * i)
            k1 |= UInt64(buf[8 + i]) << UInt64(8 * i)
        return Self(k0=k0, k1=k1)


@always_inline
def _sipround(mut v0: UInt64, mut v1: UInt64, mut v2: UInt64, mut v3: UInt64):
    v0 += v1
    v1 = rotate_bits_left[13](v1)
    v1 ^= v0
    v0 = rotate_bits_left[32](v0)
    v2 += v3
    v3 = rotate_bits_left[16](v3)
    v3 ^= v2
    v0 += v3
    v3 = rotate_bits_left[21](v3)
    v3 ^= v0
    v2 += v1
    v1 = rotate_bits_left[17](v1)
    v1 ^= v2
    v2 = rotate_bits_left[32](v2)


def siphash[c: Int, d: Int](key: SipKey, data: Span[Byte, _]) -> UInt64:
    """SipHash-c-d of `data`; allocation-free, one pass over the input."""
    var v0 = key.k0 ^ 0x736F6D6570736575
    var v1 = key.k1 ^ 0x646F72616E646F6D
    var v2 = key.k0 ^ 0x6C7967656E657261
    var v3 = key.k1 ^ 0x7465646279746573
    var n = len(data)
    var end = n - (n % 8)
    var i = 0
    while i < end:
        var m = UInt64(0)
        for j in range(8):
            m |= UInt64(data[i + j]) << UInt64(8 * j)
        v3 ^= m
        comptime for _ in range(c):
            _sipround(v0, v1, v2, v3)
        v0 ^= m
        i += 8
    var b = UInt64(n & 0xFF) << 56
    for j in range(n - end):
        b |= UInt64(data[end + j]) << UInt64(8 * j)
    v3 ^= b
    comptime for _ in range(c):
        _sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    comptime for _ in range(d):
        _sipround(v0, v1, v2, v3)
    return v0 ^ v1 ^ v2 ^ v3


@always_inline
def siphash13(key: SipKey, data: Span[Byte, _]) -> UInt64:
    """SipHash-1-3, the table-keying variant used across navette."""
    return siphash[1, 3](key, data)
