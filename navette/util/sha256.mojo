"""SHA-256 (FIPS 180-4), allocation-free, for short inputs on rare paths.

The rustls shim exports HMAC-SHA256 but not a bare digest; the Retry
token binds the client address through a plain SHA-256 of its IP bytes
and port, which this module computes without a round trip to the shim.
"""

from std.bit import rotate_bits_right
from std.collections import InlineArray, Span

comptime _K: InlineArray[UInt32, 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _compress(mut h: InlineArray[UInt32, 8], block: InlineArray[UInt8, 64]):
    var w = InlineArray[UInt32, 64](fill=UInt32(0))
    for t in range(16):
        w[t] = (
            (UInt32(block[4 * t]) << 24)
            | (UInt32(block[4 * t + 1]) << 16)
            | (UInt32(block[4 * t + 2]) << 8)
            | UInt32(block[4 * t + 3])
        )
    for t in range(16, 64):
        var s0 = rotate_bits_right[7](w[t - 15]) ^ rotate_bits_right[18](w[t - 15]) ^ (w[t - 15] >> 3)
        var s1 = rotate_bits_right[17](w[t - 2]) ^ rotate_bits_right[19](w[t - 2]) ^ (w[t - 2] >> 10)
        w[t] = w[t - 16] + s0 + w[t - 7] + s1
    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    var e = h[4]
    var f = h[5]
    var g = h[6]
    var hh = h[7]
    var k = materialize[_K]()
    for t in range(64):
        var big_s1 = rotate_bits_right[6](e) ^ rotate_bits_right[11](e) ^ rotate_bits_right[25](e)
        var ch = (e & f) ^ (~e & g)
        var t1 = hh + big_s1 + ch + k[t] + w[t]
        var big_s0 = rotate_bits_right[2](a) ^ rotate_bits_right[13](a) ^ rotate_bits_right[22](a)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = big_s0 + maj
        hh = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    h[0] += a
    h[1] += b
    h[2] += c
    h[3] += d
    h[4] += e
    h[5] += f
    h[6] += g
    h[7] += hh


def sha256(data: Span[Byte, _]) -> InlineArray[UInt8, 32]:
    """Digest of `data`; stack-only, so it is safe on the per-Retry path."""
    var h: InlineArray[UInt32, 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]
    var n = len(data)
    var block = InlineArray[UInt8, 64](fill=UInt8(0))
    var off = 0
    while off + 64 <= n:
        for i in range(64):
            block[i] = data[off + i]
        _compress(h, block)
        off += 64
    var rem = n - off
    for i in range(64):
        block[i] = data[off + i] if i < rem else UInt8(0)
    block[rem] = 0x80
    if rem >= 56:
        _compress(h, block)
        for i in range(64):
            block[i] = 0
    var bits = UInt64(n) * 8
    for i in range(8):
        block[63 - i] = UInt8((bits >> UInt64(8 * i)) & 0xFF)
    _compress(h, block)
    var out = InlineArray[UInt8, 32](fill=UInt8(0))
    for i in range(8):
        out[4 * i] = UInt8((h[i] >> 24) & 0xFF)
        out[4 * i + 1] = UInt8((h[i] >> 16) & 0xFF)
        out[4 * i + 2] = UInt8((h[i] >> 8) & 0xFF)
        out[4 * i + 3] = UInt8(h[i] & 0xFF)
    return out^
