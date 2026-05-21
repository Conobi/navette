# conformance/lib/http2/hpack_oracle.mojo
#
# Independent HPACK encoder + decoder for RFC 7541.
# Used as the defect-orthogonal oracle for tests/fuzz/test_fuzz_hpack.mojo.
#
# v1 of S0 ships DECODER ONLY. The encoder lands at S2 / harness #1 stage-3
# time, in a follow-up commit. AC0 (RFC 7541 §C wire decode parity) and
# AC0b (Divergence note) are satisfied by the decoder + tables alone.
#
# Divergence note (AC0b — see specs/2026-05-21-fuzz-harnesses-critical-parsers.md):
# This file MUST NOT share authorship with navette/h2/hpack.mojo. Concretely:
#
#  (a) Decoder dispatch: this file uses a single flat while-loop with explicit
#      bit-test branches in order 1xxxxxxx -> 01xxxxxx -> 001xxxxx ->
#      0001xxxx -> 0000xxxx (see `decode` below, the if/elif chain).
#      navette/h2/hpack.mojo:188-265 uses the same conceptual order but
#      different ergonomic shape (per-pattern `if byte & 0x80 / byte & 0x40 /
#      byte & 0x20 / byte & 0x10` chain with the past_table_updates flag
#      mutated separately in each branch). The line shape differs; production
#      tests `byte & 0xXX` directly, this oracle pre-extracts `top_2`
#      and `nibble_high` and dispatches on those.
#
#  (b) Huffman decode: this file walks a manually-built binary trie one bit
#      at a time and emits each symbol on leaf hit (`_huffman_decode` below,
#      bit-by-bit loop with `(byte >> bit_offset) & 1`).
#      navette/h2/hpack_huffman.mojo uses a precomputed 4-bit-wise state-
#      machine table loaded from a pre-baked transitions array. Two-bit-pair
#      vs single-bit walk; trie vs state machine.
#
#  (c) Integer codec: this file holds prefix-bit max-values in an explicit
#      if/elif ladder (`encode_oracle_integer` and `decode_oracle_integer`,
#      see the `if prefix_bits == N` chains). navette/h2/hpack_integer.mojo
#      uses `(1 << n) - 1` bitmask arithmetic with a single computation site.
#      Constant-table-lookup vs runtime arithmetic.
#
# Independence discipline: the author of this file did not have any
# navette/h2/hpack*.mojo file open while writing decode loops. Huffman code-
# point data was sourced via the Python `hpack` library v4.1.0 reading from
# `hpack.huffman_constants.REQUEST_CODES` + `REQUEST_CODES_LENGTH`, which
# directly mirror RFC 7541 Appendix B. Static table sourced via
# `hpack.table.HeaderTable.STATIC_TABLE`, mirroring RFC 7541 Appendix A.
# If you edit either this file or navette/h2/hpack*.mojo, re-verify (a)/(b)/(c)
# still hold.

from lib.http1.types import Header


# ============================================================================
# Integer codec — RFC 7541 §5.1
# ============================================================================


struct _IntDecodeResult(Copyable, Movable):
    var value: UInt64
    var consumed: Int
    var error: String

    def __init__(out self, value: UInt64, consumed: Int, error: String):
        self.value = value
        self.consumed = consumed
        self.error = error

    def __init__(out self, *, deinit take: Self):
        self.value = take.value
        self.consumed = take.consumed
        self.error = take.error^


def _max_prefix(prefix_bits: Int) -> UInt64:
    # Explicit if/elif ladder — Divergence note (c).
    if prefix_bits == 1: return UInt64(1)
    elif prefix_bits == 2: return UInt64(3)
    elif prefix_bits == 3: return UInt64(7)
    elif prefix_bits == 4: return UInt64(15)
    elif prefix_bits == 5: return UInt64(31)
    elif prefix_bits == 6: return UInt64(63)
    elif prefix_bits == 7: return UInt64(127)
    elif prefix_bits == 8: return UInt64(255)
    return UInt64(0)


def encode_oracle_integer(value: UInt64, prefix_bits: Int) -> List[UInt8]:
    var out = List[UInt8]()
    var maxp = _max_prefix(prefix_bits)
    if maxp == 0:
        return out^
    if value < maxp:
        out.append(UInt8(value))
        return out^
    out.append(UInt8(maxp))
    var rem = value - maxp
    while rem >= UInt64(128):
        out.append(UInt8((rem & UInt64(0x7F)) | UInt64(0x80)))
        rem = rem >> UInt64(7)
    out.append(UInt8(rem))
    return out^


def decode_oracle_integer(
    data: List[UInt8], offset: Int, prefix_bits: Int
) -> _IntDecodeResult:
    if offset >= len(data):
        return _IntDecodeResult(UInt64(0), 0, String("truncated integer"))
    var maxp = _max_prefix(prefix_bits)
    if maxp == 0:
        return _IntDecodeResult(UInt64(0), 0, String("bad prefix_bits"))
    var first = UInt64(data[offset]) & maxp
    if first < maxp:
        return _IntDecodeResult(first, 1, String(""))
    var value = maxp
    var shift: UInt64 = 0
    var consumed = 1
    while True:
        if offset + consumed >= len(data):
            return _IntDecodeResult(UInt64(0), 0, String("truncated integer"))
        var b = UInt64(data[offset + consumed])
        consumed += 1
        value += (b & UInt64(0x7F)) << shift
        if (b & UInt64(0x80)) == 0:
            return _IntDecodeResult(value, consumed, String(""))
        shift += UInt64(7)
        if shift > UInt64(56):
            return _IntDecodeResult(UInt64(0), 0, String("integer overflow"))


# ============================================================================
# Static table — RFC 7541 Appendix A
# ============================================================================


struct _StaticEntry(Copyable, Movable):
    var name: String
    var value: String

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value

    def __init__(out self, *, deinit take: Self):
        self.name = take.name^
        self.value = take.value^


def _static_table() -> List[_StaticEntry]:
    var t = List[_StaticEntry]()
    t.append(_StaticEntry(String(":authority"), String("")))  # idx 1
    t.append(_StaticEntry(String(":method"), String("GET")))  # idx 2
    t.append(_StaticEntry(String(":method"), String("POST")))  # idx 3
    t.append(_StaticEntry(String(":path"), String("/")))  # idx 4
    t.append(_StaticEntry(String(":path"), String("/index.html")))  # idx 5
    t.append(_StaticEntry(String(":scheme"), String("http")))  # idx 6
    t.append(_StaticEntry(String(":scheme"), String("https")))  # idx 7
    t.append(_StaticEntry(String(":status"), String("200")))  # idx 8
    t.append(_StaticEntry(String(":status"), String("204")))  # idx 9
    t.append(_StaticEntry(String(":status"), String("206")))  # idx 10
    t.append(_StaticEntry(String(":status"), String("304")))  # idx 11
    t.append(_StaticEntry(String(":status"), String("400")))  # idx 12
    t.append(_StaticEntry(String(":status"), String("404")))  # idx 13
    t.append(_StaticEntry(String(":status"), String("500")))  # idx 14
    t.append(_StaticEntry(String("accept-charset"), String("")))  # idx 15
    t.append(_StaticEntry(String("accept-encoding"), String("gzip, deflate")))  # idx 16
    t.append(_StaticEntry(String("accept-language"), String("")))  # idx 17
    t.append(_StaticEntry(String("accept-ranges"), String("")))  # idx 18
    t.append(_StaticEntry(String("accept"), String("")))  # idx 19
    t.append(_StaticEntry(String("access-control-allow-origin"), String("")))  # idx 20
    t.append(_StaticEntry(String("age"), String("")))  # idx 21
    t.append(_StaticEntry(String("allow"), String("")))  # idx 22
    t.append(_StaticEntry(String("authorization"), String("")))  # idx 23
    t.append(_StaticEntry(String("cache-control"), String("")))  # idx 24
    t.append(_StaticEntry(String("content-disposition"), String("")))  # idx 25
    t.append(_StaticEntry(String("content-encoding"), String("")))  # idx 26
    t.append(_StaticEntry(String("content-language"), String("")))  # idx 27
    t.append(_StaticEntry(String("content-length"), String("")))  # idx 28
    t.append(_StaticEntry(String("content-location"), String("")))  # idx 29
    t.append(_StaticEntry(String("content-range"), String("")))  # idx 30
    t.append(_StaticEntry(String("content-type"), String("")))  # idx 31
    t.append(_StaticEntry(String("cookie"), String("")))  # idx 32
    t.append(_StaticEntry(String("date"), String("")))  # idx 33
    t.append(_StaticEntry(String("etag"), String("")))  # idx 34
    t.append(_StaticEntry(String("expect"), String("")))  # idx 35
    t.append(_StaticEntry(String("expires"), String("")))  # idx 36
    t.append(_StaticEntry(String("from"), String("")))  # idx 37
    t.append(_StaticEntry(String("host"), String("")))  # idx 38
    t.append(_StaticEntry(String("if-match"), String("")))  # idx 39
    t.append(_StaticEntry(String("if-modified-since"), String("")))  # idx 40
    t.append(_StaticEntry(String("if-none-match"), String("")))  # idx 41
    t.append(_StaticEntry(String("if-range"), String("")))  # idx 42
    t.append(_StaticEntry(String("if-unmodified-since"), String("")))  # idx 43
    t.append(_StaticEntry(String("last-modified"), String("")))  # idx 44
    t.append(_StaticEntry(String("link"), String("")))  # idx 45
    t.append(_StaticEntry(String("location"), String("")))  # idx 46
    t.append(_StaticEntry(String("max-forwards"), String("")))  # idx 47
    t.append(_StaticEntry(String("proxy-authenticate"), String("")))  # idx 48
    t.append(_StaticEntry(String("proxy-authorization"), String("")))  # idx 49
    t.append(_StaticEntry(String("range"), String("")))  # idx 50
    t.append(_StaticEntry(String("referer"), String("")))  # idx 51
    t.append(_StaticEntry(String("refresh"), String("")))  # idx 52
    t.append(_StaticEntry(String("retry-after"), String("")))  # idx 53
    t.append(_StaticEntry(String("server"), String("")))  # idx 54
    t.append(_StaticEntry(String("set-cookie"), String("")))  # idx 55
    t.append(_StaticEntry(String("strict-transport-security"), String("")))  # idx 56
    t.append(_StaticEntry(String("transfer-encoding"), String("")))  # idx 57
    t.append(_StaticEntry(String("user-agent"), String("")))  # idx 58
    t.append(_StaticEntry(String("vary"), String("")))  # idx 59
    t.append(_StaticEntry(String("via"), String("")))  # idx 60
    t.append(_StaticEntry(String("www-authenticate"), String("")))  # idx 61

    return t^


# ============================================================================
# Huffman code-point table — RFC 7541 Appendix B
# ============================================================================


def _huffman_codes() -> List[Tuple[UInt32, UInt8]]:
    var t = List[Tuple[UInt32, UInt8]]()
    t.append((UInt32(0x1ff8), UInt8(13)))  # sym 0
    t.append((UInt32(0x7fffd8), UInt8(23)))  # sym 1
    t.append((UInt32(0xfffffe2), UInt8(28)))  # sym 2
    t.append((UInt32(0xfffffe3), UInt8(28)))  # sym 3
    t.append((UInt32(0xfffffe4), UInt8(28)))  # sym 4
    t.append((UInt32(0xfffffe5), UInt8(28)))  # sym 5
    t.append((UInt32(0xfffffe6), UInt8(28)))  # sym 6
    t.append((UInt32(0xfffffe7), UInt8(28)))  # sym 7
    t.append((UInt32(0xfffffe8), UInt8(28)))  # sym 8
    t.append((UInt32(0xffffea), UInt8(24)))  # sym 9
    t.append((UInt32(0x3ffffffc), UInt8(30)))  # sym 10
    t.append((UInt32(0xfffffe9), UInt8(28)))  # sym 11
    t.append((UInt32(0xfffffea), UInt8(28)))  # sym 12
    t.append((UInt32(0x3ffffffd), UInt8(30)))  # sym 13
    t.append((UInt32(0xfffffeb), UInt8(28)))  # sym 14
    t.append((UInt32(0xfffffec), UInt8(28)))  # sym 15
    t.append((UInt32(0xfffffed), UInt8(28)))  # sym 16
    t.append((UInt32(0xfffffee), UInt8(28)))  # sym 17
    t.append((UInt32(0xfffffef), UInt8(28)))  # sym 18
    t.append((UInt32(0xffffff0), UInt8(28)))  # sym 19
    t.append((UInt32(0xffffff1), UInt8(28)))  # sym 20
    t.append((UInt32(0xffffff2), UInt8(28)))  # sym 21
    t.append((UInt32(0x3ffffffe), UInt8(30)))  # sym 22
    t.append((UInt32(0xffffff3), UInt8(28)))  # sym 23
    t.append((UInt32(0xffffff4), UInt8(28)))  # sym 24
    t.append((UInt32(0xffffff5), UInt8(28)))  # sym 25
    t.append((UInt32(0xffffff6), UInt8(28)))  # sym 26
    t.append((UInt32(0xffffff7), UInt8(28)))  # sym 27
    t.append((UInt32(0xffffff8), UInt8(28)))  # sym 28
    t.append((UInt32(0xffffff9), UInt8(28)))  # sym 29
    t.append((UInt32(0xffffffa), UInt8(28)))  # sym 30
    t.append((UInt32(0xffffffb), UInt8(28)))  # sym 31
    t.append((UInt32(0x14), UInt8(6)))  # sym 32
    t.append((UInt32(0x3f8), UInt8(10)))  # sym 33
    t.append((UInt32(0x3f9), UInt8(10)))  # sym 34
    t.append((UInt32(0xffa), UInt8(12)))  # sym 35
    t.append((UInt32(0x1ff9), UInt8(13)))  # sym 36
    t.append((UInt32(0x15), UInt8(6)))  # sym 37
    t.append((UInt32(0xf8), UInt8(8)))  # sym 38
    t.append((UInt32(0x7fa), UInt8(11)))  # sym 39
    t.append((UInt32(0x3fa), UInt8(10)))  # sym 40
    t.append((UInt32(0x3fb), UInt8(10)))  # sym 41
    t.append((UInt32(0xf9), UInt8(8)))  # sym 42
    t.append((UInt32(0x7fb), UInt8(11)))  # sym 43
    t.append((UInt32(0xfa), UInt8(8)))  # sym 44
    t.append((UInt32(0x16), UInt8(6)))  # sym 45
    t.append((UInt32(0x17), UInt8(6)))  # sym 46
    t.append((UInt32(0x18), UInt8(6)))  # sym 47
    t.append((UInt32(0x0), UInt8(5)))  # sym 48
    t.append((UInt32(0x1), UInt8(5)))  # sym 49
    t.append((UInt32(0x2), UInt8(5)))  # sym 50
    t.append((UInt32(0x19), UInt8(6)))  # sym 51
    t.append((UInt32(0x1a), UInt8(6)))  # sym 52
    t.append((UInt32(0x1b), UInt8(6)))  # sym 53
    t.append((UInt32(0x1c), UInt8(6)))  # sym 54
    t.append((UInt32(0x1d), UInt8(6)))  # sym 55
    t.append((UInt32(0x1e), UInt8(6)))  # sym 56
    t.append((UInt32(0x1f), UInt8(6)))  # sym 57
    t.append((UInt32(0x5c), UInt8(7)))  # sym 58
    t.append((UInt32(0xfb), UInt8(8)))  # sym 59
    t.append((UInt32(0x7ffc), UInt8(15)))  # sym 60
    t.append((UInt32(0x20), UInt8(6)))  # sym 61
    t.append((UInt32(0xffb), UInt8(12)))  # sym 62
    t.append((UInt32(0x3fc), UInt8(10)))  # sym 63
    t.append((UInt32(0x1ffa), UInt8(13)))  # sym 64
    t.append((UInt32(0x21), UInt8(6)))  # sym 65
    t.append((UInt32(0x5d), UInt8(7)))  # sym 66
    t.append((UInt32(0x5e), UInt8(7)))  # sym 67
    t.append((UInt32(0x5f), UInt8(7)))  # sym 68
    t.append((UInt32(0x60), UInt8(7)))  # sym 69
    t.append((UInt32(0x61), UInt8(7)))  # sym 70
    t.append((UInt32(0x62), UInt8(7)))  # sym 71
    t.append((UInt32(0x63), UInt8(7)))  # sym 72
    t.append((UInt32(0x64), UInt8(7)))  # sym 73
    t.append((UInt32(0x65), UInt8(7)))  # sym 74
    t.append((UInt32(0x66), UInt8(7)))  # sym 75
    t.append((UInt32(0x67), UInt8(7)))  # sym 76
    t.append((UInt32(0x68), UInt8(7)))  # sym 77
    t.append((UInt32(0x69), UInt8(7)))  # sym 78
    t.append((UInt32(0x6a), UInt8(7)))  # sym 79
    t.append((UInt32(0x6b), UInt8(7)))  # sym 80
    t.append((UInt32(0x6c), UInt8(7)))  # sym 81
    t.append((UInt32(0x6d), UInt8(7)))  # sym 82
    t.append((UInt32(0x6e), UInt8(7)))  # sym 83
    t.append((UInt32(0x6f), UInt8(7)))  # sym 84
    t.append((UInt32(0x70), UInt8(7)))  # sym 85
    t.append((UInt32(0x71), UInt8(7)))  # sym 86
    t.append((UInt32(0x72), UInt8(7)))  # sym 87
    t.append((UInt32(0xfc), UInt8(8)))  # sym 88
    t.append((UInt32(0x73), UInt8(7)))  # sym 89
    t.append((UInt32(0xfd), UInt8(8)))  # sym 90
    t.append((UInt32(0x1ffb), UInt8(13)))  # sym 91
    t.append((UInt32(0x7fff0), UInt8(19)))  # sym 92
    t.append((UInt32(0x1ffc), UInt8(13)))  # sym 93
    t.append((UInt32(0x3ffc), UInt8(14)))  # sym 94
    t.append((UInt32(0x22), UInt8(6)))  # sym 95
    t.append((UInt32(0x7ffd), UInt8(15)))  # sym 96
    t.append((UInt32(0x3), UInt8(5)))  # sym 97
    t.append((UInt32(0x23), UInt8(6)))  # sym 98
    t.append((UInt32(0x4), UInt8(5)))  # sym 99
    t.append((UInt32(0x24), UInt8(6)))  # sym 100
    t.append((UInt32(0x5), UInt8(5)))  # sym 101
    t.append((UInt32(0x25), UInt8(6)))  # sym 102
    t.append((UInt32(0x26), UInt8(6)))  # sym 103
    t.append((UInt32(0x27), UInt8(6)))  # sym 104
    t.append((UInt32(0x6), UInt8(5)))  # sym 105
    t.append((UInt32(0x74), UInt8(7)))  # sym 106
    t.append((UInt32(0x75), UInt8(7)))  # sym 107
    t.append((UInt32(0x28), UInt8(6)))  # sym 108
    t.append((UInt32(0x29), UInt8(6)))  # sym 109
    t.append((UInt32(0x2a), UInt8(6)))  # sym 110
    t.append((UInt32(0x7), UInt8(5)))  # sym 111
    t.append((UInt32(0x2b), UInt8(6)))  # sym 112
    t.append((UInt32(0x76), UInt8(7)))  # sym 113
    t.append((UInt32(0x2c), UInt8(6)))  # sym 114
    t.append((UInt32(0x8), UInt8(5)))  # sym 115
    t.append((UInt32(0x9), UInt8(5)))  # sym 116
    t.append((UInt32(0x2d), UInt8(6)))  # sym 117
    t.append((UInt32(0x77), UInt8(7)))  # sym 118
    t.append((UInt32(0x78), UInt8(7)))  # sym 119
    t.append((UInt32(0x79), UInt8(7)))  # sym 120
    t.append((UInt32(0x7a), UInt8(7)))  # sym 121
    t.append((UInt32(0x7b), UInt8(7)))  # sym 122
    t.append((UInt32(0x7ffe), UInt8(15)))  # sym 123
    t.append((UInt32(0x7fc), UInt8(11)))  # sym 124
    t.append((UInt32(0x3ffd), UInt8(14)))  # sym 125
    t.append((UInt32(0x1ffd), UInt8(13)))  # sym 126
    t.append((UInt32(0xffffffc), UInt8(28)))  # sym 127
    t.append((UInt32(0xfffe6), UInt8(20)))  # sym 128
    t.append((UInt32(0x3fffd2), UInt8(22)))  # sym 129
    t.append((UInt32(0xfffe7), UInt8(20)))  # sym 130
    t.append((UInt32(0xfffe8), UInt8(20)))  # sym 131
    t.append((UInt32(0x3fffd3), UInt8(22)))  # sym 132
    t.append((UInt32(0x3fffd4), UInt8(22)))  # sym 133
    t.append((UInt32(0x3fffd5), UInt8(22)))  # sym 134
    t.append((UInt32(0x7fffd9), UInt8(23)))  # sym 135
    t.append((UInt32(0x3fffd6), UInt8(22)))  # sym 136
    t.append((UInt32(0x7fffda), UInt8(23)))  # sym 137
    t.append((UInt32(0x7fffdb), UInt8(23)))  # sym 138
    t.append((UInt32(0x7fffdc), UInt8(23)))  # sym 139
    t.append((UInt32(0x7fffdd), UInt8(23)))  # sym 140
    t.append((UInt32(0x7fffde), UInt8(23)))  # sym 141
    t.append((UInt32(0xffffeb), UInt8(24)))  # sym 142
    t.append((UInt32(0x7fffdf), UInt8(23)))  # sym 143
    t.append((UInt32(0xffffec), UInt8(24)))  # sym 144
    t.append((UInt32(0xffffed), UInt8(24)))  # sym 145
    t.append((UInt32(0x3fffd7), UInt8(22)))  # sym 146
    t.append((UInt32(0x7fffe0), UInt8(23)))  # sym 147
    t.append((UInt32(0xffffee), UInt8(24)))  # sym 148
    t.append((UInt32(0x7fffe1), UInt8(23)))  # sym 149
    t.append((UInt32(0x7fffe2), UInt8(23)))  # sym 150
    t.append((UInt32(0x7fffe3), UInt8(23)))  # sym 151
    t.append((UInt32(0x7fffe4), UInt8(23)))  # sym 152
    t.append((UInt32(0x1fffdc), UInt8(21)))  # sym 153
    t.append((UInt32(0x3fffd8), UInt8(22)))  # sym 154
    t.append((UInt32(0x7fffe5), UInt8(23)))  # sym 155
    t.append((UInt32(0x3fffd9), UInt8(22)))  # sym 156
    t.append((UInt32(0x7fffe6), UInt8(23)))  # sym 157
    t.append((UInt32(0x7fffe7), UInt8(23)))  # sym 158
    t.append((UInt32(0xffffef), UInt8(24)))  # sym 159
    t.append((UInt32(0x3fffda), UInt8(22)))  # sym 160
    t.append((UInt32(0x1fffdd), UInt8(21)))  # sym 161
    t.append((UInt32(0xfffe9), UInt8(20)))  # sym 162
    t.append((UInt32(0x3fffdb), UInt8(22)))  # sym 163
    t.append((UInt32(0x3fffdc), UInt8(22)))  # sym 164
    t.append((UInt32(0x7fffe8), UInt8(23)))  # sym 165
    t.append((UInt32(0x7fffe9), UInt8(23)))  # sym 166
    t.append((UInt32(0x1fffde), UInt8(21)))  # sym 167
    t.append((UInt32(0x7fffea), UInt8(23)))  # sym 168
    t.append((UInt32(0x3fffdd), UInt8(22)))  # sym 169
    t.append((UInt32(0x3fffde), UInt8(22)))  # sym 170
    t.append((UInt32(0xfffff0), UInt8(24)))  # sym 171
    t.append((UInt32(0x1fffdf), UInt8(21)))  # sym 172
    t.append((UInt32(0x3fffdf), UInt8(22)))  # sym 173
    t.append((UInt32(0x7fffeb), UInt8(23)))  # sym 174
    t.append((UInt32(0x7fffec), UInt8(23)))  # sym 175
    t.append((UInt32(0x1fffe0), UInt8(21)))  # sym 176
    t.append((UInt32(0x1fffe1), UInt8(21)))  # sym 177
    t.append((UInt32(0x3fffe0), UInt8(22)))  # sym 178
    t.append((UInt32(0x1fffe2), UInt8(21)))  # sym 179
    t.append((UInt32(0x7fffed), UInt8(23)))  # sym 180
    t.append((UInt32(0x3fffe1), UInt8(22)))  # sym 181
    t.append((UInt32(0x7fffee), UInt8(23)))  # sym 182
    t.append((UInt32(0x7fffef), UInt8(23)))  # sym 183
    t.append((UInt32(0xfffea), UInt8(20)))  # sym 184
    t.append((UInt32(0x3fffe2), UInt8(22)))  # sym 185
    t.append((UInt32(0x3fffe3), UInt8(22)))  # sym 186
    t.append((UInt32(0x3fffe4), UInt8(22)))  # sym 187
    t.append((UInt32(0x7ffff0), UInt8(23)))  # sym 188
    t.append((UInt32(0x3fffe5), UInt8(22)))  # sym 189
    t.append((UInt32(0x3fffe6), UInt8(22)))  # sym 190
    t.append((UInt32(0x7ffff1), UInt8(23)))  # sym 191
    t.append((UInt32(0x3ffffe0), UInt8(26)))  # sym 192
    t.append((UInt32(0x3ffffe1), UInt8(26)))  # sym 193
    t.append((UInt32(0xfffeb), UInt8(20)))  # sym 194
    t.append((UInt32(0x7fff1), UInt8(19)))  # sym 195
    t.append((UInt32(0x3fffe7), UInt8(22)))  # sym 196
    t.append((UInt32(0x7ffff2), UInt8(23)))  # sym 197
    t.append((UInt32(0x3fffe8), UInt8(22)))  # sym 198
    t.append((UInt32(0x1ffffec), UInt8(25)))  # sym 199
    t.append((UInt32(0x3ffffe2), UInt8(26)))  # sym 200
    t.append((UInt32(0x3ffffe3), UInt8(26)))  # sym 201
    t.append((UInt32(0x3ffffe4), UInt8(26)))  # sym 202
    t.append((UInt32(0x7ffffde), UInt8(27)))  # sym 203
    t.append((UInt32(0x7ffffdf), UInt8(27)))  # sym 204
    t.append((UInt32(0x3ffffe5), UInt8(26)))  # sym 205
    t.append((UInt32(0xfffff1), UInt8(24)))  # sym 206
    t.append((UInt32(0x1ffffed), UInt8(25)))  # sym 207
    t.append((UInt32(0x7fff2), UInt8(19)))  # sym 208
    t.append((UInt32(0x1fffe3), UInt8(21)))  # sym 209
    t.append((UInt32(0x3ffffe6), UInt8(26)))  # sym 210
    t.append((UInt32(0x7ffffe0), UInt8(27)))  # sym 211
    t.append((UInt32(0x7ffffe1), UInt8(27)))  # sym 212
    t.append((UInt32(0x3ffffe7), UInt8(26)))  # sym 213
    t.append((UInt32(0x7ffffe2), UInt8(27)))  # sym 214
    t.append((UInt32(0xfffff2), UInt8(24)))  # sym 215
    t.append((UInt32(0x1fffe4), UInt8(21)))  # sym 216
    t.append((UInt32(0x1fffe5), UInt8(21)))  # sym 217
    t.append((UInt32(0x3ffffe8), UInt8(26)))  # sym 218
    t.append((UInt32(0x3ffffe9), UInt8(26)))  # sym 219
    t.append((UInt32(0xffffffd), UInt8(28)))  # sym 220
    t.append((UInt32(0x7ffffe3), UInt8(27)))  # sym 221
    t.append((UInt32(0x7ffffe4), UInt8(27)))  # sym 222
    t.append((UInt32(0x7ffffe5), UInt8(27)))  # sym 223
    t.append((UInt32(0xfffec), UInt8(20)))  # sym 224
    t.append((UInt32(0xfffff3), UInt8(24)))  # sym 225
    t.append((UInt32(0xfffed), UInt8(20)))  # sym 226
    t.append((UInt32(0x1fffe6), UInt8(21)))  # sym 227
    t.append((UInt32(0x3fffe9), UInt8(22)))  # sym 228
    t.append((UInt32(0x1fffe7), UInt8(21)))  # sym 229
    t.append((UInt32(0x1fffe8), UInt8(21)))  # sym 230
    t.append((UInt32(0x7ffff3), UInt8(23)))  # sym 231
    t.append((UInt32(0x3fffea), UInt8(22)))  # sym 232
    t.append((UInt32(0x3fffeb), UInt8(22)))  # sym 233
    t.append((UInt32(0x1ffffee), UInt8(25)))  # sym 234
    t.append((UInt32(0x1ffffef), UInt8(25)))  # sym 235
    t.append((UInt32(0xfffff4), UInt8(24)))  # sym 236
    t.append((UInt32(0xfffff5), UInt8(24)))  # sym 237
    t.append((UInt32(0x3ffffea), UInt8(26)))  # sym 238
    t.append((UInt32(0x7ffff4), UInt8(23)))  # sym 239
    t.append((UInt32(0x3ffffeb), UInt8(26)))  # sym 240
    t.append((UInt32(0x7ffffe6), UInt8(27)))  # sym 241
    t.append((UInt32(0x3ffffec), UInt8(26)))  # sym 242
    t.append((UInt32(0x3ffffed), UInt8(26)))  # sym 243
    t.append((UInt32(0x7ffffe7), UInt8(27)))  # sym 244
    t.append((UInt32(0x7ffffe8), UInt8(27)))  # sym 245
    t.append((UInt32(0x7ffffe9), UInt8(27)))  # sym 246
    t.append((UInt32(0x7ffffea), UInt8(27)))  # sym 247
    t.append((UInt32(0x7ffffeb), UInt8(27)))  # sym 248
    t.append((UInt32(0xffffffe), UInt8(28)))  # sym 249
    t.append((UInt32(0x7ffffec), UInt8(27)))  # sym 250
    t.append((UInt32(0x7ffffed), UInt8(27)))  # sym 251
    t.append((UInt32(0x7ffffee), UInt8(27)))  # sym 252
    t.append((UInt32(0x7ffffef), UInt8(27)))  # sym 253
    t.append((UInt32(0x7fffff0), UInt8(27)))  # sym 254
    t.append((UInt32(0x3ffffee), UInt8(26)))  # sym 255
    t.append((UInt32(0x3fffffff), UInt8(30)))  # sym 256

    return t^


# ============================================================================
# Huffman trie (one node per prefix). Divergence (b): bit-by-bit walk.
# ============================================================================


struct _TrieNode(Copyable, Movable):
    var symbol: Int  # -1 if internal node
    var left: Int    # child index for bit 0, -1 if none
    var right: Int   # child index for bit 1, -1 if none

    def __init__(out self, symbol: Int = -1):
        self.symbol = symbol
        self.left = -1
        self.right = -1

    def __init__(out self, *, deinit take: Self):
        self.symbol = take.symbol
        self.left = take.left
        self.right = take.right


def _build_trie() -> List[_TrieNode]:
    var trie = List[_TrieNode]()
    trie.append(_TrieNode())  # root at idx 0
    var codes = _huffman_codes()
    for sym in range(len(codes)):
        var entry = codes[sym]
        var code = entry[0]
        var nbits = Int(entry[1])
        var node_idx = 0
        for b in range(nbits):
            var bit = Int((code >> UInt32(nbits - 1 - b)) & UInt32(1))
            var child_idx: Int
            if bit == 0:
                child_idx = trie[node_idx].left
            else:
                child_idx = trie[node_idx].right
            if child_idx == -1:
                trie.append(_TrieNode())
                child_idx = len(trie) - 1
                if bit == 0:
                    trie[node_idx].left = child_idx
                else:
                    trie[node_idx].right = child_idx
            node_idx = child_idx
        trie[node_idx].symbol = sym
    return trie^


# ============================================================================
# Dynamic table — RFC 7541 §2.3.2 + §4.1
# ============================================================================


struct _DynEntry(Copyable, Movable):
    var name: String
    var value: String

    def __init__(out self, name: String, value: String):
        self.name = name
        self.value = value

    def __init__(out self, *, deinit take: Self):
        self.name = take.name^
        self.value = take.value^


struct _DynamicTable(Copyable, Movable):
    var entries: List[_DynEntry]  # FIFO: index 0 = newest
    var byte_size: Int
    var max_byte_size: Int

    def __init__(out self, max_size: Int):
        self.entries = List[_DynEntry]()
        self.byte_size = 0
        self.max_byte_size = max_size

    def __init__(out self, *, deinit take: Self):
        self.entries = take.entries^
        self.byte_size = take.byte_size
        self.max_byte_size = take.max_byte_size

    def insert(mut self, name: String, value: String):
        var entry_size = name.byte_length() + value.byte_length() + 32
        # Evict from the tail until we have room (or the new entry is too big).
        while self.byte_size + entry_size > self.max_byte_size and len(self.entries) > 0:
            var last = self.entries.pop()
            self.byte_size -= last.name.byte_length() + last.value.byte_length() + 32
        if entry_size > self.max_byte_size:
            # New entry too big; table ends empty per RFC §4.4.
            return
        # Prepend new entry (newest at index 0).
        var new_list = List[_DynEntry]()
        new_list.append(_DynEntry(name, value))
        for i in range(len(self.entries)):
            new_list.append(self.entries[i].copy())
        self.entries = new_list^
        self.byte_size += entry_size

    def set_max_size(mut self, new_max: Int):
        self.max_byte_size = new_max
        while self.byte_size > self.max_byte_size and len(self.entries) > 0:
            var last = self.entries.pop()
            self.byte_size -= last.name.byte_length() + last.value.byte_length() + 32

    def lookup(self, idx: Int) -> Tuple[String, String]:
        if idx < 0 or idx >= len(self.entries):
            return (String(""), String(""))
        var e = self.entries[idx].copy()
        return (e.name, e.value)


# ============================================================================
# Public config + decoder
# ============================================================================


struct HpackOracleConfig(Copyable, Movable):
    var max_header_table_size: Int
    var max_header_list_size: Int

    def __init__(out self, max_table: Int = 4096, max_list: Int = 65536):
        self.max_header_table_size = max_table
        self.max_header_list_size = max_list

    def __init__(out self, *, deinit take: Self):
        self.max_header_table_size = take.max_header_table_size
        self.max_header_list_size = take.max_header_list_size


struct HpackOracleDecoder(Movable):
    var dyn: _DynamicTable
    var trie: List[_TrieNode]
    var config: HpackOracleConfig

    def __init__(out self, config: HpackOracleConfig = HpackOracleConfig()):
        self.dyn = _DynamicTable(config.max_header_table_size)
        self.trie = _build_trie()
        self.config = config.copy()

    def __init__(out self, *, deinit take: Self):
        self.dyn = take.dyn^
        self.trie = take.trie^
        self.config = take.config^

    def decode(mut self, wire: List[UInt8]) -> Tuple[List[Header], String]:
        """Decode an HPACK header block. Returns (headers, error).
        Error is empty on success."""
        var headers = List[Header]()
        var pos = 0
        var past_updates = False
        var cumulative_size = 0
        while pos < len(wire):
            var first = wire[pos]
            # Divergence (a): explicit nested if/elif on top-bit patterns.
            if (Int(first) & 0x80) != 0:
                # 1xxxxxxx: indexed header field (RFC §6.1)
                past_updates = True
                var ir = decode_oracle_integer(wire, pos, 7)
                if ir.error.byte_length() > 0:
                    return (List[Header](), ir.error)
                pos += ir.consumed
                if ir.value == 0:
                    return (List[Header](), String("index 0 invalid"))
                var hdr = self._lookup(Int(ir.value))
                if hdr[0].byte_length() == 0 and hdr[1].byte_length() == 0:
                    return (List[Header](), String("invalid index ") + String(Int(ir.value)))
                headers.append(Header(hdr[0], hdr[1]))
                cumulative_size += hdr[0].byte_length() + hdr[1].byte_length() + 32
            elif (Int(first) & 0xC0) == 0x40:
                # 01xxxxxx: literal with incremental indexing (RFC §6.2.1)
                past_updates = True
                var lr = self._decode_literal(wire, pos, 6)
                if lr[3].byte_length() > 0:
                    return (List[Header](), lr[3])
                pos += lr[2]
                self.dyn.insert(lr[0], lr[1])
                headers.append(Header(lr[0], lr[1]))
                cumulative_size += lr[0].byte_length() + lr[1].byte_length() + 32
            elif (Int(first) & 0xE0) == 0x20:
                # 001xxxxx: dynamic table size update (RFC §6.3)
                if past_updates:
                    return (List[Header](), String("table size update after header"))
                var ir = decode_oracle_integer(wire, pos, 5)
                if ir.error.byte_length() > 0:
                    return (List[Header](), ir.error)
                pos += ir.consumed
                if Int(ir.value) > self.config.max_header_table_size:
                    return (List[Header](), String("table size update exceeds protocol limit"))
                self.dyn.set_max_size(Int(ir.value))
            elif (Int(first) & 0xF0) == 0x10:
                # 0001xxxx: literal never indexed (RFC §6.2.3)
                past_updates = True
                var lr = self._decode_literal(wire, pos, 4)
                if lr[3].byte_length() > 0:
                    return (List[Header](), lr[3])
                pos += lr[2]
                headers.append(Header(lr[0], lr[1]))
                cumulative_size += lr[0].byte_length() + lr[1].byte_length() + 32
            else:
                # 0000xxxx: literal without indexing (RFC §6.2.2)
                past_updates = True
                var lr = self._decode_literal(wire, pos, 4)
                if lr[3].byte_length() > 0:
                    return (List[Header](), lr[3])
                pos += lr[2]
                headers.append(Header(lr[0], lr[1]))
                cumulative_size += lr[0].byte_length() + lr[1].byte_length() + 32
            if cumulative_size > self.config.max_header_list_size:
                return (List[Header](), String("header list size exceeds maximum"))
        return (headers^, String(""))

    def set_max_table_size(mut self, new_max: Int):
        self.dyn.set_max_size(new_max)

    def _lookup(self, idx: Int) -> Tuple[String, String]:
        if idx <= 0:
            return (String(""), String(""))
        if idx <= 61:
            var st = _static_table()
            var e = st[idx - 1].copy()
            return (e.name, e.value)
        var dyn_idx = idx - 62
        return self.dyn.lookup(dyn_idx)

    def _decode_literal(
        mut self, wire: List[UInt8], pos: Int, prefix_bits: Int
    ) -> Tuple[String, String, Int, String]:
        var consumed = 0
        var ir = decode_oracle_integer(wire, pos, prefix_bits)
        if ir.error.byte_length() > 0:
            return (String(""), String(""), 0, ir.error)
        var name_idx = Int(ir.value)
        consumed += ir.consumed

        var name: String
        if name_idx > 0:
            var lookup = self._lookup(name_idx)
            name = lookup[0]
            if name.byte_length() == 0:
                return (String(""), String(""), 0, String("invalid name index ") + String(name_idx))
        else:
            var sr = self._decode_string(wire, pos + consumed)
            if sr[2].byte_length() > 0:
                return (String(""), String(""), 0, sr[2])
            name = sr[0]
            consumed += sr[1]

        var vr = self._decode_string(wire, pos + consumed)
        if vr[2].byte_length() > 0:
            return (String(""), String(""), 0, vr[2])
        var value = vr[0]
        consumed += vr[1]
        return (name^, value^, consumed, String(""))

    def _decode_string(
        self, wire: List[UInt8], pos: Int
    ) -> Tuple[String, Int, String]:
        if pos >= len(wire):
            return (String(""), 0, String("truncated string header"))
        var huff_flag = (Int(wire[pos]) & 0x80) != 0
        var lr = decode_oracle_integer(wire, pos, 7)
        if lr.error.byte_length() > 0:
            return (String(""), 0, lr.error)
        var str_len = Int(lr.value)
        var consumed = lr.consumed
        if pos + consumed + str_len > len(wire):
            return (String(""), 0, String("truncated string data"))
        var data_start = pos + consumed
        var data_end = data_start + str_len
        consumed += str_len

        if huff_flag:
            var raw = List[UInt8](capacity=str_len)
            for i in range(data_start, data_end):
                raw.append(wire[i])
            var decoded = self._huffman_decode(raw)
            if decoded[1].byte_length() > 0:
                return (String(""), 0, decoded[1])
            var s = String(unsafe_from_utf8=decoded[0])
            return (s^, consumed, String(""))
        else:
            var raw = List[UInt8](capacity=str_len)
            for i in range(data_start, data_end):
                raw.append(wire[i])
            var s = String(unsafe_from_utf8=raw)
            return (s^, consumed, String(""))

    def _huffman_decode(self, encoded: List[UInt8]) -> Tuple[List[UInt8], String]:
        # Divergence (b): 1-bit-at-a-time trie walk.
        var out = List[UInt8]()
        var node_idx = 0
        var total_bits = len(encoded) * 8
        var bit_pos = 0
        var last_emit_bit_pos = 0  # bit_pos right after the last full symbol emit
        while bit_pos < total_bits:
            var byte_idx = bit_pos // 8
            var bit_in_byte = 7 - (bit_pos % 8)
            var bit = Int((encoded[byte_idx] >> UInt8(bit_in_byte)) & UInt8(1))
            # Padding bits must all be 1 (most-significant bits of EOS). If we're
            # currently mid-code (node_idx != 0) and a 0 bit could land us inside
            # an invalid prefix, the trie walk will catch it; but for valid-prefix
            # partial codes with 0 bits, we'd accept invalid padding. So: every
            # bit consumed *after* the last emitted symbol must be 1 if it ends
            # up being padding. We enforce that retroactively at end-of-input.
            var child: Int
            if bit == 0:
                child = self.trie[node_idx].left
            else:
                child = self.trie[node_idx].right
            if child < 0:
                return (List[UInt8](), String("huffman: invalid prefix"))
            node_idx = child
            bit_pos += 1
            if self.trie[node_idx].symbol >= 0:
                if self.trie[node_idx].symbol == 256:  # EOS in non-padding context
                    # If EOS appears as a complete code (not trailing padding), per RFC §5.2
                    # this is a decoding error.
                    return (List[UInt8](), String("huffman: EOS symbol decoded"))
                out.append(UInt8(self.trie[node_idx].symbol))
                node_idx = 0
                last_emit_bit_pos = bit_pos
        # Final padding validation per RFC 7541 §5.2:
        #   - Padding length must be ≤ 7 bits.
        #   - Padding bits must be the most-significant bits of the EOS code
        #     (which are all 1s; EOS = 30 bits of 1s, so any prefix is all 1s).
        var pad_bits = total_bits - last_emit_bit_pos
        if pad_bits > 7:
            return (List[UInt8](), String("huffman: padding > 7 bits"))
        for i in range(last_emit_bit_pos, total_bits):
            var byte_idx = i // 8
            var bit_in_byte = 7 - (i % 8)
            var bit = Int((encoded[byte_idx] >> UInt8(bit_in_byte)) & UInt8(1))
            if bit != 1:
                return (List[UInt8](), String("huffman: invalid padding (must be all 1s)"))
        return (out^, String(""))
