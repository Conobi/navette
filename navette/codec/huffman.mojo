# codec/huffman.mojo
#
# Unified Huffman codec for RFC 7541 Appendix B, shared by HPACK (HTTP/2)
# and QPACK (HTTP/3). Both use the identical table per RFC 9204 §4.1.2.
#
# Provides: encode table, decode trie + 8-bit fast-path, encode/decode fns.

from navette.util.byte_string import bytes_to_string


comptime HUFFMAN_EOS_CODE: UInt32 = 0x3FFFFFFF
comptime HUFFMAN_EOS_BITS: UInt8 = 30


struct HuffmanEntry(Copyable, Movable):
    """One row of the RFC 7541 Appendix B Huffman table."""

    var code: UInt32
    var nbits: UInt8

    def __init__(out self, code: UInt32, nbits: UInt8):
        self.code = code
        self.nbits = nbits


struct HuffTrieNode(Copyable, Movable):
    """Flat-trie node for Huffman decoding.

    Internal nodes: symbol == -1, at least one child != -1.
    Leaf nodes: symbol in [0, 256], both children == -1.
    Symbol 256 is EOS.
    """

    var left: Int
    var right: Int
    var symbol: Int

    def __init__(out self):
        self.left = -1
        self.right = -1
        self.symbol = -1


struct HuffFastEntry(Copyable, Movable):
    """8-bit root fast-path entry for Huffman decoding.

    consumed in [1,8]: bits resolved by this entry.
    consumed == 0: no symbol resolves within 8 bits, fall through to trie.
    """

    var consumed: Int
    var symbol: Int

    def __init__(out self):
        self.consumed = 0
        self.symbol = 0


# ---------------------------------------------------------------------------
# Table construction — RFC 7541 Appendix B (256 byte symbols + EOS)
# ---------------------------------------------------------------------------


def build_huffman_table() -> List[HuffmanEntry]:
    """Return the 256-entry encode table from RFC 7541 Appendix B."""
    # RFC-frozen data as dense arrays — the signal is the hex codes and bit
    # lengths, not the scaffolding that loads them.
    var codes: InlineArray[UInt32, 256] = [
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    ]
    var nbits: InlineArray[UInt8, 256] = [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    ]
    var t = List[HuffmanEntry](capacity=256)
    for i in range(256):
        t.append(HuffmanEntry(codes[i], nbits[i]))
    return t^


# ---------------------------------------------------------------------------
# Trie construction
# ---------------------------------------------------------------------------


def build_huffman_trie() raises -> List[HuffTrieNode]:
    """Build a flat decode trie from the RFC 7541 Appendix B table.

    Includes EOS (symbol 256) so explicit EOS in the stream is detected.
    """
    var encode = build_huffman_table()
    return build_huffman_trie_from(encode)


def build_huffman_trie_from(ref encode: List[HuffmanEntry]) raises -> List[HuffTrieNode]:
    """Build a flat decode trie from a pre-built encode table."""
    var trie = List[HuffTrieNode]()
    trie.append(HuffTrieNode())

    for sym in range(256):
        var code = encode[sym].code
        var nbits = Int(encode[sym].nbits)
        var node_idx = 0
        for bit_pos in range(nbits - 1, -1, -1):
            var bit = Int((code >> UInt32(bit_pos)) & UInt32(1))
            if bit == 0:
                if trie[node_idx].left == -1:
                    trie[node_idx].left = len(trie)
                    trie.append(HuffTrieNode())
                node_idx = trie[node_idx].left
            else:
                if trie[node_idx].right == -1:
                    trie[node_idx].right = len(trie)
                    trie.append(HuffTrieNode())
                node_idx = trie[node_idx].right
        trie[node_idx].symbol = sym

    # EOS leaf (symbol 256)
    var eos_code = HUFFMAN_EOS_CODE
    var eos_nbits = Int(HUFFMAN_EOS_BITS)
    var node_idx = 0
    for bit_pos in range(eos_nbits - 1, -1, -1):
        var bit = Int((eos_code >> UInt32(bit_pos)) & UInt32(1))
        if bit == 0:
            if trie[node_idx].left == -1:
                trie[node_idx].left = len(trie)
                trie.append(HuffTrieNode())
            node_idx = trie[node_idx].left
        else:
            if trie[node_idx].right == -1:
                trie[node_idx].right = len(trie)
                trie.append(HuffTrieNode())
            node_idx = trie[node_idx].right
    trie[node_idx].symbol = 256

    return trie^


def build_huffman_fast(ref trie: List[HuffTrieNode]) -> List[HuffFastEntry]:
    """Build a 256-entry 8-bit root fast-path lookup table.

    For each top-byte, walk the trie up to 8 bits. If a leaf is reached,
    record (consumed, symbol). Otherwise fall through to bit-by-bit.
    """
    var fast = List[HuffFastEntry]()
    for b in range(256):
        var node_idx = 0
        var entry = HuffFastEntry()
        for bit_pos in range(7, -1, -1):
            var bit = Int((b >> bit_pos) & 1)
            if bit == 0:
                node_idx = trie[node_idx].left
            else:
                node_idx = trie[node_idx].right
            if node_idx < 0:
                break
            var sym = trie[node_idx].symbol
            if sym >= 0:
                if sym <= 255:
                    entry.consumed = 8 - bit_pos
                    entry.symbol = sym
                break
        fast.append(HuffFastEntry(copy=entry))
    return fast^


# ---------------------------------------------------------------------------
# HPACK/QPACK string literal encode/decode (RFC 7541 §5.2)
# ---------------------------------------------------------------------------


def hpack_encode_string_into(
    mut buf: List[Byte],
    s: String,
    use_huffman: Bool,
    ref table: List[HuffmanEntry],
) raises:
    """Encode an HPACK/QPACK string literal (RFC 7541 §5.2), appending to buf.

    Shared by HPACK and QPACK: Huffman flag in high bit of the 7-bit
    prefix-encoded length, followed by raw or Huffman-encoded payload.
    """
    from navette.quic.codec import hpack_encode_int_at

    if use_huffman:
        var huff_len = huffman_encoded_len(s, table)
        var idx = len(buf)
        buf.resize(idx + 6, Byte(0))
        buf[idx] = UInt8(0x80)
        var n = hpack_encode_int_at(buf, idx, huff_len, 7)
        buf.resize(idx + n, Byte(0))
        huffman_encode_into(buf, s, table)
    else:
        var raw = s.as_bytes()
        var idx = len(buf)
        buf.resize(idx + 6, Byte(0))
        var n = hpack_encode_int_at(buf, idx, len(raw), 7)
        buf.resize(idx + n, Byte(0))
        buf.extend(Span(raw))


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def huffman_encode_into(mut buf: List[Byte], s: String, ref table: List[HuffmanEntry]) raises:
    """Huffman-encode a string using a pre-built table, appending to buf."""
    var acc: UInt64 = 0
    var bits: Int = 0
    var sbytes = s.as_bytes()

    for ref byte in sbytes:
        var sym = Int(byte)
        if sym >= len(table):
            raise "Huffman: symbol out of range: " + String(sym)
        acc = (acc << UInt64(table[sym].nbits)) | UInt64(table[sym].code)
        bits += Int(table[sym].nbits)
        while bits >= 8:
            bits -= 8
            buf.append(UInt8((acc >> UInt64(bits)) & 0xFF))

    if bits > 0:
        var pad_bits_count = 8 - bits
        var pad = UInt8(((UInt32(1) << UInt32(pad_bits_count)) - 1) & 0xFF)
        var last_byte = UInt8((acc << UInt64(pad_bits_count)) & 0xFF) | pad
        buf.append(last_byte)


def huffman_encode_into_bytes(mut buf: List[Byte], data: List[Byte], ref table: List[HuffmanEntry]):
    """Huffman-encode raw bytes using a pre-built table, appending to buf."""
    var acc: UInt64 = 0
    var bits: Int = 0

    for ref byte in data:
        var sym = Int(byte)
        var code = UInt64(table[sym].code)
        var length = Int(table[sym].nbits)
        acc = (acc << UInt64(length)) | code
        bits += length
        while bits >= 8:
            bits -= 8
            buf.append(UInt8((acc >> UInt64(bits)) & 0xFF))

    if bits > 0:
        var pad = 8 - bits
        acc = (acc << UInt64(pad)) | UInt64((1 << pad) - 1)
        buf.append(UInt8(acc & 0xFF))


def huffman_encoded_len(s: String, ref table: List[HuffmanEntry]) raises -> Int:
    """Compute Huffman byte length without materializing the encoding."""
    var total_bits: Int = 0
    var sbytes = s.as_bytes()
    for ref byte in sbytes:
        var sym = Int(byte)
        if sym >= len(table):
            raise "Huffman: symbol out of range: " + String(sym)
        total_bits += Int(table[sym].nbits)
    return (total_bits + 7) // 8


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------


def huffman_decode_with_tables(
    ref data: List[Byte],
    ref trie: List[HuffTrieNode],
    ref fast: List[HuffFastEntry],
) raises -> String:
    """Decode Huffman-compressed bytes using pre-built tables.

    Uses 8-bit fast-path for codes <= 8 bits, bit-by-bit trie for longer.
    Caller passes precomputed tables for amortization across multiple decodes.
    """
    if len(data) == 0:
        return String("")
    var buf = List[Byte](capacity=len(data) * 2)

    var acc: UInt64 = 0
    var acc_bits: Int = 0
    var pos: Int = 0
    var data_len = len(data)
    var node: Int = 0

    var bits_since_root: Int = 0
    var all_ones_since_root: Bool = True

    while True:
        while acc_bits <= 56 and pos < data_len:
            acc = (acc << 8) | UInt64(data[pos])
            acc_bits += 8
            pos += 1

        if node == 0 and acc_bits >= 8:
            var top8 = Int((acc >> UInt64(acc_bits - 8)) & UInt64(0xFF))
            if fast[top8].consumed > 0:
                buf.append(UInt8(fast[top8].symbol))
                acc_bits -= fast[top8].consumed
                bits_since_root = 0
                all_ones_since_root = True
                continue

        if acc_bits == 0:
            if node == 0:
                return bytes_to_string(buf^)
            if bits_since_root > 7:
                raise "Huffman: truncated input (mid-symbol at EOF)"
            if not all_ones_since_root:
                raise "Huffman: invalid padding (not all-ones)"
            return bytes_to_string(buf^)

        var bit = Int((acc >> UInt64(acc_bits - 1)) & UInt64(1))
        acc_bits -= 1
        bits_since_root += 1
        if bit == 0:
            all_ones_since_root = False
            node = trie[node].left
        else:
            node = trie[node].right
        if node < 0:
            raise "Huffman: invalid code (no trie edge)"

        var sym = trie[node].symbol
        if sym >= 0:
            if sym == 256:
                raise "Huffman: explicit EOS in stream"
            buf.append(UInt8(sym))
            node = 0
            bits_since_root = 0
            all_ones_since_root = True


def huffman_decode(data: List[Byte]) raises -> String:
    """Huffman-decode bytes per RFC 7541 §5.2 (convenience, builds tables)."""
    if len(data) == 0:
        return String("")
    var table = build_huffman_table()
    var trie = build_huffman_trie_from(table)
    var fast = build_huffman_fast(trie)
    return huffman_decode_with_tables(data, trie, fast)
