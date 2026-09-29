# src/h2/hpack_huffman.mojo
#
# HPACK Huffman encoder/decoder (RFC 7541 Section 5.2 + Appendix B).
# Thin wrapper around navette.codec.huffman shared module.

from navette.codec.huffman import (
    HuffmanEntry,
    HuffTrieNode,
    build_huffman_table,
    build_huffman_trie_from,
    huffman_encode_into_bytes,
)
from navette.util.byte_string import bytes_to_string


struct HuffmanCodec(Movable):
    """HPACK Huffman encoder/decoder.

    Wraps the shared codec tables from navette.codec.huffman. Encoding
    is O(total_output_bits), decoding is O(total_input_bits) via
    bit-by-bit trie traversal.
    """

    var codes: List[HuffmanEntry]
    var _trie: List[HuffTrieNode]

    def __init__(out self):
        """Build the codec from the shared table."""
        self.codes = build_huffman_table()
        try:
            self._trie = build_huffman_trie_from(self.codes)
        except:
            self._trie = List[HuffTrieNode]()

    def encode(self, data: List[Byte]) -> List[Byte]:
        """Encode a byte sequence using HPACK Huffman coding."""
        var result = List[Byte]()
        huffman_encode_into_bytes(result, data, self.codes)
        return result^

    def encode_into(self, mut buf: List[Byte], data: List[Byte]):
        """Append HPACK Huffman-encoded bytes directly to buf."""
        huffman_encode_into_bytes(buf, data, self.codes)

    def decode(self, data: List[Byte]) -> Tuple[List[Byte], String]:
        """Decode Huffman-compressed bytes back to raw bytes."""
        var result = List[Byte]()

        if len(data) == 0:
            return (result^, String())

        var node_idx = 0
        var bits_since_last_symbol = 0
        var all_ones_since_last_symbol = True

        for ref b in data:
            for bit_pos in range(7, -1, -1):
                var bit = Int((b >> UInt8(bit_pos)) & 1)
                bits_since_last_symbol += 1
                if bit == 0:
                    all_ones_since_last_symbol = False
                    node_idx = self._trie[node_idx].left
                else:
                    node_idx = self._trie[node_idx].right

                if node_idx == -1:
                    return (result^, String("invalid Huffman code"))

                var sym = self._trie[node_idx].symbol
                if sym >= 0:
                    if sym == 256:
                        return (
                            result^,
                            String("EOS symbol in Huffman data"),
                        )
                    result.append(UInt8(sym))
                    node_idx = 0
                    bits_since_last_symbol = 0
                    all_ones_since_last_symbol = True

        if node_idx != 0:
            if bits_since_last_symbol > 7:
                return (result^, String("incomplete Huffman code"))
            if not all_ones_since_last_symbol:
                return (result^, String("invalid Huffman padding"))

        return (result^, String())
