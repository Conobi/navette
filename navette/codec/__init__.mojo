"""Wire-format codecs shared across HTTP/2 and HTTP/3."""

from .huffman import (
    HuffmanEntry,
    HuffTrieNode,
    HuffFastEntry,
    build_huffman_table,
    build_huffman_trie,
    build_huffman_fast,
    hpack_encode_string_into,
    huffman_encode_into,
    huffman_encoded_len,
    huffman_decode,
    huffman_decode_with_tables,
    HUFFMAN_EOS_CODE,
    HUFFMAN_EOS_BITS,
)
