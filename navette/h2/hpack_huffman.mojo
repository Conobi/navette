# src/h2/hpack_huffman.mojo
#
# HPACK Huffman encoder/decoder (RFC 7541 Section 5.2 + Appendix B).
#
# Encodes byte sequences using the static Huffman table defined in
# RFC 7541 Appendix B, and decodes Huffman-compressed bytes back to
# raw bytes using a bit-by-bit trie traversal.


struct _TrieNode(Copyable, Movable):
    """A single node in the Huffman decode trie.

    Internal nodes have symbol == -1 and at least one child != -1.
    Leaf nodes have symbol in [0, 256] and both children == -1.
    Symbol 256 is EOS (end-of-stream).
    """

    var left: Int  # child index for bit 0 (-1 = none)
    var right: Int  # child index for bit 1 (-1 = none)
    var symbol: Int  # -1 = internal, 0-256 = leaf (256 = EOS)

    def __init__(out self):
        self.left = -1
        self.right = -1
        self.symbol = -1

    def __init__(out self, *, deinit take: Self):
        self.left = take.left
        self.right = take.right
        self.symbol = take.symbol

    def __init__(out self, *, read copy: Self):
        self.left = copy.left
        self.right = copy.right
        self.symbol = copy.symbol


struct HuffmanCodec(Movable):
    """HPACK Huffman encoder/decoder.

    Stores all 257 Huffman codes from RFC 7541 Appendix B and a decode
    trie built at construction time. Encoding is O(total_output_bits),
    decoding is O(total_input_bits) via bit-by-bit trie traversal.
    """

    var codes: List[UInt32]  # 257 entries: code bits for each symbol
    var code_lengths: List[UInt8]  # 257 entries: bit length of each code
    var _trie: List[_TrieNode]  # flat trie for decoding

    def __init__(out self):
        """Build the codec: populate codes and construct the decode trie."""
        self.codes = List[UInt32]()
        self.code_lengths = List[UInt8]()
        self._trie = List[_TrieNode]()

        self._init_codes()
        self._build_trie()

    def __init__(out self, *, deinit take: Self):
        self.codes = take.codes^
        self.code_lengths = take.code_lengths^
        self._trie = take._trie^

    def _init_codes(mut self):
        """Populate all 257 Huffman codes from RFC 7541 Appendix B."""
        # Pre-size lists
        for _ in range(257):
            self.codes.append(UInt32(0))
            self.code_lengths.append(UInt8(0))

        # Symbol 0-31 (control characters)
        self.codes[0] = 0x1FF8;       self.code_lengths[0] = 13
        self.codes[1] = 0x7FFFD8;     self.code_lengths[1] = 23
        self.codes[2] = 0xFFFFFE2;    self.code_lengths[2] = 28
        self.codes[3] = 0xFFFFFE3;    self.code_lengths[3] = 28
        self.codes[4] = 0xFFFFFE4;    self.code_lengths[4] = 28
        self.codes[5] = 0xFFFFFE5;    self.code_lengths[5] = 28
        self.codes[6] = 0xFFFFFE6;    self.code_lengths[6] = 28
        self.codes[7] = 0xFFFFFE7;    self.code_lengths[7] = 28
        self.codes[8] = 0xFFFFFE8;    self.code_lengths[8] = 28
        self.codes[9] = 0xFFFFEA;     self.code_lengths[9] = 24
        self.codes[10] = 0x3FFFFFFC;  self.code_lengths[10] = 30
        self.codes[11] = 0xFFFFFE9;   self.code_lengths[11] = 28
        self.codes[12] = 0xFFFFFEA;   self.code_lengths[12] = 28
        self.codes[13] = 0x3FFFFFFD;  self.code_lengths[13] = 30
        self.codes[14] = 0xFFFFFEB;   self.code_lengths[14] = 28
        self.codes[15] = 0xFFFFFEC;   self.code_lengths[15] = 28
        self.codes[16] = 0xFFFFFED;   self.code_lengths[16] = 28
        self.codes[17] = 0xFFFFFEE;   self.code_lengths[17] = 28
        self.codes[18] = 0xFFFFFEF;   self.code_lengths[18] = 28
        self.codes[19] = 0xFFFFFF0;   self.code_lengths[19] = 28
        self.codes[20] = 0xFFFFFF1;   self.code_lengths[20] = 28
        self.codes[21] = 0xFFFFFF2;   self.code_lengths[21] = 28
        self.codes[22] = 0x3FFFFFFE;  self.code_lengths[22] = 30
        self.codes[23] = 0xFFFFFF3;   self.code_lengths[23] = 28
        self.codes[24] = 0xFFFFFF4;   self.code_lengths[24] = 28
        self.codes[25] = 0xFFFFFF5;   self.code_lengths[25] = 28
        self.codes[26] = 0xFFFFFF6;   self.code_lengths[26] = 28
        self.codes[27] = 0xFFFFFF7;   self.code_lengths[27] = 28
        self.codes[28] = 0xFFFFFF8;   self.code_lengths[28] = 28
        self.codes[29] = 0xFFFFFF9;   self.code_lengths[29] = 28
        self.codes[30] = 0xFFFFFFA;   self.code_lengths[30] = 28
        self.codes[31] = 0xFFFFFFB;   self.code_lengths[31] = 28

        # Symbol 32-63 (printable ASCII starts)
        self.codes[32] = 0x14;    self.code_lengths[32] = 6
        self.codes[33] = 0x3F8;   self.code_lengths[33] = 10
        self.codes[34] = 0x3F9;   self.code_lengths[34] = 10
        self.codes[35] = 0xFFA;   self.code_lengths[35] = 12
        self.codes[36] = 0x1FF9;  self.code_lengths[36] = 13
        self.codes[37] = 0x15;    self.code_lengths[37] = 6
        self.codes[38] = 0xF8;    self.code_lengths[38] = 8
        self.codes[39] = 0x7FA;   self.code_lengths[39] = 11
        self.codes[40] = 0x3FA;   self.code_lengths[40] = 10
        self.codes[41] = 0x3FB;   self.code_lengths[41] = 10
        self.codes[42] = 0xF9;    self.code_lengths[42] = 8
        self.codes[43] = 0x7FB;   self.code_lengths[43] = 11
        self.codes[44] = 0xFA;    self.code_lengths[44] = 8
        self.codes[45] = 0x16;    self.code_lengths[45] = 6
        self.codes[46] = 0x17;    self.code_lengths[46] = 6
        self.codes[47] = 0x18;    self.code_lengths[47] = 6
        self.codes[48] = 0x0;     self.code_lengths[48] = 5
        self.codes[49] = 0x1;     self.code_lengths[49] = 5
        self.codes[50] = 0x2;     self.code_lengths[50] = 5
        self.codes[51] = 0x19;    self.code_lengths[51] = 6
        self.codes[52] = 0x1A;    self.code_lengths[52] = 6
        self.codes[53] = 0x1B;    self.code_lengths[53] = 6
        self.codes[54] = 0x1C;    self.code_lengths[54] = 6
        self.codes[55] = 0x1D;    self.code_lengths[55] = 6
        self.codes[56] = 0x1E;    self.code_lengths[56] = 6
        self.codes[57] = 0x1F;    self.code_lengths[57] = 6
        self.codes[58] = 0x5C;    self.code_lengths[58] = 7
        self.codes[59] = 0xFB;    self.code_lengths[59] = 8
        self.codes[60] = 0x7FFC;  self.code_lengths[60] = 15
        self.codes[61] = 0x20;    self.code_lengths[61] = 6
        self.codes[62] = 0xFFB;   self.code_lengths[62] = 12
        self.codes[63] = 0x3FC;   self.code_lengths[63] = 10

        # Symbol 64-95
        self.codes[64] = 0x1FFA;  self.code_lengths[64] = 13
        self.codes[65] = 0x21;    self.code_lengths[65] = 6
        self.codes[66] = 0x5D;    self.code_lengths[66] = 7
        self.codes[67] = 0x5E;    self.code_lengths[67] = 7
        self.codes[68] = 0x5F;    self.code_lengths[68] = 7
        self.codes[69] = 0x60;    self.code_lengths[69] = 7
        self.codes[70] = 0x61;    self.code_lengths[70] = 7
        self.codes[71] = 0x62;    self.code_lengths[71] = 7
        self.codes[72] = 0x63;    self.code_lengths[72] = 7
        self.codes[73] = 0x64;    self.code_lengths[73] = 7
        self.codes[74] = 0x65;    self.code_lengths[74] = 7
        self.codes[75] = 0x66;    self.code_lengths[75] = 7
        self.codes[76] = 0x67;    self.code_lengths[76] = 7
        self.codes[77] = 0x68;    self.code_lengths[77] = 7
        self.codes[78] = 0x69;    self.code_lengths[78] = 7
        self.codes[79] = 0x6A;    self.code_lengths[79] = 7
        self.codes[80] = 0x6B;    self.code_lengths[80] = 7
        self.codes[81] = 0x6C;    self.code_lengths[81] = 7
        self.codes[82] = 0x6D;    self.code_lengths[82] = 7
        self.codes[83] = 0x6E;    self.code_lengths[83] = 7
        self.codes[84] = 0x6F;    self.code_lengths[84] = 7
        self.codes[85] = 0x70;    self.code_lengths[85] = 7
        self.codes[86] = 0x71;    self.code_lengths[86] = 7
        self.codes[87] = 0x72;    self.code_lengths[87] = 7
        self.codes[88] = 0xFC;    self.code_lengths[88] = 8
        self.codes[89] = 0x73;    self.code_lengths[89] = 7
        self.codes[90] = 0xFD;    self.code_lengths[90] = 8
        self.codes[91] = 0x1FFB;  self.code_lengths[91] = 13
        self.codes[92] = 0x7FFF0; self.code_lengths[92] = 19
        self.codes[93] = 0x1FFC;  self.code_lengths[93] = 13
        self.codes[94] = 0x3FFC;  self.code_lengths[94] = 14
        self.codes[95] = 0x22;    self.code_lengths[95] = 6

        # Symbol 96-127
        self.codes[96] = 0x7FFD;   self.code_lengths[96] = 15
        self.codes[97] = 0x3;      self.code_lengths[97] = 5
        self.codes[98] = 0x23;     self.code_lengths[98] = 6
        self.codes[99] = 0x4;      self.code_lengths[99] = 5
        self.codes[100] = 0x24;    self.code_lengths[100] = 6
        self.codes[101] = 0x5;     self.code_lengths[101] = 5
        self.codes[102] = 0x25;    self.code_lengths[102] = 6
        self.codes[103] = 0x26;    self.code_lengths[103] = 6
        self.codes[104] = 0x27;    self.code_lengths[104] = 6
        self.codes[105] = 0x6;     self.code_lengths[105] = 5
        self.codes[106] = 0x74;    self.code_lengths[106] = 7
        self.codes[107] = 0x75;    self.code_lengths[107] = 7
        self.codes[108] = 0x28;    self.code_lengths[108] = 6
        self.codes[109] = 0x29;    self.code_lengths[109] = 6
        self.codes[110] = 0x2A;    self.code_lengths[110] = 6
        self.codes[111] = 0x7;     self.code_lengths[111] = 5
        self.codes[112] = 0x2B;    self.code_lengths[112] = 6
        self.codes[113] = 0x76;    self.code_lengths[113] = 7
        self.codes[114] = 0x2C;    self.code_lengths[114] = 6
        self.codes[115] = 0x8;     self.code_lengths[115] = 5
        self.codes[116] = 0x9;     self.code_lengths[116] = 5
        self.codes[117] = 0x2D;    self.code_lengths[117] = 6
        self.codes[118] = 0x77;    self.code_lengths[118] = 7
        self.codes[119] = 0x78;    self.code_lengths[119] = 7
        self.codes[120] = 0x79;    self.code_lengths[120] = 7
        self.codes[121] = 0x7A;    self.code_lengths[121] = 7
        self.codes[122] = 0x7B;    self.code_lengths[122] = 7
        self.codes[123] = 0x7FFE;  self.code_lengths[123] = 15
        self.codes[124] = 0x7FC;   self.code_lengths[124] = 11
        self.codes[125] = 0x3FFD;  self.code_lengths[125] = 14
        self.codes[126] = 0x1FFD;  self.code_lengths[126] = 13
        self.codes[127] = 0xFFFFFFC; self.code_lengths[127] = 28

        # Symbol 128-255 + EOS (256) — same as original
        self.codes[128] = 0xFFFE6;   self.code_lengths[128] = 20
        self.codes[129] = 0x3FFFD2;  self.code_lengths[129] = 22
        self.codes[130] = 0xFFFE7;   self.code_lengths[130] = 20
        self.codes[131] = 0xFFFE8;   self.code_lengths[131] = 20
        self.codes[132] = 0x3FFFD3;  self.code_lengths[132] = 22
        self.codes[133] = 0x3FFFD4;  self.code_lengths[133] = 22
        self.codes[134] = 0x3FFFD5;  self.code_lengths[134] = 22
        self.codes[135] = 0x7FFFD9;  self.code_lengths[135] = 23
        self.codes[136] = 0x3FFFD6;  self.code_lengths[136] = 22
        self.codes[137] = 0x7FFFDA;  self.code_lengths[137] = 23
        self.codes[138] = 0x7FFFDB;  self.code_lengths[138] = 23
        self.codes[139] = 0x7FFFDC;  self.code_lengths[139] = 23
        self.codes[140] = 0x7FFFDD;  self.code_lengths[140] = 23
        self.codes[141] = 0x7FFFDE;  self.code_lengths[141] = 23
        self.codes[142] = 0xFFFFEB;  self.code_lengths[142] = 24
        self.codes[143] = 0x7FFFDF;  self.code_lengths[143] = 23
        self.codes[144] = 0xFFFFEC;  self.code_lengths[144] = 24
        self.codes[145] = 0xFFFFED;  self.code_lengths[145] = 24
        self.codes[146] = 0x3FFFD7;  self.code_lengths[146] = 22
        self.codes[147] = 0x7FFFE0;  self.code_lengths[147] = 23
        self.codes[148] = 0xFFFFEE;  self.code_lengths[148] = 24
        self.codes[149] = 0x7FFFE1;  self.code_lengths[149] = 23
        self.codes[150] = 0x7FFFE2;  self.code_lengths[150] = 23
        self.codes[151] = 0x7FFFE3;  self.code_lengths[151] = 23
        self.codes[152] = 0x7FFFE4;  self.code_lengths[152] = 23
        self.codes[153] = 0x1FFFDC;  self.code_lengths[153] = 21
        self.codes[154] = 0x3FFFD8;  self.code_lengths[154] = 22
        self.codes[155] = 0x7FFFE5;  self.code_lengths[155] = 23
        self.codes[156] = 0x3FFFD9;  self.code_lengths[156] = 22
        self.codes[157] = 0x7FFFE6;  self.code_lengths[157] = 23
        self.codes[158] = 0x7FFFE7;  self.code_lengths[158] = 23
        self.codes[159] = 0xFFFFEF;  self.code_lengths[159] = 24
        self.codes[160] = 0x3FFFDA;  self.code_lengths[160] = 22
        self.codes[161] = 0x1FFFDD;  self.code_lengths[161] = 21
        self.codes[162] = 0xFFFE9;   self.code_lengths[162] = 20
        self.codes[163] = 0x3FFFDB;  self.code_lengths[163] = 22
        self.codes[164] = 0x3FFFDC;  self.code_lengths[164] = 22
        self.codes[165] = 0x7FFFE8;  self.code_lengths[165] = 23
        self.codes[166] = 0x7FFFE9;  self.code_lengths[166] = 23
        self.codes[167] = 0x1FFFDE;  self.code_lengths[167] = 21
        self.codes[168] = 0x7FFFEA;  self.code_lengths[168] = 23
        self.codes[169] = 0x3FFFDD;  self.code_lengths[169] = 22
        self.codes[170] = 0x3FFFDE;  self.code_lengths[170] = 22
        self.codes[171] = 0xFFFFF0;  self.code_lengths[171] = 24
        self.codes[172] = 0x1FFFDF;  self.code_lengths[172] = 21
        self.codes[173] = 0x3FFFDF;  self.code_lengths[173] = 22
        self.codes[174] = 0x7FFFEB;  self.code_lengths[174] = 23
        self.codes[175] = 0x7FFFEC;  self.code_lengths[175] = 23
        self.codes[176] = 0x1FFFE0;  self.code_lengths[176] = 21
        self.codes[177] = 0x1FFFE1;  self.code_lengths[177] = 21
        self.codes[178] = 0x3FFFE0;  self.code_lengths[178] = 22
        self.codes[179] = 0x1FFFE2;  self.code_lengths[179] = 21
        self.codes[180] = 0x7FFFED;  self.code_lengths[180] = 23
        self.codes[181] = 0x3FFFE1;  self.code_lengths[181] = 22
        self.codes[182] = 0x7FFFEE;  self.code_lengths[182] = 23
        self.codes[183] = 0x7FFFEF;  self.code_lengths[183] = 23
        self.codes[184] = 0xFFFEA;   self.code_lengths[184] = 20
        self.codes[185] = 0x3FFFE2;  self.code_lengths[185] = 22
        self.codes[186] = 0x3FFFE3;  self.code_lengths[186] = 22
        self.codes[187] = 0x3FFFE4;  self.code_lengths[187] = 22
        self.codes[188] = 0x7FFFF0;  self.code_lengths[188] = 23
        self.codes[189] = 0x3FFFE5;  self.code_lengths[189] = 22
        self.codes[190] = 0x3FFFE6;  self.code_lengths[190] = 22
        self.codes[191] = 0x7FFFF1;  self.code_lengths[191] = 23
        self.codes[192] = 0x3FFFFE0;  self.code_lengths[192] = 26
        self.codes[193] = 0x3FFFFE1;  self.code_lengths[193] = 26
        self.codes[194] = 0xFFFEB;    self.code_lengths[194] = 20
        self.codes[195] = 0x7FFF1;    self.code_lengths[195] = 19
        self.codes[196] = 0x3FFFE7;   self.code_lengths[196] = 22
        self.codes[197] = 0x7FFFF2;   self.code_lengths[197] = 23
        self.codes[198] = 0x3FFFE8;   self.code_lengths[198] = 22
        self.codes[199] = 0x1FFFFEC;  self.code_lengths[199] = 25
        self.codes[200] = 0x3FFFFE2;  self.code_lengths[200] = 26
        self.codes[201] = 0x3FFFFE3;  self.code_lengths[201] = 26
        self.codes[202] = 0x3FFFFE4;  self.code_lengths[202] = 26
        self.codes[203] = 0x7FFFFDE;  self.code_lengths[203] = 27
        self.codes[204] = 0x7FFFFDF;  self.code_lengths[204] = 27
        self.codes[205] = 0x3FFFFE5;  self.code_lengths[205] = 26
        self.codes[206] = 0xFFFFF1;   self.code_lengths[206] = 24
        self.codes[207] = 0x1FFFFED;  self.code_lengths[207] = 25
        self.codes[208] = 0x7FFF2;    self.code_lengths[208] = 19
        self.codes[209] = 0x1FFFE3;   self.code_lengths[209] = 21
        self.codes[210] = 0x3FFFFE6;  self.code_lengths[210] = 26
        self.codes[211] = 0x7FFFFE0;  self.code_lengths[211] = 27
        self.codes[212] = 0x7FFFFE1;  self.code_lengths[212] = 27
        self.codes[213] = 0x3FFFFE7;  self.code_lengths[213] = 26
        self.codes[214] = 0x7FFFFE2;  self.code_lengths[214] = 27
        self.codes[215] = 0xFFFFF2;   self.code_lengths[215] = 24
        self.codes[216] = 0x1FFFE4;   self.code_lengths[216] = 21
        self.codes[217] = 0x1FFFE5;   self.code_lengths[217] = 21
        self.codes[218] = 0x3FFFFE8;  self.code_lengths[218] = 26
        self.codes[219] = 0x3FFFFE9;  self.code_lengths[219] = 26
        self.codes[220] = 0xFFFFFFD;  self.code_lengths[220] = 28
        self.codes[221] = 0x7FFFFE3;  self.code_lengths[221] = 27
        self.codes[222] = 0x7FFFFE4;  self.code_lengths[222] = 27
        self.codes[223] = 0x7FFFFE5;  self.code_lengths[223] = 27
        self.codes[224] = 0xFFFEC;    self.code_lengths[224] = 20
        self.codes[225] = 0xFFFFF3;   self.code_lengths[225] = 24
        self.codes[226] = 0xFFFED;    self.code_lengths[226] = 20
        self.codes[227] = 0x1FFFE6;   self.code_lengths[227] = 21
        self.codes[228] = 0x3FFFE9;   self.code_lengths[228] = 22
        self.codes[229] = 0x1FFFE7;   self.code_lengths[229] = 21
        self.codes[230] = 0x1FFFE8;   self.code_lengths[230] = 21
        self.codes[231] = 0x7FFFF3;   self.code_lengths[231] = 23
        self.codes[232] = 0x3FFFEA;   self.code_lengths[232] = 22
        self.codes[233] = 0x3FFFEB;   self.code_lengths[233] = 22
        self.codes[234] = 0x1FFFFEE;  self.code_lengths[234] = 25
        self.codes[235] = 0x1FFFFEF;  self.code_lengths[235] = 25
        self.codes[236] = 0xFFFFF4;   self.code_lengths[236] = 24
        self.codes[237] = 0xFFFFF5;   self.code_lengths[237] = 24
        self.codes[238] = 0x3FFFFEA;  self.code_lengths[238] = 26
        self.codes[239] = 0x7FFFF4;   self.code_lengths[239] = 23
        self.codes[240] = 0x3FFFFEB;  self.code_lengths[240] = 26
        self.codes[241] = 0x7FFFFE6;  self.code_lengths[241] = 27
        self.codes[242] = 0x3FFFFEC;  self.code_lengths[242] = 26
        self.codes[243] = 0x3FFFFED;  self.code_lengths[243] = 26
        self.codes[244] = 0x7FFFFE7;  self.code_lengths[244] = 27
        self.codes[245] = 0x7FFFFE8;  self.code_lengths[245] = 27
        self.codes[246] = 0x7FFFFE9;  self.code_lengths[246] = 27
        self.codes[247] = 0x7FFFFEA;  self.code_lengths[247] = 27
        self.codes[248] = 0x7FFFFEB;  self.code_lengths[248] = 27
        self.codes[249] = 0xFFFFFFE;  self.code_lengths[249] = 28
        self.codes[250] = 0x7FFFFEC;  self.code_lengths[250] = 27
        self.codes[251] = 0x7FFFFED;  self.code_lengths[251] = 27
        self.codes[252] = 0x7FFFFEE;  self.code_lengths[252] = 27
        self.codes[253] = 0x7FFFFEF;  self.code_lengths[253] = 27
        self.codes[254] = 0x7FFFFF0;  self.code_lengths[254] = 27
        self.codes[255] = 0x3FFFFEE;  self.code_lengths[255] = 26

        # Symbol 256 = EOS
        self.codes[256] = 0x3FFFFFFF; self.code_lengths[256] = 30

    def _build_trie(mut self):
        """Build a decode trie from the 257 Huffman codes."""
        self._trie.append(_TrieNode())

        for sym in range(257):
            var code = self.codes[sym]
            var length = Int(self.code_lengths[sym])
            var node_idx = 0

            for bit_pos in range(length - 1, -1, -1):
                var bit = Int((code >> UInt32(bit_pos)) & 1)

                if bit == 0:
                    if self._trie[node_idx].left == -1:
                        self._trie[node_idx].left = len(self._trie)
                        self._trie.append(_TrieNode())
                    node_idx = self._trie[node_idx].left
                else:
                    if self._trie[node_idx].right == -1:
                        self._trie[node_idx].right = len(self._trie)
                        self._trie.append(_TrieNode())
                    node_idx = self._trie[node_idx].right

            self._trie[node_idx].symbol = sym

    def encode(self, data: List[UInt8]) -> List[UInt8]:
        """Encode a byte sequence using HPACK Huffman coding."""
        var result = List[UInt8]()
        var current = UInt64(0)
        var bits = 0

        for i in range(len(data)):
            var sym = Int(data[i])
            var code = UInt64(self.codes[sym])
            var length = Int(self.code_lengths[sym])

            current = (current << UInt64(length)) | code
            bits += length

            while bits >= 8:
                bits -= 8
                result.append(UInt8((current >> UInt64(bits)) & 0xFF))

        if bits > 0:
            var pad = 8 - bits
            current = (current << UInt64(pad)) | UInt64((1 << pad) - 1)
            result.append(UInt8(current & 0xFF))

        return result^

    def decode(self, data: List[UInt8]) -> Tuple[List[UInt8], String]:
        """Decode Huffman-compressed bytes back to raw bytes."""
        var result = List[UInt8]()

        if len(data) == 0:
            return (result^, String())

        var node_idx = 0
        var bits_since_last_symbol = 0
        var all_ones_since_last_symbol = True

        for byte_idx in range(len(data)):
            var b = data[byte_idx]
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
