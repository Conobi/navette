# src/quic/packet_protect.mojo
#
# PacketProtect — QUIC header protection and AEAD encrypt/decrypt.
#
# Wraps librustls-mojo FFI (Wave 1 KEYS_TABLE) for packet-level crypto.
# Each PacketProtect holds up to three keys handles (initial, handshake,
# application) and delegates all crypto operations to the Rust library.
#
# Encryption levels:
#   0 = Initial
#   1 = Handshake
#   2 = Application (1-RTT)
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from mojo_net.tls.lib import RustlsLibrary

comptime _AEAD_TAG_LEN: Int = 16
comptime _HP_SAMPLE_LEN: Int = 16
comptime _MAX_PN_LEN: Int = 4


struct PacketProtect(Movable):
    """QUIC packet protection: header protection and AEAD encrypt/decrypt.

    Holds keys handles for up to three encryption levels (initial=0,
    handshake=1, application=2). Keys handles are indices into the Rust-side
    KEYS_TABLE and are freed via `keys_free` on discard or destruction.
    """

    var keys: List[Int32]
    var lib_addr: UInt64

    # -- Construction ----------------------------------------------------------

    def __init__(out self, lib_addr: UInt64):
        """Create a PacketProtect with no keys installed."""
        self.keys = List[Int32](capacity=3)
        self.keys.append(Int32(-1))
        self.keys.append(Int32(-1))
        self.keys.append(Int32(-1))
        self.lib_addr = lib_addr

    def __init__(out self, *, deinit take: Self):
        self.keys = take.keys^
        self.lib_addr = take.lib_addr

    def __del__(deinit self):
        for i in range(len(self.keys)):
            if self.keys[i] != Int32(-1):
                _ = self._lib()[].keys_free(self.keys[i])

    # -- Key management --------------------------------------------------------

    def _check_level(self, level: Int) raises:
        if level < 0 or level >= 3:
            raise "PacketProtect: level out of range (0-2)"

    def set_keys(mut self, level: Int, handle: Int32) raises:
        """Install a keys handle at the given encryption level."""
        self._check_level(level)
        # Free old handle if present to prevent leak.
        if self.keys[level] != Int32(-1):
            _ = self._lib()[].keys_free(self.keys[level])
        self.keys[level] = handle

    def has_keys(self, level: Int) -> Bool:
        """True if keys are present for the given encryption level."""
        if level < 0 or level >= 3:
            return False
        return self.keys[level] != Int32(-1)

    def discard_keys(mut self, level: Int):
        """Free and remove keys at the given encryption level."""
        if level < 0 or level >= 3:
            return
        if self.keys[level] != Int32(-1):
            _ = self._lib()[].keys_free(self.keys[level])
            self.keys[level] = Int32(-1)

    def derive_initial_keys(mut self, dcid: Span[UInt8, _], is_client: Bool) raises:
        """Derive QUIC v1 Initial keys from a destination connection ID.

        Stores the resulting keys handle at level 0 (Initial). Raises if
        the FFI call fails (returns -1).

        Args:
            dcid: The destination connection ID bytes.
            is_client: True for client-side keys, False for server-side.
        """
        self.discard_keys(0)  # Free existing Initial keys if any
        var dcid_len = len(dcid)
        var dcid_buf = _heap_alloc[UInt8](dcid_len).as_any_origin()
        for i in range(dcid_len):
            dcid_buf[i] = dcid[i]

        var is_client_i32 = Int32(1) if is_client else Int32(0)
        var handle = self._lib()[].initial_keys(
            Int32(1),  # version = QUIC v1
            dcid_buf,
            Int32(dcid_len),
            is_client_i32,
        )
        dcid_buf.free()

        if handle < 0:
            raise (
                "derive_initial_keys failed: "
                + self._lib()[].last_error()
            )
        self.keys[0] = handle

    # -- Header protection (decrypt direction) ---------------------------------

    def unprotect_header_ptr(
        self,
        level: Int,
        pkt_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        pkt_len: Int,
        pn_offset: Int,
    ) raises -> Tuple[UInt8, Int]:
        """Remove header protection in-place. Zero-copy — no heap allocs.

        Modifies pkt_ptr[0] (first byte) and pkt_ptr[pn_offset..pn_offset+4]
        (PN bytes) in-place via the Rust FFI.

        Returns (unprotected first byte, pn_length 1..4).
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        if pn_offset + _MAX_PN_LEN + _HP_SAMPLE_LEN > pkt_len:
            raise "packet too short for header unprotection"

        # Pass pointers directly into the packet buffer — no copies.
        var rc = self._lib()[].keys_remote_header_unprotect(
            keys_handle,
            pkt_ptr + pn_offset + _MAX_PN_LEN,  # sample (16 bytes, read-only)
            Int32(_HP_SAMPLE_LEN),
            pkt_ptr,                              # first_byte (modified in-place)
            pkt_ptr + pn_offset,                  # pn_bytes (modified in-place)
            Int32(_MAX_PN_LEN),
        )

        if rc < 0:
            raise "header unprotect failed: " + self._lib()[].last_error()

        var fb = pkt_ptr[0]
        var pn_length = Int(fb & 0x03) + 1
        return Tuple[UInt8, Int](fb, pn_length)

    def unprotect_header(
        self, level: Int, mut packet_buf: List[UInt8], pn_offset: Int
    ) raises -> Tuple[UInt8, Int]:
        """Remove header protection (List convenience wrapper)."""
        return self.unprotect_header_ptr(
            level,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin(),
            len(packet_buf),
            pn_offset,
        )

    # -- AEAD decrypt ----------------------------------------------------------

    def decrypt_payload_in_place(
        self,
        level: Int,
        pn: UInt64,
        header_len: Int,
        pkt_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        pkt_len: Int,
    ) raises -> Int:
        """Decrypt AEAD payload in-place. Zero-copy.

        pkt_ptr[0..header_len] is the header (AAD, read-only by Rust).
        pkt_ptr[header_len..pkt_len] is ciphertext+tag (decrypted in-place).

        Returns plaintext length. After call, plaintext is at
        pkt_ptr[header_len .. header_len + result].
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        if header_len >= pkt_len:
            raise "header_len >= packet length"

        var payload_len = pkt_len - header_len

        var rc = self._lib()[].keys_remote_decrypt(
            keys_handle,
            pn,
            pkt_ptr,                 # header (AAD)
            Int32(header_len),
            pkt_ptr + header_len,    # payload (decrypted in-place)
            Int32(payload_len),
        )

        if rc < 0:
            raise "decrypt_payload failed: " + self._lib()[].last_error()

        return Int(rc)

    def decrypt_payload(
        self,
        level: Int,
        pn: UInt64,
        header_len: Int,
        mut packet_buf: List[UInt8],
    ) raises -> List[UInt8]:
        """Decrypt payload (List convenience wrapper — copies result out)."""
        var plaintext_len = self.decrypt_payload_in_place(
            level, pn, header_len,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin(),
            len(packet_buf),
        )
        # Copy plaintext out of the buffer for backward compatibility.
        var result = List[UInt8](capacity=plaintext_len)
        for i in range(plaintext_len):
            result.append(packet_buf[header_len + i])
        return result^

    # -- AEAD encrypt ----------------------------------------------------------

    def encrypt_payload_in_place(
        self,
        level: Int,
        pn: UInt64,
        pkt_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        header_len: Int,
        payload_len: Int,
        total_capacity: Int,
    ) raises -> Int:
        """Encrypt payload in-place. Zero-copy.

        pkt_ptr[0..header_len] = header (AAD, read-only).
        pkt_ptr[header_len..header_len+payload_len] = plaintext -> ciphertext.
        pkt_ptr[header_len+payload_len..total_capacity] = space for AEAD tag.

        Returns ciphertext length (payload_len + tag_len).
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        if total_capacity < header_len + payload_len + _AEAD_TAG_LEN:
            raise "encrypt_payload_in_place: buffer too small"

        var buf_capacity = total_capacity - header_len

        var rc = self._lib()[].keys_local_encrypt(
            keys_handle,
            pn,
            pkt_ptr,                 # header (AAD)
            Int32(header_len),
            pkt_ptr + header_len,    # payload (encrypted in-place)
            Int32(payload_len),
            Int32(buf_capacity),
        )

        if rc < 0:
            raise "encrypt_payload failed: " + self._lib()[].last_error()

        return Int(rc)

    def encrypt_payload(
        self,
        level: Int,
        pn: UInt64,
        header: Span[UInt8, _],
        plaintext: Span[UInt8, _],
    ) raises -> List[UInt8]:
        """Encrypt payload (Span convenience wrapper — returns new List)."""
        var header_len = len(header)
        var pt_len = len(plaintext)
        var capacity = header_len + pt_len + _AEAD_TAG_LEN

        # Build contiguous buffer: header + plaintext + tag space
        var buf = _heap_alloc[UInt8](capacity).as_any_origin()
        for i in range(header_len):
            buf[i] = header[i]
        for i in range(pt_len):
            buf[header_len + i] = plaintext[i]
        for i in range(_AEAD_TAG_LEN):
            buf[header_len + pt_len + i] = 0

        var ct_len = self.encrypt_payload_in_place(
            level, pn, buf, header_len, pt_len, capacity,
        )

        # Copy ciphertext (without header) to result.
        var result = List[UInt8](capacity=ct_len)
        for i in range(ct_len):
            result.append(buf[header_len + i])

        buf.free()
        return result^

    # -- Header protection (encrypt direction) ---------------------------------

    def protect_header_ptr(
        self,
        level: Int,
        pkt_ptr: UnsafePointer[UInt8, MutAnyOrigin],
        pkt_len: Int,
        pn_offset: Int,
        pn_length: Int,
    ) raises:
        """Apply header protection in-place. Zero-copy — no heap allocs."""
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        if pn_offset + _MAX_PN_LEN + _HP_SAMPLE_LEN > pkt_len:
            raise "packet too short for header protection"

        var rc = self._lib()[].keys_local_header_protect(
            keys_handle,
            pkt_ptr + pn_offset + _MAX_PN_LEN,  # sample
            Int32(_HP_SAMPLE_LEN),
            pkt_ptr,                              # first_byte
            pkt_ptr + pn_offset,                  # pn_bytes
            Int32(pn_length),
        )

        if rc < 0:
            raise "header protect failed: " + self._lib()[].last_error()

    def protect_header(
        self,
        level: Int,
        mut packet_buf: List[UInt8],
        pn_offset: Int,
        pn_length: Int,
    ) raises:
        """Apply header protection (List convenience wrapper)."""
        self.protect_header_ptr(
            level,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_any_origin(),
            len(packet_buf),
            pn_offset,
            pn_length,
        )

    # -- Batch operations (Phase 2) -------------------------------------------

    def batch_unprotect_headers(
        self,
        level: Int,
        count: Int,
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        pn_offsets: UnsafePointer[Int32, MutAnyOrigin],
        out_first_bytes: UnsafePointer[UInt8, MutAnyOrigin],
        out_pn_lengths: UnsafePointer[Int32, MutAnyOrigin],
    ) raises -> Int:
        """Batch header unprotection for N packets at the same level.

        Returns count of successfully unprotected packets.
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var rc = self._lib()[].keys_batch_header_unprotect(
            keys_handle, Int32(count),
            packet_ptrs, packet_lens, pn_offsets,
            out_first_bytes, out_pn_lengths,
        )

        if rc < 0:
            raise "batch_unprotect_headers failed: " + self._lib()[].last_error()

        return Int(rc)

    def batch_decrypt_in_place(
        self,
        level: Int,
        count: Int,
        packet_numbers: UnsafePointer[UInt64, MutAnyOrigin],
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        header_lens: UnsafePointer[Int32, MutAnyOrigin],
        out_plaintext_lens: UnsafePointer[Int32, MutAnyOrigin],
    ) raises -> Int:
        """Batch AEAD decryption for N packets at the same level.

        Returns count of successfully decrypted packets.
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var rc = self._lib()[].keys_batch_decrypt(
            keys_handle, Int32(count),
            packet_numbers, packet_ptrs, packet_lens, header_lens,
            out_plaintext_lens,
        )

        if rc < 0:
            raise "batch_decrypt_in_place failed: " + self._lib()[].last_error()

        return Int(rc)

    def batch_encrypt_in_place(
        self,
        level: Int,
        count: Int,
        packet_numbers: UnsafePointer[UInt64, MutAnyOrigin],
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        header_lens: UnsafePointer[Int32, MutAnyOrigin],
        payload_lens: UnsafePointer[Int32, MutAnyOrigin],
        buf_capacities: UnsafePointer[Int32, MutAnyOrigin],
        out_ciphertext_lens: UnsafePointer[Int32, MutAnyOrigin],
    ) raises -> Int:
        """Batch AEAD encryption for N packets at the same level.

        Returns count of successfully encrypted packets.
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var rc = self._lib()[].keys_batch_encrypt(
            keys_handle, Int32(count),
            packet_numbers, packet_ptrs,
            header_lens, payload_lens, buf_capacities,
            out_ciphertext_lens,
        )

        if rc < 0:
            raise "batch_encrypt_in_place failed: " + self._lib()[].last_error()

        return Int(rc)

    def batch_protect_headers(
        self,
        level: Int,
        count: Int,
        packet_ptrs: UnsafePointer[UnsafePointer[UInt8, MutAnyOrigin], MutAnyOrigin],
        packet_lens: UnsafePointer[Int32, MutAnyOrigin],
        pn_offsets: UnsafePointer[Int32, MutAnyOrigin],
        pn_lengths: UnsafePointer[Int32, MutAnyOrigin],
        out_results: UnsafePointer[Int32, MutAnyOrigin],
    ) raises -> Int:
        """Batch header protection for N packets at the same level.

        Returns count of successfully protected packets.
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var rc = self._lib()[].keys_batch_header_protect(
            keys_handle, Int32(count),
            packet_ptrs, packet_lens, pn_offsets, pn_lengths,
            out_results,
        )

        if rc < 0:
            raise "batch_protect_headers failed: " + self._lib()[].last_error()

        return Int(rc)

    # -- Internal --------------------------------------------------------------

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self.lib_addr)
        )
