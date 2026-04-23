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

from src.tls.lib import RustlsLibrary

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

    def decrypt_payload(
        self,
        level: Int,
        pn: UInt64,
        header_len: Int,
        mut packet_buf: List[UInt8],
    ) raises -> List[UInt8]:
        """Decrypt the AEAD-protected payload of a QUIC packet.

        Args:
            level: Encryption level.
            pn: Full (decoded) packet number.
            header_len: Length of the packet header (bytes before payload).
            packet_buf: The full packet buffer (header + ciphertext + tag).

        Returns:
            The decrypted plaintext (without AEAD tag).
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var total_len = len(packet_buf)
        if header_len >= total_len:
            raise "header_len >= packet length"

        var payload_len = total_len - header_len

        # Copy header to a heap buffer for the FFI AAD parameter.
        var header_buf = _heap_alloc[UInt8](header_len).as_any_origin()
        for i in range(header_len):
            header_buf[i] = packet_buf[i]

        # Copy payload (ciphertext + tag) to a mutable heap buffer.
        var payload_buf = _heap_alloc[UInt8](payload_len).as_any_origin()
        for i in range(payload_len):
            payload_buf[i] = packet_buf[header_len + i]

        var rc = self._lib()[].keys_remote_decrypt(
            keys_handle,
            pn,
            header_buf,
            Int32(header_len),
            payload_buf,
            Int32(payload_len),
        )

        header_buf.free()

        if rc < 0:
            var err = self._lib()[].last_error()
            payload_buf.free()
            raise "decrypt_payload failed: " + err

        # rc = plaintext length (payload_len - tag_len).
        var plaintext_len = Int(rc)
        var result = List[UInt8](capacity=plaintext_len)
        for i in range(plaintext_len):
            result.append(payload_buf[i])

        payload_buf.free()
        return result^

    # -- AEAD encrypt ----------------------------------------------------------

    def encrypt_payload(
        self,
        level: Int,
        pn: UInt64,
        header: Span[UInt8, _],
        plaintext: Span[UInt8, _],
    ) raises -> List[UInt8]:
        """Encrypt a QUIC payload with AEAD.

        Args:
            level: Encryption level.
            pn: Full packet number.
            header: The serialized packet header (used as AAD).
            plaintext: The plaintext payload to encrypt.

        Returns:
            The ciphertext including the 16-byte AEAD tag.
        """
        self._check_level(level)
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + String(level)

        var pt_len = len(plaintext)
        var capacity = pt_len + _AEAD_TAG_LEN

        # Copy header to heap for FFI.
        var header_len = len(header)
        var header_buf = _heap_alloc[UInt8](header_len).as_any_origin()
        for i in range(header_len):
            header_buf[i] = header[i]

        # Copy plaintext to a buffer with extra capacity for the tag.
        var payload_buf = _heap_alloc[UInt8](capacity).as_any_origin()
        for i in range(pt_len):
            payload_buf[i] = plaintext[i]

        var rc = self._lib()[].keys_local_encrypt(
            keys_handle,
            pn,
            header_buf,
            Int32(header_len),
            payload_buf,
            Int32(pt_len),
            Int32(capacity),
        )

        header_buf.free()

        if rc < 0:
            var err = self._lib()[].last_error()
            payload_buf.free()
            raise "encrypt_payload failed: " + err

        # rc = ciphertext length (plaintext + tag).
        var ct_len = Int(rc)
        var result = List[UInt8](capacity=ct_len)
        for i in range(ct_len):
            result.append(payload_buf[i])

        payload_buf.free()
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

    # -- Internal --------------------------------------------------------------

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self.lib_addr)
        )
