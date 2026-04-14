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

    def set_keys(mut self, level: Int, handle: Int32):
        """Install a keys handle at the given encryption level."""
        self.keys[level] = handle

    def has_keys(self, level: Int) -> Bool:
        """True if keys are present for the given encryption level."""
        return self.keys[level] != Int32(-1)

    def discard_keys(mut self, level: Int):
        """Free and remove keys at the given encryption level."""
        if self.keys[level] != Int32(-1):
            _ = self._lib()[].keys_free(self.keys[level])
            self.keys[level] = Int32(-1)

    def derive_initial_keys(mut self, dcid: Span[UInt8], is_client: Bool) raises:
        """Derive QUIC v1 Initial keys from a destination connection ID.

        Stores the resulting keys handle at level 0 (Initial). Raises if
        the FFI call fails (returns -1).

        Args:
            dcid: The destination connection ID bytes.
            is_client: True for client-side keys, False for server-side.
        """
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

    def unprotect_header(
        self, level: Int, mut packet_buf: List[UInt8], pn_offset: Int
    ) raises -> Tuple[UInt8, Int]:
        """Remove header protection and return (first_byte, pn_length).

        Modifies packet_buf in-place: the first byte and the PN bytes at
        pn_offset are unmasked.

        Args:
            level: Encryption level (0=Initial, 1=Handshake, 2=Application).
            packet_buf: The full packet buffer (modified in-place).
            pn_offset: Byte offset where the packet number starts.

        Returns:
            A tuple of (unprotected first byte, packet number length 1..4).
        """
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + str(level)

        # Need at least pn_offset + 4 (max PN) + 16 (HP sample).
        if pn_offset + _MAX_PN_LEN + _HP_SAMPLE_LEN > len(packet_buf):
            raise "packet too short for header unprotection"

        # Extract 16-byte HP sample starting at pn_offset + 4.
        var sample = _heap_alloc[UInt8](_HP_SAMPLE_LEN).as_any_origin()
        for i in range(_HP_SAMPLE_LEN):
            sample[i] = packet_buf[pn_offset + _MAX_PN_LEN + i]

        # Copy first byte and 4 PN bytes for the FFI call.
        var first_byte = _heap_alloc[UInt8](1).as_any_origin()
        first_byte[0] = packet_buf[0]

        var pn_bytes = _heap_alloc[UInt8](_MAX_PN_LEN).as_any_origin()
        for i in range(_MAX_PN_LEN):
            pn_bytes[i] = packet_buf[pn_offset + i]

        var rc = self._lib()[].keys_remote_header_unprotect(
            keys_handle,
            sample,
            Int32(_HP_SAMPLE_LEN),
            first_byte,
            pn_bytes,
            Int32(_MAX_PN_LEN),
        )

        if rc < 0:
            var err = self._lib()[].last_error()
            sample.free()
            first_byte.free()
            pn_bytes.free()
            raise "header unprotect failed: " + err

        # Read back the unprotected values.
        var fb = first_byte[0]
        var pn_length = Int(fb & 0x03) + 1

        # Write unprotected values back into the packet buffer.
        packet_buf[0] = fb
        for i in range(_MAX_PN_LEN):
            packet_buf[pn_offset + i] = pn_bytes[i]

        sample.free()
        first_byte.free()
        pn_bytes.free()

        return Tuple[UInt8, Int](fb, pn_length)

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
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + str(level)

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
        header: Span[UInt8],
        plaintext: Span[UInt8],
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
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + str(level)

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

    def protect_header(
        self,
        level: Int,
        mut packet_buf: List[UInt8],
        pn_offset: Int,
        pn_length: Int,
    ) raises:
        """Apply header protection to a serialized QUIC packet.

        Modifies packet_buf in-place: masks the first byte and the PN bytes
        at pn_offset using the HP sample from the ciphertext.

        Args:
            level: Encryption level.
            packet_buf: The full packet (header + ciphertext + tag), modified in-place.
            pn_offset: Byte offset where the packet number starts.
            pn_length: Length of the encoded packet number (1..4).
        """
        var keys_handle = self.keys[level]
        if keys_handle == Int32(-1):
            raise "no keys for level " + str(level)

        # HP sample starts 4 bytes after pn_offset (into the ciphertext).
        if pn_offset + _MAX_PN_LEN + _HP_SAMPLE_LEN > len(packet_buf):
            raise "packet too short for header protection"

        var sample = _heap_alloc[UInt8](_HP_SAMPLE_LEN).as_any_origin()
        for i in range(_HP_SAMPLE_LEN):
            sample[i] = packet_buf[pn_offset + _MAX_PN_LEN + i]

        var first_byte = _heap_alloc[UInt8](1).as_any_origin()
        first_byte[0] = packet_buf[0]

        var pn_bytes = _heap_alloc[UInt8](pn_length).as_any_origin()
        for i in range(pn_length):
            pn_bytes[i] = packet_buf[pn_offset + i]

        var rc = self._lib()[].keys_local_header_protect(
            keys_handle,
            sample,
            Int32(_HP_SAMPLE_LEN),
            first_byte,
            pn_bytes,
            Int32(pn_length),
        )

        if rc < 0:
            var err = self._lib()[].last_error()
            sample.free()
            first_byte.free()
            pn_bytes.free()
            raise "header protect failed: " + err

        # Write protected values back.
        packet_buf[0] = first_byte[0]
        for i in range(pn_length):
            packet_buf[pn_offset + i] = pn_bytes[i]

        sample.free()
        first_byte.free()
        pn_bytes.free()

    # -- Internal --------------------------------------------------------------

    @always_inline
    def _lib(self) -> UnsafePointer[RustlsLibrary, MutAnyOrigin]:
        return UnsafePointer[RustlsLibrary, MutAnyOrigin](
            unsafe_from_address=Int(self.lib_addr)
        )
