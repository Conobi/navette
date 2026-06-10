# src/quic/packet_protect.mojo
#
# PacketProtect — QUIC header protection and AEAD encrypt/decrypt.
#
# Wraps librustls-mojo FFI (Wave 1 KEYS_TABLE) for packet-level crypto.
# Each PacketProtect holds up to FOUR keys handles (initial, handshake,
# application, 0-RTT decrypt) and delegates all crypto operations to the
# Rust library.
#
# Encryption levels:
#   0 = Initial         (both directions; discarded at handshake-complete)
#   1 = Handshake       (both directions; discarded at handshake-complete)
#   2 = Application     (both directions; discarded at connection-close)
#   3 = 0-RTT (server-side decrypt only; discarded at handshake-complete
#       OR connection-close, whichever first — RFC 9001 §4.1.3)
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from navette.tls.lib import SharedLibrary

comptime _AEAD_TAG_LEN: Int = 16
comptime _HP_SAMPLE_LEN: Int = 16
comptime _MAX_PN_LEN: Int = 4

# 0-RTT decrypt key slot index.
#
# DECOUPLING NOTE (paired with `ZERO_RTT_SPACE_IDX` in guard_predicates.mojo):
# Both constants share the value 3 today, but nothing depends on that
# equality: every site where a dispatch-space index flows into a
# `PacketProtect` key-slot parameter maps it explicitly
# (`key_slot = ZERO_RTT_KEY_SLOT_IDX if space_idx == ZERO_RTT_SPACE_IDX
# else space_idx` in connection.mojo's decrypt path), and the PN-space
# collapse compares the sentinel by identity, not magnitude.
#
#   - `ZERO_RTT_SPACE_IDX` is a frame-dispatch sentinel. Its residual
#     constraints are: it must be a non-negative integer outside 0..2
#     (i.e. > 2) — negative values are consumed by connection.mojo's
#     `if space_idx < 0: break` (the VN/Retry unparseable-packet path)
#     before dispatch fires, and it must not collide with a valid
#     PN-space index (0..2). See guard_predicates.mojo.
#
#   - `ZERO_RTT_KEY_SLOT_IDX = 3` IS a valid `PacketProtect.keys[]` index.
comptime ZERO_RTT_KEY_SLOT_IDX: Int = 3


struct PacketProtect(Movable):
    """QUIC packet protection: header protection and AEAD encrypt/decrypt.

    Holds keys handles for up to four encryption levels (initial=0,
    handshake=1, application=2, 0-RTT-decrypt=3). Keys handles are
    indices into the Rust-side KEYS_TABLE and are freed via `keys_free`
    on discard or destruction.
    """

    var keys: List[Int32]
    var _lib: SharedLibrary

    # -- Construction ----------------------------------------------------------

    def __init__(out self, lib: SharedLibrary):
        """Create a PacketProtect with no keys installed."""
        self.keys = List[Int32](capacity=4)
        self.keys.append(Int32(-1))
        self.keys.append(Int32(-1))
        self.keys.append(Int32(-1))
        self.keys.append(Int32(-1))
        self._lib = SharedLibrary(other=lib)

    def __init__(out self, *, deinit take: Self):
        self.keys = take.keys^
        self._lib = take._lib^

    def __del__(deinit self):
        for i in range(len(self.keys)):
            if self.keys[i] != Int32(-1):
                _ = self._lib.inner_ptr()[].keys_free(self.keys[i])

    # -- Key management --------------------------------------------------------

    def _check_level(self, level: Int) raises:
        if level < 0 or level >= 4:
            raise "PacketProtect: level out of range (0-3)"

    def set_keys(mut self, level: Int, handle: Int32) raises:
        """Install a keys handle at the given encryption level."""
        self._check_level(level)
        # Free old handle if present to prevent leak.
        if self.keys[level] != Int32(-1):
            _ = self._lib.inner_ptr()[].keys_free(self.keys[level])
        self.keys[level] = handle

    def has_keys(self, level: Int) -> Bool:
        """True if keys are present for the given encryption level."""
        if level < 0 or level >= 4:
            return False
        return self.keys[level] != Int32(-1)

    def discard_keys(mut self, level: Int):
        """Free and remove keys at the given encryption level."""
        if level < 0 or level >= 4:
            return
        if self.keys[level] != Int32(-1):
            _ = self._lib.inner_ptr()[].keys_free(self.keys[level])
            self.keys[level] = Int32(-1)

    def install_zero_rtt_read_keys(mut self, conn_handle: Int32) raises -> Bool:
        """Fetch 0-RTT decrypt keys from rustls (server side) and install at slot 3.

        Semantics are *free-first-then-install*:

        1. If slot 3 is currently populated, free the existing handle BEFORE
           invoking the FFI, regardless of what the FFI subsequently returns.
        2. Call `rlsm_quic_server_conn_zero_rtt_keys`.
        3. On rc=0 (success): install the new handle at slot 3, return True.
        4. On rc=1 (unavailable): slot 3 ends empty, return False.
        5. On rc=-1 (error): slot 3 ends empty, raise with the FFI's
           last_error message.

        The free-first ordering makes a second install replace the first
        without leak, and makes failure cases (1 / -1) leave slot 3 empty
        even if it was populated before the call. Callers wanting to
        preserve a prior key across an install attempt must check
        has_keys(ZERO_RTT_KEY_SLOT_IDX) first.

        Preconditions: self is a server-side PacketProtect (caller's
        responsibility); the corresponding QuicConn handle is in the
        pre-KeyChange::OneRtt window (caller's responsibility — the FFI
        is direction-stateless).

        Args:
            conn_handle: The server-side QuicConn FFI handle.

        Returns:
            True if rustls produced 0-RTT decrypt keys and slot 3 was
            populated; False if the keys were not available (rc=1).
        """
        self.discard_keys(ZERO_RTT_KEY_SLOT_IDX)

        var out_handle = _heap_alloc[Int32](1).as_any_origin()
        out_handle[0] = Int32(-1)
        var rlib = self._lib.inner_ptr()
        var rc = rlib[].quic_server_conn_zero_rtt_keys(conn_handle, out_handle)

        if rc == Int32(0):
            var kh = out_handle[0]
            out_handle.free()
            self.keys[ZERO_RTT_KEY_SLOT_IDX] = kh
            return True
        elif rc == Int32(1):
            out_handle.free()
            return False
        else:
            out_handle.free()
            var err = rlib[].last_error()
            raise "install_zero_rtt_read_keys failed: " + err

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
        var handle = self._lib.inner_ptr()[].initial_keys(
            Int32(1),  # version = QUIC v1
            dcid_buf,
            Int32(dcid_len),
            is_client_i32,
        )
        dcid_buf.free()

        if handle < 0:
            raise (
                "derive_initial_keys failed: "
                + self._lib.inner_ptr()[].last_error()
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
        var rc = self._lib.inner_ptr()[].keys_remote_header_unprotect(
            keys_handle,
            pkt_ptr + pn_offset + _MAX_PN_LEN,  # sample (16 bytes, read-only)
            Int32(_HP_SAMPLE_LEN),
            pkt_ptr,                              # first_byte (modified in-place)
            pkt_ptr + pn_offset,                  # pn_bytes (modified in-place)
            Int32(_MAX_PN_LEN),
        )

        if rc < 0:
            raise "header unprotect failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_remote_decrypt(
            keys_handle,
            pn,
            pkt_ptr,                 # header (AAD)
            Int32(header_len),
            pkt_ptr + header_len,    # payload (decrypted in-place)
            Int32(payload_len),
        )

        if rc < 0:
            raise "decrypt_payload failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_local_encrypt(
            keys_handle,
            pn,
            pkt_ptr,                 # header (AAD)
            Int32(header_len),
            pkt_ptr + header_len,    # payload (encrypted in-place)
            Int32(payload_len),
            Int32(buf_capacity),
        )

        if rc < 0:
            raise "encrypt_payload failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_local_header_protect(
            keys_handle,
            pkt_ptr + pn_offset + _MAX_PN_LEN,  # sample
            Int32(_HP_SAMPLE_LEN),
            pkt_ptr,                              # first_byte
            pkt_ptr + pn_offset,                  # pn_bytes
            Int32(pn_length),
        )

        if rc < 0:
            raise "header protect failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_batch_header_unprotect(
            keys_handle, Int32(count),
            packet_ptrs, packet_lens, pn_offsets,
            out_first_bytes, out_pn_lengths,
        )

        if rc < 0:
            raise "batch_unprotect_headers failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_batch_decrypt(
            keys_handle, Int32(count),
            packet_numbers, packet_ptrs, packet_lens, header_lens,
            out_plaintext_lens,
        )

        if rc < 0:
            raise "batch_decrypt_in_place failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_batch_encrypt(
            keys_handle, Int32(count),
            packet_numbers, packet_ptrs,
            header_lens, payload_lens, buf_capacities,
            out_ciphertext_lens,
        )

        if rc < 0:
            raise "batch_encrypt_in_place failed: " + self._lib.inner_ptr()[].last_error()

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

        var rc = self._lib.inner_ptr()[].keys_batch_header_protect(
            keys_handle, Int32(count),
            packet_ptrs, packet_lens, pn_offsets, pn_lengths,
            out_results,
        )

        if rc < 0:
            raise "batch_protect_headers failed: " + self._lib.inner_ptr()[].last_error()

        return Int(rc)

