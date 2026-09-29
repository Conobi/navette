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
from std.memory import Pointer
from std.collections import Span

from navette.util.owned_alloc import Owned
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
        self._lib = SharedLibrary(copy=lib)

    def __deinit__(deinit self):
        """Free every installed keys handle.

        A destructor may not raise. `keys_free` can, but only from the
        symbol lookup — an unknown handle returns -1 on the Rust side
        and that status is already discarded. A lookup failure means the
        loaded librustls_mojo.so does not export `rlsm_keys_free`, so
        none of the handles can be reached; swallowing it leaks up to
        four KEYS_TABLE entries (AEAD keys and header-protection masks)
        rather than aborting the process during connection teardown.

        The guard is inside the loop, not around it, so a failure on one
        encryption level still lets the others be freed. `deinit self`
        consumes the object and each slot is visited once, so no handle
        can be freed twice.
        """
        for ref key in self.keys:
            if key != Int32(-1):
                try:
                    _ = self._lib.inner_ptr()[].keys_free(key)
                except:
                    pass
        # Anchor: `inner_ptr()` returns an untracked pointer, so the checker
        # cannot see that the call above depends on `_lib`. Without a later
        # reference, ASAP destruction frees `_lib` at that line -- closing the
        # dylib -- and the FFI call runs through a null handle.
        _ = self._lib.inner_ptr()

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

    def discard_keys(mut self, level: Int) raises:
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

        var out_handle_buf = Owned[Int32](1)
        var out_handle = out_handle_buf.ptr()
        out_handle[unsafe_offset=0] = Int32(-1)
        var rlib = self._lib.inner_ptr()
        var rc = rlib[].quic_server_conn_zero_rtt_keys(conn_handle, out_handle)

        if rc == Int32(0):
            var kh = out_handle[unsafe_offset=0]
            # Keep out_handle_buf alive through the post-FFI read above.
            _ = out_handle_buf
            self.keys[ZERO_RTT_KEY_SLOT_IDX] = kh
            return True
        elif rc == Int32(1):
            return False
        else:
            var err = rlib[].last_error()
            raise "install_zero_rtt_read_keys failed: " + err

    def derive_initial_keys(mut self, dcid: Span[Byte, _], is_client: Bool) raises:
        """Derive QUIC v1 Initial keys from a destination connection ID.

        Stores the resulting keys handle at level 0 (Initial). Raises if
        the FFI call fails (returns -1).

        Args:
            dcid: The destination connection ID bytes.
            is_client: True for client-side keys, False for server-side.
        """
        self.discard_keys(0)  # Free existing Initial keys if any
        var dcid_len = len(dcid)
        var dcid_owned = Owned[UInt8](dcid_len)
        var dcid_buf = dcid_owned.ptr()
        for i in range(dcid_len):
            dcid_buf[unsafe_offset=i] = dcid[i]

        var is_client_i32 = Int32(1) if is_client else Int32(0)
        var handle = self._lib.inner_ptr()[].initial_keys(
            Int32(1),  # version = QUIC v1
            dcid_buf,
            Int32(dcid_len),
            is_client_i32,
        )

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
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
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
        # rustls reads and writes several regions of this one packet buffer
        # through separate pointers. Mojo 1.0.0 rejects two mutable pointers
        # with the same tracked origin in one call, so the buffer is handed
        # over untracked: the aliasing is intended and confined to C. The
        # `pkt_ptr` parameter keeps the caller's buffer borrowed for this
        # whole method, which spans the synchronous call below.
        var raw = pkt_ptr.unsafe_origin_cast[MutUntrackedOrigin]()
        var rc = self._lib.inner_ptr()[].keys_remote_header_unprotect(
            keys_handle,
            raw.unsafe_offset(pn_offset + _MAX_PN_LEN),  # sample (16B, read-only)
            Int32(_HP_SAMPLE_LEN),
            raw,                                  # first_byte (modified in-place)
            raw.unsafe_offset(pn_offset),         # pn_bytes (modified in-place)
            Int32(_MAX_PN_LEN),
        )

        if rc < 0:
            raise "header unprotect failed: " + self._lib.inner_ptr()[].last_error()

        var fb = pkt_ptr[unsafe_offset=0]
        var pn_length = Int(fb & 0x03) + 1
        return Tuple[UInt8, Int](fb, pn_length)

    def unprotect_header(
        self, level: Int, mut packet_buf: List[Byte], pn_offset: Int
    ) raises -> Tuple[UInt8, Int]:
        """Remove header protection (List convenience wrapper)."""
        return self.unprotect_header_ptr(
            level,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin(),
            len(packet_buf),
            pn_offset,
        )

    # -- AEAD decrypt ----------------------------------------------------------

    def decrypt_payload_in_place(
        self,
        level: Int,
        pn: UInt64,
        header_len: Int,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
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

        # rustls reads and writes several regions of this one packet buffer
        # through separate pointers. Mojo 1.0.0 rejects two mutable pointers
        # with the same tracked origin in one call, so the buffer is handed
        # over untracked: the aliasing is intended and confined to C. The
        # `pkt_ptr` parameter keeps the caller's buffer borrowed for this
        # whole method, which spans the synchronous call below.
        var raw = pkt_ptr.unsafe_origin_cast[MutUntrackedOrigin]()
        var rc = self._lib.inner_ptr()[].keys_remote_decrypt(
            keys_handle,
            pn,
            raw,                                  # header (AAD)
            Int32(header_len),
            raw.unsafe_offset(header_len),        # payload (decrypted in-place)
            Int32(payload_len),
        )

        if rc < 0:
            raise "decrypt_payload failed: " + self._lib.inner_ptr()[].last_error()

        return Int(rc)

    def decrypt_payload(
        self,
        mut buf: List[Byte],
        level: Int,
        pn: UInt64,
        header_len: Int,
        mut packet_buf: List[Byte],
    ) raises:
        """Decrypt payload, appending the plaintext directly to buf."""
        var plaintext_len = self.decrypt_payload_in_place(
            level, pn, header_len,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin(),
            len(packet_buf),
        )
        buf.extend(Span(packet_buf)[header_len : header_len + plaintext_len])

    # -- AEAD encrypt ----------------------------------------------------------

    def encrypt_payload_in_place(
        self,
        level: Int,
        pn: UInt64,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
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

        # rustls reads and writes several regions of this one packet buffer
        # through separate pointers. Mojo 1.0.0 rejects two mutable pointers
        # with the same tracked origin in one call, so the buffer is handed
        # over untracked: the aliasing is intended and confined to C. The
        # `pkt_ptr` parameter keeps the caller's buffer borrowed for this
        # whole method, which spans the synchronous call below.
        var raw = pkt_ptr.unsafe_origin_cast[MutUntrackedOrigin]()
        var rc = self._lib.inner_ptr()[].keys_local_encrypt(
            keys_handle,
            pn,
            raw,                                  # header (AAD)
            Int32(header_len),
            raw.unsafe_offset(header_len),        # payload (encrypted in-place)
            Int32(payload_len),
            Int32(buf_capacity),
        )

        if rc < 0:
            raise "encrypt_payload failed: " + self._lib.inner_ptr()[].last_error()

        return Int(rc)

    def encrypt_payload(
        self,
        mut buf: List[Byte],
        level: Int,
        pn: UInt64,
        header: Span[Byte, _],
        plaintext: Span[Byte, _],
    ) raises:
        """Encrypt payload, appending the ciphertext (without header) to buf."""
        var header_len = len(header)
        var pt_len = len(plaintext)
        var capacity = header_len + pt_len + _AEAD_TAG_LEN

        # Build contiguous buffer: header + plaintext + tag space
        var scratch_owned = Owned[UInt8](capacity)
        var scratch = scratch_owned.ptr()
        for i in range(header_len):
            scratch[unsafe_offset=i] = header[i]
        for i in range(pt_len):
            scratch[unsafe_offset=header_len + i] = plaintext[i]
        for i in range(_AEAD_TAG_LEN):
            scratch[unsafe_offset=header_len + pt_len + i] = 0

        var ct_len = self.encrypt_payload_in_place(
            level, pn, scratch, header_len, pt_len, capacity,
        )

        # Append ciphertext (without header) to buf.
        buf.extend(Span(unsafe_ptr=scratch.unsafe_offset(header_len), length=ct_len))

        # Keep scratch_owned alive through the post-FFI read above.
        _ = scratch_owned

    # -- Header protection (encrypt direction) ---------------------------------

    def protect_header_ptr(
        self,
        level: Int,
        pkt_ptr: Pointer[mut=True, T=UInt8, origin=_],
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

        # rustls reads and writes several regions of this one packet buffer
        # through separate pointers. Mojo 1.0.0 rejects two mutable pointers
        # with the same tracked origin in one call, so the buffer is handed
        # over untracked: the aliasing is intended and confined to C. The
        # `pkt_ptr` parameter keeps the caller's buffer borrowed for this
        # whole method, which spans the synchronous call below.
        var raw = pkt_ptr.unsafe_origin_cast[MutUntrackedOrigin]()
        var rc = self._lib.inner_ptr()[].keys_local_header_protect(
            keys_handle,
            raw.unsafe_offset(pn_offset + _MAX_PN_LEN),  # sample
            Int32(_HP_SAMPLE_LEN),
            raw,                                  # first_byte
            raw.unsafe_offset(pn_offset),         # pn_bytes
            Int32(pn_length),
        )

        if rc < 0:
            raise "header protect failed: " + self._lib.inner_ptr()[].last_error()

    def protect_header(
        self,
        level: Int,
        mut packet_buf: List[Byte],
        pn_offset: Int,
        pn_length: Int,
    ) raises:
        """Apply header protection (List convenience wrapper)."""
        self.protect_header_ptr(
            level,
            packet_buf.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin(),
            len(packet_buf),
            pn_offset,
            pn_length,
        )

    # -- Batch operations (Phase 2) -------------------------------------------

    def batch_unprotect_headers(
        self,
        level: Int,
        count: Int,
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        pn_offsets: Pointer[mut=True, T=Int32, origin=_],
        out_first_bytes: Pointer[mut=True, T=UInt8, origin=_],
        out_pn_lengths: Pointer[mut=True, T=Int32, origin=_],
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
        packet_numbers: Pointer[mut=True, T=UInt64, origin=_],
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        header_lens: Pointer[mut=True, T=Int32, origin=_],
        out_plaintext_lens: Pointer[mut=True, T=Int32, origin=_],
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
        packet_numbers: Pointer[mut=True, T=UInt64, origin=_],
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        header_lens: Pointer[mut=True, T=Int32, origin=_],
        payload_lens: Pointer[mut=True, T=Int32, origin=_],
        buf_capacities: Pointer[mut=True, T=Int32, origin=_],
        out_ciphertext_lens: Pointer[mut=True, T=Int32, origin=_],
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
        packet_ptrs: Pointer[mut=True, T=Pointer[UInt8, MutUntrackedOrigin], origin=_],
        packet_lens: Pointer[mut=True, T=Int32, origin=_],
        pn_offsets: Pointer[mut=True, T=Int32, origin=_],
        pn_lengths: Pointer[mut=True, T=Int32, origin=_],
        out_results: Pointer[mut=True, T=Int32, origin=_],
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

