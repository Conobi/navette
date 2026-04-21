# src/quic/retry.mojo
# Stateless Retry token generation/validation and integrity tag computation.
# RFC 9001 Section 8.1 (Retry), Appendix A.4 (integrity tag test vector).

from std.ffi import external_call
from std.memory import UnsafePointer, Span
from std.memory.unsafe_pointer import alloc as _heap_alloc

from src.tls.lib import RustlsLibrary


# --- RFC 9001 Section 5.8: Retry Integrity Tag key and nonce (QUIC v1) ---
# Key: 0xbe0c690b9f66575a1d766b54e368c84e
# Nonce: 0x461599d35d632bf2239825bb


def _copy_span_to_ptr(
    src: Span[UInt8, _], dst: UnsafePointer[UInt8, MutAnyOrigin], offset: Int
) -> Int:
    """Copy span bytes into dst starting at offset. Returns new offset."""
    for i in range(len(src)):
        dst[offset + i] = src[i]
    return offset + len(src)


def _write_u64_be(
    dst: UnsafePointer[UInt8, MutAnyOrigin], offset: Int, value: UInt64
) -> Int:
    """Write a UInt64 in big-endian at offset. Returns new offset."""
    dst[offset + 0] = UInt8((value >> 56) & 0xFF)
    dst[offset + 1] = UInt8((value >> 48) & 0xFF)
    dst[offset + 2] = UInt8((value >> 40) & 0xFF)
    dst[offset + 3] = UInt8((value >> 32) & 0xFF)
    dst[offset + 4] = UInt8((value >> 24) & 0xFF)
    dst[offset + 5] = UInt8((value >> 16) & 0xFF)
    dst[offset + 6] = UInt8((value >> 8) & 0xFF)
    dst[offset + 7] = UInt8(value & 0xFF)
    return offset + 8


def _read_u64_be(
    src: UnsafePointer[UInt8, MutAnyOrigin], offset: Int
) -> UInt64:
    """Read a big-endian UInt64 from src at offset."""
    return (
        (UInt64(src[offset + 0]) << 56)
        | (UInt64(src[offset + 1]) << 48)
        | (UInt64(src[offset + 2]) << 40)
        | (UInt64(src[offset + 3]) << 32)
        | (UInt64(src[offset + 4]) << 24)
        | (UInt64(src[offset + 5]) << 16)
        | (UInt64(src[offset + 6]) << 8)
        | UInt64(src[offset + 7])
    )


def generate_retry_token(
    lib_addr: UInt64,
    server_secret: Span[UInt8, _],
    orig_dcid: Span[UInt8, _],
    client_addr_hash: Span[UInt8, _],
    now: UInt64,
) raises -> List[UInt8]:
    """Generate an encrypted Retry token.

    Token format: nonce (12) || ciphertext+tag
    Plaintext: dcid_len (1) || orig_dcid || addr_hash (32) || timestamp (8 BE)
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != 32:
        raise "client_addr_hash must be 32 bytes"
    if len(orig_dcid) > 20:
        raise "orig_dcid too long"

    var lib = UnsafePointer[RustlsLibrary, MutAnyOrigin](unsafe_from_address=Int(lib_addr))

    # Build plaintext: 1 + dcid_len + 32 + 8
    var pt_len = 1 + len(orig_dcid) + 32 + 8
    var pt_ptr = _heap_alloc[UInt8](pt_len).as_any_origin()
    pt_ptr[0] = UInt8(len(orig_dcid))
    var off = 1
    off = _copy_span_to_ptr(orig_dcid, pt_ptr, off)
    off = _copy_span_to_ptr(client_addr_hash, pt_ptr, off)
    off = _write_u64_be(pt_ptr, off, now)

    # Generate 12-byte random nonce via getrandom(2).
    var nonce_ptr = _heap_alloc[UInt8](12).as_any_origin()
    _ = external_call["getrandom", Int](nonce_ptr, UInt64(12), UInt32(0))

    # Prepare key pointer
    var key_ptr = _heap_alloc[UInt8](16).as_any_origin()
    _ = _copy_span_to_ptr(server_secret, key_ptr, 0)

    # Prepare AAD
    var aad_str = String("mojo-net-retry-v1")
    var aad_bytes = aad_str.as_bytes()
    var aad_len = len(aad_bytes)
    var aad_ptr = _heap_alloc[UInt8](aad_len).as_any_origin()
    for i in range(aad_len):
        aad_ptr[i] = aad_bytes[i]

    # Output buffer: plaintext + 16-byte tag
    var out_cap = pt_len + 16
    var out_ptr = _heap_alloc[UInt8](out_cap).as_any_origin()
    var out_len_ptr = _heap_alloc[Int32](1).as_any_origin()
    out_len_ptr[0] = Int32(0)

    var rc = lib[].aes_gcm_128_seal(
        key_ptr,
        Int32(16),
        nonce_ptr,
        Int32(12),
        aad_ptr,
        Int32(aad_len),
        pt_ptr,
        Int32(pt_len),
        out_ptr,
        out_len_ptr,
    )

    if rc != 0:
        var err = lib[].last_error()
        pt_ptr.free()
        nonce_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "AES-GCM-128 seal failed: " + err

    var ct_len = Int(out_len_ptr[0])

    # Build token: nonce (12) || ciphertext+tag
    var token = List[UInt8](capacity=12 + ct_len)
    for i in range(12):
        token.append(nonce_ptr[i])
    for i in range(ct_len):
        token.append(out_ptr[i])

    # Cleanup
    pt_ptr.free()
    nonce_ptr.free()
    key_ptr.free()
    aad_ptr.free()
    out_ptr.free()
    out_len_ptr.free()

    return token^


def validate_retry_token(
    lib_addr: UInt64,
    server_secret: Span[UInt8, _],
    token: Span[UInt8, _],
    client_addr_hash: Span[UInt8, _],
    now: UInt64,
    max_age: UInt64 = 5,
) raises -> List[UInt8]:
    """Validate a Retry token and return the original DCID.

    Raises on authentication failure, address mismatch, or expiration.
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != 32:
        raise "client_addr_hash must be 32 bytes"
    # Minimum: 12 (nonce) + 16 (tag) = 28 bytes
    if len(token) < 28:
        raise "token too short"

    var lib = UnsafePointer[RustlsLibrary, MutAnyOrigin](unsafe_from_address=Int(lib_addr))

    # Extract nonce (first 12 bytes) and ciphertext+tag (rest)
    var nonce_ptr = _heap_alloc[UInt8](12).as_any_origin()
    for i in range(12):
        nonce_ptr[i] = token[i]

    var ct_len = len(token) - 12
    var ct_ptr = _heap_alloc[UInt8](ct_len).as_any_origin()
    for i in range(ct_len):
        ct_ptr[i] = token[12 + i]

    # Prepare key
    var key_ptr = _heap_alloc[UInt8](16).as_any_origin()
    for i in range(16):
        key_ptr[i] = server_secret[i]

    # Prepare AAD
    var aad_str = String("mojo-net-retry-v1")
    var aad_bytes = aad_str.as_bytes()
    var aad_len = len(aad_bytes)
    var aad_ptr = _heap_alloc[UInt8](aad_len).as_any_origin()
    for i in range(aad_len):
        aad_ptr[i] = aad_bytes[i]

    # Output buffer for plaintext (ct_len - 16 bytes)
    var pt_cap = ct_len - 16
    if pt_cap < 0:
        nonce_ptr.free()
        ct_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        raise "token ciphertext too short"

    var out_ptr = _heap_alloc[UInt8](pt_cap).as_any_origin()
    var out_len_ptr = _heap_alloc[Int32](1).as_any_origin()
    out_len_ptr[0] = Int32(0)

    var rc = lib[].aes_gcm_128_open(
        key_ptr,
        Int32(16),
        nonce_ptr,
        Int32(12),
        aad_ptr,
        Int32(aad_len),
        ct_ptr,
        Int32(ct_len),
        out_ptr,
        out_len_ptr,
    )

    if rc != 0:
        var err = lib[].last_error()
        nonce_ptr.free()
        ct_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "token authentication failed: " + err

    var pt_len = Int(out_len_ptr[0])

    # Parse plaintext: dcid_len (1) || dcid || addr_hash (32) || timestamp (8)
    if pt_len < 1 + 0 + 32 + 8:
        nonce_ptr.free()
        ct_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "decrypted token plaintext too short"

    var dcid_len = Int(out_ptr[0])
    if 1 + dcid_len + 32 + 8 != pt_len:
        nonce_ptr.free()
        ct_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "token plaintext length mismatch"

    # Extract orig_dcid
    var orig_dcid = List[UInt8](capacity=dcid_len)
    for i in range(dcid_len):
        orig_dcid.append(out_ptr[1 + i])

    # Verify addr_hash
    var hash_offset = 1 + dcid_len
    for i in range(32):
        if out_ptr[hash_offset + i] != client_addr_hash[i]:
            nonce_ptr.free()
            ct_ptr.free()
            key_ptr.free()
            aad_ptr.free()
            out_ptr.free()
            out_len_ptr.free()
            raise "token address hash mismatch"

    # Verify timestamp
    var ts_offset = hash_offset + 32
    var timestamp = _read_u64_be(out_ptr, ts_offset)
    if now < timestamp or (now - timestamp) > max_age:
        nonce_ptr.free()
        ct_ptr.free()
        key_ptr.free()
        aad_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "token expired"

    # Cleanup
    nonce_ptr.free()
    ct_ptr.free()
    key_ptr.free()
    aad_ptr.free()
    out_ptr.free()
    out_len_ptr.free()

    return orig_dcid^


def compute_retry_integrity_tag(
    lib_addr: UInt64,
    orig_dcid: Span[UInt8, _],
    retry_packet_without_tag: Span[UInt8, _],
) raises -> List[UInt8]:
    """Compute the 16-byte Retry Integrity Tag per RFC 9001 Section 5.8.

    Uses fixed key/nonce from the spec, with the pseudo-Retry packet as AAD
    and empty plaintext.
    """
    var lib = UnsafePointer[RustlsLibrary, MutAnyOrigin](unsafe_from_address=Int(lib_addr))

    # Fixed key: 0xbe0c690b9f66575a1d766b54e368c84e
    var key_ptr = _heap_alloc[UInt8](16).as_any_origin()
    key_ptr[0] = 0xBE
    key_ptr[1] = 0x0C
    key_ptr[2] = 0x69
    key_ptr[3] = 0x0B
    key_ptr[4] = 0x9F
    key_ptr[5] = 0x66
    key_ptr[6] = 0x57
    key_ptr[7] = 0x5A
    key_ptr[8] = 0x1D
    key_ptr[9] = 0x76
    key_ptr[10] = 0x6B
    key_ptr[11] = 0x54
    key_ptr[12] = 0xE3
    key_ptr[13] = 0x68
    key_ptr[14] = 0xC8
    key_ptr[15] = 0x4E

    # Fixed nonce: 0x461599d35d632bf2239825bb
    var nonce_ptr = _heap_alloc[UInt8](12).as_any_origin()
    nonce_ptr[0] = 0x46
    nonce_ptr[1] = 0x15
    nonce_ptr[2] = 0x99
    nonce_ptr[3] = 0xD3
    nonce_ptr[4] = 0x5D
    nonce_ptr[5] = 0x63
    nonce_ptr[6] = 0x2B
    nonce_ptr[7] = 0xF2
    nonce_ptr[8] = 0x23
    nonce_ptr[9] = 0x98
    nonce_ptr[10] = 0x25
    nonce_ptr[11] = 0xBB

    # Build pseudo-Retry: orig_dcid_len (1) || orig_dcid || retry_packet_without_tag
    var aad_len = 1 + len(orig_dcid) + len(retry_packet_without_tag)
    var aad_ptr = _heap_alloc[UInt8](aad_len).as_any_origin()
    aad_ptr[0] = UInt8(len(orig_dcid))
    var off = 1
    off = _copy_span_to_ptr(orig_dcid, aad_ptr, off)
    off = _copy_span_to_ptr(retry_packet_without_tag, aad_ptr, off)

    # Empty plaintext, output is just the 16-byte tag
    var empty_ptr = _heap_alloc[UInt8](1).as_any_origin()  # dummy, not used
    var out_ptr = _heap_alloc[UInt8](16).as_any_origin()
    var out_len_ptr = _heap_alloc[Int32](1).as_any_origin()
    out_len_ptr[0] = Int32(0)

    var rc = lib[].aes_gcm_128_seal(
        key_ptr,
        Int32(16),
        nonce_ptr,
        Int32(12),
        aad_ptr,
        Int32(aad_len),
        empty_ptr,
        Int32(0),
        out_ptr,
        out_len_ptr,
    )

    if rc != 0:
        var err = lib[].last_error()
        key_ptr.free()
        nonce_ptr.free()
        aad_ptr.free()
        empty_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "Retry integrity tag computation failed: " + err

    var tag_len = Int(out_len_ptr[0])
    if tag_len != 16:
        key_ptr.free()
        nonce_ptr.free()
        aad_ptr.free()
        empty_ptr.free()
        out_ptr.free()
        out_len_ptr.free()
        raise "expected 16-byte tag, got " + String(tag_len)

    var tag = List[UInt8](capacity=16)
    for i in range(16):
        tag.append(out_ptr[i])

    # Cleanup
    key_ptr.free()
    nonce_ptr.free()
    aad_ptr.free()
    empty_ptr.free()
    out_ptr.free()
    out_len_ptr.free()

    return tag^
