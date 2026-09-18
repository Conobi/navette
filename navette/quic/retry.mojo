# src/quic/retry.mojo
# Stateless Retry token generation/validation and integrity tag computation.
# RFC 9001 Section 8.1 (Retry), Appendix A.4 (integrity tag test vector).

from std.ffi import external_call
from std.memory import Pointer
from std.collections import Span

from navette.util.owned_alloc import Owned
from navette.tls.lib import SharedLibrary


# --- RFC 9001 Section 5.8: Retry Integrity Tag key and nonce (QUIC v1) ---
# Key: 0xbe0c690b9f66575a1d766b54e368c84e
# Nonce: 0x461599d35d632bf2239825bb


def _copy_span_to_ptr(
    src: Span[Byte, _],
    dst: Pointer[mut=True, T=UInt8, origin=_],
    offset: Int,
) -> Int:
    """Copy span bytes into dst starting at offset. Returns new offset."""
    for i in range(len(src)):
        dst[unsafe_offset=offset + i] = src[i]
    return offset + len(src)


def _write_u64_be(
    dst: Pointer[mut=True, T=UInt8, origin=_], offset: Int, value: UInt64
) -> Int:
    """Write a UInt64 in big-endian at offset. Returns new offset."""
    dst[unsafe_offset=offset + 0] = UInt8((value >> 56) & 0xFF)
    dst[unsafe_offset=offset + 1] = UInt8((value >> 48) & 0xFF)
    dst[unsafe_offset=offset + 2] = UInt8((value >> 40) & 0xFF)
    dst[unsafe_offset=offset + 3] = UInt8((value >> 32) & 0xFF)
    dst[unsafe_offset=offset + 4] = UInt8((value >> 24) & 0xFF)
    dst[unsafe_offset=offset + 5] = UInt8((value >> 16) & 0xFF)
    dst[unsafe_offset=offset + 6] = UInt8((value >> 8) & 0xFF)
    dst[unsafe_offset=offset + 7] = UInt8(value & 0xFF)
    return offset + 8


def _read_u64_be(
    src: Pointer[mut=True, T=UInt8, origin=_], offset: Int
) -> UInt64:
    """Read a big-endian UInt64 from src at offset."""
    return (
        (UInt64(src[unsafe_offset=offset + 0]) << 56)
        | (UInt64(src[unsafe_offset=offset + 1]) << 48)
        | (UInt64(src[unsafe_offset=offset + 2]) << 40)
        | (UInt64(src[unsafe_offset=offset + 3]) << 32)
        | (UInt64(src[unsafe_offset=offset + 4]) << 24)
        | (UInt64(src[unsafe_offset=offset + 5]) << 16)
        | (UInt64(src[unsafe_offset=offset + 6]) << 8)
        | UInt64(src[unsafe_offset=offset + 7])
    )


def generate_retry_token(
    lib: SharedLibrary,
    server_secret: Span[Byte, _],
    orig_dcid: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now: UInt64,
) raises -> List[Byte]:
    """Generate an encrypted Retry token. Delegates to generate_retry_token_into."""
    var result = List[Byte]()
    generate_retry_token_into(
        result, lib, server_secret, orig_dcid, client_addr_hash, now
    )
    return result^


def generate_retry_token_into(
    mut buf: List[Byte],
    lib: SharedLibrary,
    server_secret: Span[Byte, _],
    orig_dcid: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now: UInt64,
) raises:
    """Generate an encrypted Retry token, appending it directly to buf.

    Token format: nonce (12) || ciphertext+tag
    Plaintext: dcid_len (1) || orig_dcid || addr_hash (32) || timestamp (8 BE)
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != 32:
        raise "client_addr_hash must be 32 bytes"
    if len(orig_dcid) > 20:
        raise "orig_dcid too long"

    var rlib = lib.inner_ptr()

    # Build plaintext: 1 + dcid_len + 32 + 8
    var pt_len = 1 + len(orig_dcid) + 32 + 8
    var pt_buf = Owned[UInt8](pt_len)
    var pt_ptr = pt_buf.ptr()
    pt_ptr[unsafe_offset=0] = UInt8(len(orig_dcid))
    var off = 1
    off = _copy_span_to_ptr(orig_dcid, pt_ptr, off)
    off = _copy_span_to_ptr(client_addr_hash, pt_ptr, off)
    _ = _write_u64_be(pt_ptr, off, now)

    # Generate 12-byte random nonce via getrandom(2).
    var nonce_buf = Owned[UInt8](12)
    var nonce_ptr = nonce_buf.ptr()
    _ = external_call["getrandom", Int](nonce_ptr, UInt64(12), UInt32(0))

    # Prepare key pointer
    var key_buf = Owned[UInt8](16)
    var key_ptr = key_buf.ptr()
    _ = _copy_span_to_ptr(server_secret, key_ptr, 0)

    # Prepare AAD
    var aad_str = String("navette-retry-v1")
    var aad_bytes = aad_str.as_bytes()
    var aad_len = len(aad_bytes)
    var aad_buf = Owned[UInt8](aad_len)
    var aad_ptr = aad_buf.ptr()
    for i in range(aad_len):
        aad_ptr[unsafe_offset=i] = aad_bytes[i]

    # Output buffer: plaintext + 16-byte tag
    var out_cap = pt_len + 16
    var out_buf = Owned[UInt8](out_cap)
    var out_ptr = out_buf.ptr()
    var out_len_buf = Owned[Int32](1)
    var out_len_ptr = out_len_buf.ptr()
    out_len_ptr[unsafe_offset=0] = Int32(0)

    var rc = rlib[].aes_gcm_128_seal(
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
        var err = rlib[].last_error()
        raise "AES-GCM-128 seal failed: " + err

    var ct_len = Int(out_len_ptr[unsafe_offset=0])

    # Append token: nonce (12) || ciphertext+tag
    for i in range(12):
        buf.append(nonce_ptr[unsafe_offset=i])
    for i in range(ct_len):
        buf.append(out_ptr[unsafe_offset=i])

    # Keep the post-FFI-read buffers alive through their last reads above.
    _ = nonce_buf
    _ = out_buf
    _ = out_len_buf


def validate_retry_token(
    lib: SharedLibrary,
    server_secret: Span[Byte, _],
    token: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now: UInt64,
    max_age: UInt64 = 5,
) raises -> List[Byte]:
    """Validate a Retry token and return the original DCID.

    Delegates to validate_retry_token_into.
    """
    var result = List[Byte]()
    validate_retry_token_into(
        result, lib, server_secret, token, client_addr_hash, now, max_age
    )
    return result^


def validate_retry_token_into(
    mut buf: List[Byte],
    lib: SharedLibrary,
    server_secret: Span[Byte, _],
    token: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now: UInt64,
    max_age: UInt64 = 5,
) raises:
    """Validate a Retry token, appending the original DCID directly to buf.

    Raises on authentication failure, address mismatch, or expiration.
    buf is only appended to once every check has passed, so a rejected
    token never leaves partial output in the caller's buffer.
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != 32:
        raise "client_addr_hash must be 32 bytes"
    # Minimum: 12 (nonce) + 16 (tag) = 28 bytes
    if len(token) < 28:
        raise "token too short"

    var rlib = lib.inner_ptr()

    # Extract nonce (first 12 bytes) and ciphertext+tag (rest)
    var nonce_buf = Owned[UInt8](12)
    var nonce_ptr = nonce_buf.ptr()
    for i in range(12):
        nonce_ptr[unsafe_offset=i] = token[i]

    var ct_len = len(token) - 12
    var ct_buf = Owned[UInt8](ct_len)
    var ct_ptr = ct_buf.ptr()
    for i in range(ct_len):
        ct_ptr[unsafe_offset=i] = token[12 + i]

    # Prepare key
    var key_buf = Owned[UInt8](16)
    var key_ptr = key_buf.ptr()
    for i in range(16):
        key_ptr[unsafe_offset=i] = server_secret[i]

    # Prepare AAD
    var aad_str = String("navette-retry-v1")
    var aad_bytes = aad_str.as_bytes()
    var aad_len = len(aad_bytes)
    var aad_buf = Owned[UInt8](aad_len)
    var aad_ptr = aad_buf.ptr()
    for i in range(aad_len):
        aad_ptr[unsafe_offset=i] = aad_bytes[i]

    # Output buffer for plaintext (ct_len - 16 bytes)
    var pt_cap = ct_len - 16
    if pt_cap < 0:
        raise "token ciphertext too short"

    var out_buf = Owned[UInt8](pt_cap)
    var out_ptr = out_buf.ptr()
    var out_len_buf = Owned[Int32](1)
    var out_len_ptr = out_len_buf.ptr()
    out_len_ptr[unsafe_offset=0] = Int32(0)

    var rc = rlib[].aes_gcm_128_open(
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
        var err = rlib[].last_error()
        raise "token authentication failed: " + err

    var pt_len = Int(out_len_ptr[unsafe_offset=0])

    # Parse plaintext: dcid_len (1) || dcid || addr_hash (32) || timestamp (8)
    if pt_len < 1 + 0 + 32 + 8:
        raise "decrypted token plaintext too short"

    var dcid_len = Int(out_ptr[unsafe_offset=0])
    if 1 + dcid_len + 32 + 8 != pt_len:
        raise "token plaintext length mismatch"

    # Verify addr_hash
    var hash_offset = 1 + dcid_len
    for i in range(32):
        if out_ptr[unsafe_offset=hash_offset + i] != client_addr_hash[i]:
            raise "token address hash mismatch"

    # Verify timestamp
    var ts_offset = hash_offset + 32
    var timestamp = _read_u64_be(out_ptr, ts_offset)
    if now < timestamp or (now - timestamp) > max_age:
        raise "token expired"

    # Append orig_dcid only after every check above has passed.
    for i in range(dcid_len):
        buf.append(out_ptr[unsafe_offset=1 + i])

    # Keep the post-FFI-read output buffers alive through their last reads above.
    _ = out_buf
    _ = out_len_buf


def compute_retry_integrity_tag(
    lib: SharedLibrary,
    orig_dcid: Span[Byte, _],
    retry_packet_without_tag: Span[Byte, _],
) raises -> List[Byte]:
    """Compute the 16-byte Retry Integrity Tag. Delegates to compute_retry_integrity_tag_into."""
    var result = List[Byte]()
    compute_retry_integrity_tag_into(
        result, lib, orig_dcid, retry_packet_without_tag
    )
    return result^


def compute_retry_integrity_tag_into(
    mut buf: List[Byte],
    lib: SharedLibrary,
    orig_dcid: Span[Byte, _],
    retry_packet_without_tag: Span[Byte, _],
) raises:
    """Compute the 16-byte Retry Integrity Tag per RFC 9001 Section 5.8, appending to buf.

    Uses fixed key/nonce from the spec, with the pseudo-Retry packet as AAD
    and empty plaintext.
    """
    var rlib = lib.inner_ptr()

    # Fixed key: 0xbe0c690b9f66575a1d766b54e368c84e
    var key_buf = Owned[UInt8](16)
    var key_ptr = key_buf.ptr()
    key_ptr[unsafe_offset=0] = 0xBE
    key_ptr[unsafe_offset=1] = 0x0C
    key_ptr[unsafe_offset=2] = 0x69
    key_ptr[unsafe_offset=3] = 0x0B
    key_ptr[unsafe_offset=4] = 0x9F
    key_ptr[unsafe_offset=5] = 0x66
    key_ptr[unsafe_offset=6] = 0x57
    key_ptr[unsafe_offset=7] = 0x5A
    key_ptr[unsafe_offset=8] = 0x1D
    key_ptr[unsafe_offset=9] = 0x76
    key_ptr[unsafe_offset=10] = 0x6B
    key_ptr[unsafe_offset=11] = 0x54
    key_ptr[unsafe_offset=12] = 0xE3
    key_ptr[unsafe_offset=13] = 0x68
    key_ptr[unsafe_offset=14] = 0xC8
    key_ptr[unsafe_offset=15] = 0x4E

    # Fixed nonce: 0x461599d35d632bf2239825bb
    var nonce_buf = Owned[UInt8](12)
    var nonce_ptr = nonce_buf.ptr()
    nonce_ptr[unsafe_offset=0] = 0x46
    nonce_ptr[unsafe_offset=1] = 0x15
    nonce_ptr[unsafe_offset=2] = 0x99
    nonce_ptr[unsafe_offset=3] = 0xD3
    nonce_ptr[unsafe_offset=4] = 0x5D
    nonce_ptr[unsafe_offset=5] = 0x63
    nonce_ptr[unsafe_offset=6] = 0x2B
    nonce_ptr[unsafe_offset=7] = 0xF2
    nonce_ptr[unsafe_offset=8] = 0x23
    nonce_ptr[unsafe_offset=9] = 0x98
    nonce_ptr[unsafe_offset=10] = 0x25
    nonce_ptr[unsafe_offset=11] = 0xBB

    # Build pseudo-Retry: orig_dcid_len (1) || orig_dcid || retry_packet_without_tag
    var aad_len = 1 + len(orig_dcid) + len(retry_packet_without_tag)
    var aad_buf = Owned[UInt8](aad_len)
    var aad_ptr = aad_buf.ptr()
    aad_ptr[unsafe_offset=0] = UInt8(len(orig_dcid))
    var off = 1
    off = _copy_span_to_ptr(orig_dcid, aad_ptr, off)
    _ = _copy_span_to_ptr(retry_packet_without_tag, aad_ptr, off)

    # Empty plaintext, output is just the 16-byte tag
    var empty_buf = Owned[UInt8](1)  # dummy, not used
    var empty_ptr = empty_buf.ptr()
    var out_buf = Owned[UInt8](16)
    var out_ptr = out_buf.ptr()
    var out_len_buf = Owned[Int32](1)
    var out_len_ptr = out_len_buf.ptr()
    out_len_ptr[unsafe_offset=0] = Int32(0)

    var rc = rlib[].aes_gcm_128_seal(
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
        var err = rlib[].last_error()
        raise "Retry integrity tag computation failed: " + err

    var tag_len = Int(out_len_ptr[unsafe_offset=0])
    if tag_len != 16:
        raise "expected 16-byte tag, got " + String(tag_len)

    for i in range(16):
        buf.append(out_ptr[unsafe_offset=i])

    # Keep the post-FFI-read output buffers alive through their last reads above.
    _ = out_buf
    _ = out_len_buf
