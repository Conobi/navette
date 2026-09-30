# src/quic/retry.mojo
# Stateless Retry token generation/classification and integrity tag computation.
# RFC 9000 Section 8.1 (address validation), RFC 9001 Section 5.8
# (integrity tag, Appendix A.4 test vector).

from std.memory import Pointer
from std.collections import InlineArray, Span

from navette.util.owned_alloc import Owned
from navette.util.secure_random import fill_random
from navette.util.sha256 import sha256
from navette.util.sockaddr import sockaddr_ip, SOCKADDR_PORT_OFFSET
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


comptime RETRY_TOKEN_TYPE: UInt8 = 0x01
comptime RETRY_TOKEN_LIFETIME_US: UInt64 = 10_000_000
# Length of the shortest genuine token (empty original DCID): type (1) +
# nonce (12) + dcid_len (1) + addr_hash (32) + timestamp (8) + AEAD tag
# (16). A type-0x01 token shorter than this cannot be ours, so it is
# NONE (answer with a Retry), never INVALID (an INVALID_TOKEN close).
comptime RETRY_TOKEN_MIN_LEN: Int = 70
# Length of the longest genuine token (20-byte original DCID). A longer
# type-0x01 token cannot be ours either, so it is NONE as well.
comptime RETRY_TOKEN_MAX_LEN: Int = RETRY_TOKEN_MIN_LEN + 20
comptime TOKEN_NONE: Int = 0
comptime TOKEN_VALID: Int = 1
comptime TOKEN_INVALID: Int = 2

# Why a type-0x01 token was rejected. Integers, not messages, so the
# INVALID path of `classify_retry_token` allocates nothing.
comptime RETRY_REJECT_OK: Int = 0
comptime RETRY_REJECT_OVERSIZED: Int = 1
comptime RETRY_REJECT_AUTH: Int = 2
comptime RETRY_REJECT_LENGTH: Int = 3
comptime RETRY_REJECT_ADDRESS: Int = 4
comptime RETRY_REJECT_FUTURE: Int = 5
comptime RETRY_REJECT_EXPIRED: Int = 6
comptime RETRY_REJECT_UNDERSIZED: Int = 7

comptime _NONCE_LEN: Int = 12
comptime _TAG_LEN: Int = 16
comptime _HASH_LEN: Int = 32
# dcid_len (1) + orig_dcid (<= 20) + addr_hash (32) + timestamp (8).
comptime _MAX_PT_LEN: Int = 61
comptime _AAD_LABEL = "navette-retry-v2"
comptime _AAD_LEN: Int = 17


struct RetryTokenScratch(Movable):
    """Caller-owned buffers for token sealing and opening; one per server, reused for every Retry.

    Keeps the Retry path allocation-free: a flood of token-less Initials
    costs AEAD work only, never heap traffic. The AAD is the label plus
    the token type byte, so a token of another type can never open.
    """

    var key: InlineArray[UInt8, 16]
    var nonce: InlineArray[UInt8, _NONCE_LEN]
    var aad: InlineArray[UInt8, _AAD_LEN]
    var pt: InlineArray[UInt8, _MAX_PT_LEN]
    var ct: InlineArray[UInt8, _MAX_PT_LEN + _TAG_LEN]
    var out_len: InlineArray[Int32, 1]

    def __init__(out self):
        self.key = InlineArray[UInt8, 16](fill=UInt8(0))
        self.nonce = InlineArray[UInt8, _NONCE_LEN](fill=UInt8(0))
        self.aad = InlineArray[UInt8, _AAD_LEN](fill=UInt8(0))
        var label = StringSlice(_AAD_LABEL).as_bytes()
        for i in range(_AAD_LEN - 1):
            self.aad[i] = label[i]
        self.aad[_AAD_LEN - 1] = RETRY_TOKEN_TYPE
        self.pt = InlineArray[UInt8, _MAX_PT_LEN](fill=UInt8(0))
        self.ct = InlineArray[UInt8, _MAX_PT_LEN + _TAG_LEN](fill=UInt8(0))
        self.out_len = InlineArray[Int32, 1](fill=Int32(0))


def retry_addr_hash(sockaddr: Span[Byte, _]) -> InlineArray[UInt8, 32]:
    """SHA-256 of the peer's IP address bytes (4, or 16) and port (big-endian).

    `flowinfo` and `scope_id` are not read, and an IPv4-mapped IPv6
    address hashes as its 4 IPv4 bytes, so the token survives the
    dual-stack socket reporting the same peer either way. A malformed
    blob (no parsable IP) yields all zeros instead of a digest:
    `generate_retry_token` refuses it and classification rejects it as
    an address mismatch, so two malformed names can never share a token.
    """
    var ip = sockaddr_ip(sockaddr)
    var ip_off = ip[0]
    var ip_len = ip[1]
    if ip_len == 0:
        return InlineArray[UInt8, 32](fill=UInt8(0))
    var msg = InlineArray[UInt8, 18](fill=UInt8(0))
    for i in range(ip_len):
        msg[i] = sockaddr[ip_off + i]
    msg[ip_len] = sockaddr[SOCKADDR_PORT_OFFSET]
    msg[ip_len + 1] = sockaddr[SOCKADDR_PORT_OFFSET + 1]
    return sha256(Span(msg)[: ip_len + 2])


def _is_unusable_addr_hash(client_addr_hash: Span[Byte, _]) -> Bool:
    """True for the all-zero hash `retry_addr_hash` returns for a malformed sockaddr (no SHA-256 preimage is known)."""
    var acc = UInt8(0)
    for i in range(len(client_addr_hash)):
        acc |= client_addr_hash[i]
    return acc == 0


def generate_retry_token(
    mut buf: List[Byte],
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    server_secret: Span[Byte, _],
    orig_dcid: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now_us: UInt64,
) raises:
    """Append a Retry token for `orig_dcid` issued at `now_us` (µs) to `buf`.

    Token: `type (0x01) ‖ nonce (12) ‖ AES-128-GCM(dcid_len ‖ orig_dcid ‖
    addr_hash (32) ‖ timestamp µs (8, BE))`, AAD = label ‖ type: 70 bytes
    plus the DCID length (`RETRY_TOKEN_MIN_LEN` .. `RETRY_TOKEN_MAX_LEN`). Raises only on a
    caller error (secret, hash or DCID length, or the all-zero hash of a
    malformed peer address), an FFI failure, or a failed kernel RNG draw.
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != _HASH_LEN:
        raise "client_addr_hash must be 32 bytes"
    if len(orig_dcid) > 20:
        raise "orig_dcid too long"
    if _is_unusable_addr_hash(client_addr_hash):
        raise "unusable peer address: malformed sockaddr"

    var pt_len = 1 + len(orig_dcid) + _HASH_LEN + 8
    scratch.pt[0] = UInt8(len(orig_dcid))
    for i in range(len(orig_dcid)):
        scratch.pt[1 + i] = orig_dcid[i]
    var off = 1 + len(orig_dcid)
    for i in range(_HASH_LEN):
        scratch.pt[off + i] = client_addr_hash[i]
    off += _HASH_LEN
    for i in range(8):
        scratch.pt[off + i] = UInt8((now_us >> UInt64(56 - 8 * i)) & 0xFF)
    for i in range(16):
        scratch.key[i] = server_secret[i]
    # A partial fill would leave the previous token's nonce in scratch:
    # GCM nonce reuse under one key leaks the authentication key.
    fill_random(Span(scratch.nonce))
    scratch.out_len[0] = 0

    var rc = lib.inner_ptr()[].aes_gcm_128_seal(
        scratch.key.unsafe_ptr(), Int32(16),
        scratch.nonce.unsafe_ptr(), Int32(_NONCE_LEN),
        scratch.aad.unsafe_ptr(), Int32(_AAD_LEN),
        scratch.pt.unsafe_ptr(), Int32(pt_len),
        scratch.ct.unsafe_ptr(), scratch.out_len.unsafe_ptr(),
    )
    if rc != 0:
        raise "AES-GCM-128 seal failed: " + lib.inner_ptr()[].last_error()

    buf.append(RETRY_TOKEN_TYPE)
    buf.extend(Span(scratch.nonce))
    buf.extend(Span(scratch.ct)[: Int(scratch.out_len[0])])


def _open_retry_token(
    mut orig_dcid_out: List[Byte],
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    server_secret: Span[Byte, _],
    token: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now_us: UInt64,
    lifetime_us: UInt64,
) raises -> Int:
    """A `RETRY_REJECT_*` code for a type-0x01 token; `RETRY_REJECT_OK` only when valid, and only then is the DCID appended.

    Checks both length bounds itself rather than trusting callers: the
    nonce and ciphertext copies index the token and the fixed scratch
    buffers, so an unchecked short or long token reads or writes out of
    bounds.
    """
    if len(token) < RETRY_TOKEN_MIN_LEN:
        return RETRY_REJECT_UNDERSIZED
    if len(token) > RETRY_TOKEN_MAX_LEN:
        return RETRY_REJECT_OVERSIZED
    if _is_unusable_addr_hash(client_addr_hash):
        return RETRY_REJECT_ADDRESS
    var ct_len = len(token) - 1 - _NONCE_LEN
    for i in range(_NONCE_LEN):
        scratch.nonce[i] = token[1 + i]
    for i in range(ct_len):
        scratch.ct[i] = token[1 + _NONCE_LEN + i]
    for i in range(16):
        scratch.key[i] = server_secret[i]
    scratch.out_len[0] = 0
    var rc = lib.inner_ptr()[].aes_gcm_128_open(
        scratch.key.unsafe_ptr(), Int32(16),
        scratch.nonce.unsafe_ptr(), Int32(_NONCE_LEN),
        scratch.aad.unsafe_ptr(), Int32(_AAD_LEN),
        scratch.ct.unsafe_ptr(), Int32(ct_len),
        scratch.pt.unsafe_ptr(), scratch.out_len.unsafe_ptr(),
    )
    if rc != 0:
        return RETRY_REJECT_AUTH
    var pt_len = Int(scratch.out_len[0])
    var dcid_len = Int(scratch.pt[0])
    if pt_len < 1 + _HASH_LEN + 8 or 1 + dcid_len + _HASH_LEN + 8 != pt_len:
        return RETRY_REJECT_LENGTH
    var hash_off = 1 + dcid_len
    for i in range(_HASH_LEN):
        if scratch.pt[hash_off + i] != client_addr_hash[i]:
            return RETRY_REJECT_ADDRESS
    var ts = UInt64(0)
    for i in range(8):
        ts = (ts << 8) | UInt64(scratch.pt[hash_off + _HASH_LEN + i])
    if now_us < ts:
        return RETRY_REJECT_FUTURE
    if now_us - ts > lifetime_us:
        return RETRY_REJECT_EXPIRED
    orig_dcid_out.extend(Span(scratch.pt)[1 : 1 + dcid_len])
    return RETRY_REJECT_OK


def classify_retry_token(
    mut orig_dcid_out: List[Byte],
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    server_secret: Span[Byte, _],
    token: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now_us: UInt64,
    lifetime_us: UInt64,
) raises -> Int:
    """TOKEN_NONE, TOKEN_VALID or TOKEN_INVALID (RFC 9000 Section 8.1.2-8.1.3); appends the original DCID only when VALID.

    NONE: not identifiably ours — wrong type or length, or it does not
    open under our secret (a flipped bit, a rotated secret or a foreign
    token that happens to start with 0x01 look the same). Treated as
    absent: answer with a Retry (RFC 9000 Section 8.1.3, erratum 7861).
    INVALID: it opens but fails address validation (address mismatch,
    expiry, future timestamp) or the presenter's address is malformed —
    answer with one INVALID_TOKEN close. Raises only on a caller error or
    an FFI failure, never on token content.
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != _HASH_LEN:
        raise "client_addr_hash must be 32 bytes"
    if (
        len(token) < RETRY_TOKEN_MIN_LEN
        or len(token) > RETRY_TOKEN_MAX_LEN
        or token[0] != RETRY_TOKEN_TYPE
    ):
        return TOKEN_NONE
    var why = _open_retry_token(
        orig_dcid_out, lib, scratch, server_secret, token, client_addr_hash, now_us, lifetime_us
    )
    if why == RETRY_REJECT_OK:
        return TOKEN_VALID
    if why == RETRY_REJECT_AUTH or why == RETRY_REJECT_LENGTH:
        return TOKEN_NONE
    return TOKEN_INVALID


def validate_retry_token(
    mut buf: List[Byte],
    lib: SharedLibrary,
    mut scratch: RetryTokenScratch,
    server_secret: Span[Byte, _],
    token: Span[Byte, _],
    client_addr_hash: Span[Byte, _],
    now_us: UInt64,
    max_age_us: UInt64,
) raises:
    """Raising form of `classify_retry_token`: appends the original DCID, or raises with the reason.

    `max_age_us` has no default: the lifetime is in microseconds, the
    unit of every protocol clock in navette (the server passes
    `RETRY_TOKEN_LIFETIME_US`).
    """
    if len(server_secret) != 16:
        raise "server_secret must be 16 bytes"
    if len(client_addr_hash) != _HASH_LEN:
        raise "client_addr_hash must be 32 bytes"
    if len(token) < RETRY_TOKEN_MIN_LEN:
        raise "token too short"
    if len(token) > RETRY_TOKEN_MAX_LEN:
        raise "token too long"
    if token[0] != RETRY_TOKEN_TYPE:
        raise "not a navette retry token"
    var why = _open_retry_token(
        buf, lib, scratch, server_secret, token, client_addr_hash, now_us, max_age_us
    )
    if why == RETRY_REJECT_AUTH:
        raise "token authentication failed"
    if why == RETRY_REJECT_LENGTH:
        raise "token plaintext length mismatch"
    if why == RETRY_REJECT_ADDRESS:
        raise "token address hash mismatch"
    if why == RETRY_REJECT_FUTURE:
        raise "token timestamp in the future"
    if why == RETRY_REJECT_EXPIRED:
        raise "token expired"
    if why != RETRY_REJECT_OK:
        raise "token rejected"


def compute_retry_integrity_tag(
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

    buf.extend(Span(unsafe_ptr=out_ptr, length=16))

    # Keep the post-FFI-read output buffers alive through their last reads above.
    _ = out_buf
    _ = out_len_buf
