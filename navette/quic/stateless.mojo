"""Packets the server sends without connection state: Retry and stateless close.

Each builder clears the caller's buffer and writes one complete datagram
into it. None allocates beyond that buffer (the caller reserves 256
bytes), so a flood of junk Initials costs crypto work, not heap traffic.
Bounds and admission are the caller's job; these only encode.
"""

from std.collections import InlineArray, Span

from navette.quic.codec import varint_len, varint_encode_at
from navette.quic.packet_protect import PacketProtect
from navette.quic.retry import RETRY_INTEGRITY_KEY, RETRY_INTEGRITY_NONCE
from navette.tls.lib import SharedLibrary

comptime RETRY_SCID_LEN: Int = 8
comptime _MAX_CID_LEN: Int = 20
comptime _QUIC_V1: UInt32 = 1
comptime _TAG_LEN: Int = 16
comptime _MAX_PN_LEN: Int = 4
comptime _FRAME_CONNECTION_CLOSE: UInt8 = 0x1C


def _append_u32_be(mut out: List[Byte], v: UInt32):
    for i in range(4):
        out.append(UInt8((v >> UInt32(8 * (3 - i))) & 0xFF))


def _append_cid(mut out: List[Byte], cid: Span[Byte, _]):
    out.append(UInt8(len(cid)))
    out.extend(cid)


def build_retry(
    mut out: List[Byte],
    lib: SharedLibrary,
    client_dcid: Span[Byte, _],
    client_scid: Span[Byte, _],
    retry_scid: Span[Byte, _],
    token: Span[Byte, _],
) raises:
    """Retry to a client whose Initial carried `client_dcid` / `client_scid` (RFC 9000 Section 17.2.5).

    `client_dcid` is the original DCID: it never appears on the wire but
    keys the integrity tag (RFC 9001 Section 5.8), so the client can tell
    the Retry answers its own Initial. `retry_scid` becomes the client's
    new DCID and must differ from `client_dcid`. Raises on a CID over 20
    bytes or an empty token (a client drops a token-less Retry).
    """
    if len(client_dcid) > _MAX_CID_LEN or len(client_scid) > _MAX_CID_LEN or len(retry_scid) > _MAX_CID_LEN:
        raise "build_retry: connection ID longer than 20 bytes"
    if len(token) == 0:
        raise "build_retry: empty token"
    # Write the pseudo-Retry packet (RFC 9001 Section 5.8) in place: the
    # original DCID prefix is the tag's AAD, then it is shifted out.
    out.clear()
    _append_cid(out, client_dcid)
    var prefix = len(out)
    out.append(0xF0)
    _append_u32_be(out, _QUIC_V1)
    _append_cid(out, client_scid)
    _append_cid(out, retry_scid)
    out.extend(token)

    var key = materialize[RETRY_INTEGRITY_KEY]()
    var nonce = materialize[RETRY_INTEGRITY_NONCE]()
    var tag = InlineArray[UInt8, _TAG_LEN](fill=UInt8(0))
    var tag_len = InlineArray[Int32, 1](fill=Int32(0))
    var no_plaintext = InlineArray[UInt8, 1](fill=UInt8(0))
    var rc = lib.inner_ptr()[].aes_gcm_128_seal(
        key.unsafe_ptr(), Int32(16),
        nonce.unsafe_ptr(), Int32(12),
        out.unsafe_ptr(), Int32(len(out)),
        no_plaintext.unsafe_ptr(), Int32(0),
        tag.unsafe_ptr(), tag_len.unsafe_ptr(),
    )
    if rc != 0 or Int(tag_len[0]) != _TAG_LEN:
        raise "build_retry: integrity tag computation failed"

    var pkt_len = len(out) - prefix
    for i in range(pkt_len):
        out[i] = out[prefix + i]
    out.resize(pkt_len, Byte(0))
    for i in range(_TAG_LEN):
        out.append(tag[i])


def build_stateless_close_initial(
    mut out: List[Byte],
    mut protect: PacketProtect,
    client_dcid: Span[Byte, _],
    client_scid: Span[Byte, _],
    server_scid: Span[Byte, _],
    error_code: UInt64,
) raises:
    """Initial carrying a transport CONNECTION_CLOSE with `error_code`, sealed with the client's Initial keys.

    RFC 9000 Section 10.2: the server keeps no closing state, it answers
    once and forgets. `client_dcid` derives the keys (RFC 9001 Section
    5.2) and replaces whatever Initial keys `protect` held at level 0.
    CONNECTION_CLOSE is not ack-eliciting, so the packet is not padded to
    1,200 bytes (RFC 9000 Section 14.1): it stays far smaller than the
    client's Initial and cannot amplify. Raises on a CID over 20 bytes
    or an error code that is not a varint.
    """
    if len(client_dcid) > _MAX_CID_LEN or len(client_scid) > _MAX_CID_LEN or len(server_scid) > _MAX_CID_LEN:
        raise "build_stateless_close_initial: connection ID longer than 20 bytes"
    if error_code >= (UInt64(1) << 62):
        raise "build_stateless_close_initial: error code exceeds 2^62 - 1"
    protect.derive_initial_keys(client_dcid, is_client=False)

    # Frame: type, error code, offending frame type 0, empty reason.
    var frame_len = 1 + varint_len(error_code) + 1 + 1
    # Header protection samples 16 bytes from pn_offset + 4, and the PN is
    # one byte: the plaintext needs at least 3 bytes (RFC 9001 Section 5.4.2).
    var plaintext_len = max(frame_len, _MAX_PN_LEN - 1)
    var length_field = UInt64(1 + plaintext_len + _TAG_LEN)

    out.clear()
    out.append(0xC0)  # Initial, 1-byte packet number
    _append_u32_be(out, _QUIC_V1)
    _append_cid(out, client_scid)
    _append_cid(out, server_scid)
    out.append(0x00)  # token length
    out.append(UInt8(0x40 | (length_field >> 8)))  # 2-byte varint
    out.append(UInt8(length_field & 0xFF))
    var pn_offset = len(out)
    out.append(0x00)  # packet number 0

    var payload_start = len(out)
    out.append(_FRAME_CONNECTION_CLOSE)
    var code_at = len(out)
    out.resize(code_at + varint_len(error_code), Byte(0))
    _ = varint_encode_at(out, code_at, error_code)
    out.append(0x00)  # frame type
    out.append(0x00)  # reason length
    out.resize(payload_start + plaintext_len + _TAG_LEN, Byte(0))  # PADDING, then tag room

    var total_len = len(out)
    var pkt_ptr = out.unsafe_ptr().unsafe_mut_cast[True]().as_unsafe_any_origin()
    _ = protect.encrypt_payload_in_place(0, UInt64(0), pkt_ptr, payload_start, plaintext_len, total_len)
    protect.protect_header_ptr(0, pkt_ptr, total_len, pn_offset, 1)
