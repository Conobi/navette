//! Raw QUIC packet helper for the TLS-conformance harness.
//!
//! Scenario binaries drive navette's TLS surface with adversarial inputs that
//! h3i and the quiche client API cannot construct. This module synthesises
//! Initial, Handshake, and 1-RTT packets at the wire level on top of
//! `librustls-mojo`'s `rlsm_*` C ABI (keys + AEAD + header protection).
//! Public types are all navette-owned; upstream FFI types never leak.
//!
//! References: RFC 9000 §17 (packet formats), §16 (varints), §14.1
//! (anti-amplification, ≥1200-byte client Initials), RFC 9001 §5.4.2 (HP).

use std::convert::TryFrom;

/// QUIC endpoint role for key derivation (maps to `is_client` int FFI-side).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Role { Client, Server }

/// Error from a `librustls-mojo` FFI call. `code` is the raw `i32` status.
#[derive(Debug)]
pub struct FfiError { pub code: i32 }

/// Owned handle to a `KeysEntry` inside `librustls-mojo`; freed on drop.
/// Inner `i32` is `pub` only so module-internal helpers can call FFI without
/// re-exposing `librustls_mojo` types in the public surface.
pub struct KeysHandle(pub i32);
impl Drop for KeysHandle {
    fn drop(&mut self) {
        if self.0 > 0 {
            // `rlsm_keys_free` returns -1 for unknown handles (idempotent).
            let _ = librustls_mojo::rlsm_keys_free(self.0);
        }
    }
}

/// Parsed long-header view (RFC 9000 §17.2). `payload_offset` points at the
/// first byte of the protected packet number; `length` is the varint Length
/// field (PN + payload + AEAD tag).
#[derive(Debug)]
pub struct LongHeader {
    pub version: u32,
    /// 0 = Initial, 1 = 0-RTT, 2 = Handshake, 3 = Retry.
    pub packet_type: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub payload_offset: usize,
    pub length: usize,
}

/// Parsed short-header view (RFC 9000 §17.3.1).
#[derive(Debug)]
pub struct ShortHeader { pub dcid: Vec<u8>, pub packet_number_offset: usize }

/// Parsed CONNECTION_CLOSE frame (RFC 9000 §19.19). `frame_type` is `0x1c`
/// for transport CC, `0x1d` for application CC.
#[derive(Debug)]
pub struct ConnectionClose { pub error_code: u64, pub frame_type: u8, pub reason: String }

/// QUIC v1 version int expected by `rlsm_initial_keys` (1 → V1, 2 → V2).
const QUIC_VERSION_V1: i32 = 1;
/// Max DCID length permitted by RFC 9000 §17.2 in a v1 long header.
const MAX_CID_LEN: usize = 20;
/// Anti-amplification minimum for client-sent Initial packets (§14.1).
const INITIAL_MIN_BYTES: usize = 1200;

#[inline] fn err() -> FfiError { FfiError { code: -1 } }
#[inline] fn role_to_int(role: Role) -> i32 { match role { Role::Client => 1, Role::Server => 0 } }

/// Derive QUIC v1 Initial keys for the given role + DCID.
pub fn initial_keys(role: Role, dcid: &[u8]) -> Result<KeysHandle, FfiError> {
    let dcid_len = i32::try_from(dcid.len()).map_err(|_| err())?;
    let h = librustls_mojo::rlsm_initial_keys(
        QUIC_VERSION_V1, dcid.as_ptr(), dcid_len, role_to_int(role),
    );
    if h <= 0 { Err(FfiError { code: h }) } else { Ok(KeysHandle(h)) }
}

/// AEAD tag length (16 for QUIC v1 / AES-128-GCM).
fn keys_tag_len(keys: &KeysHandle) -> Result<usize, FfiError> {
    let n = librustls_mojo::rlsm_keys_tag_len(keys.0);
    if n < 0 { Err(FfiError { code: n }) } else { Ok(n as usize) }
}

/// AEAD-encrypt `payload[..plaintext_len]` in place with `header` as AAD.
/// Returns total ciphertext length (plaintext + tag).
fn local_encrypt(
    keys: &KeysHandle, pn: u64, header: &[u8], payload: &mut [u8], plaintext_len: usize,
) -> Result<usize, FfiError> {
    let hl = i32::try_from(header.len()).map_err(|_| err())?;
    let cap = i32::try_from(payload.len()).map_err(|_| err())?;
    let pt = i32::try_from(plaintext_len).map_err(|_| err())?;
    let rc = librustls_mojo::rlsm_keys_local_encrypt(
        keys.0, pn, header.as_ptr(), hl, payload.as_mut_ptr(), pt, cap,
    );
    if rc < 0 { Err(FfiError { code: rc }) } else { Ok(rc as usize) }
}

/// Apply header protection in place using local HP keys (sample = 16 bytes
/// starting at pn_offset + 4 per RFC 9001 §5.4.2).
fn local_header_protect(
    keys: &KeysHandle, sample: &[u8], first_byte: &mut u8, pn_bytes: &mut [u8],
) -> Result<(), FfiError> {
    let sl = i32::try_from(sample.len()).map_err(|_| err())?;
    let pl = i32::try_from(pn_bytes.len()).map_err(|_| err())?;
    let rc = librustls_mojo::rlsm_keys_local_header_protect(
        keys.0, sample.as_ptr(), sl, first_byte as *mut u8, pn_bytes.as_mut_ptr(), pl,
    );
    if rc == 0 { Ok(()) } else { Err(FfiError { code: rc }) }
}

/// AEAD-decrypt `payload` in place with `header` as AAD. Returns plaintext
/// length (ciphertext_len − tag_len).
///
/// Lifted from `#[cfg(test)]` so `drive_handshake_initial` can decrypt the
/// server's Initial reply. `remote_*` keys are the peer's role (server-side
/// when this client is decoding server packets).
pub fn remote_decrypt(
    keys: &KeysHandle, pn: u64, header: &[u8], payload: &mut [u8],
) -> Result<usize, FfiError> {
    let hl = i32::try_from(header.len()).map_err(|_| err())?;
    let pl = i32::try_from(payload.len()).map_err(|_| err())?;
    let rc = librustls_mojo::rlsm_keys_remote_decrypt(
        keys.0, pn, header.as_ptr(), hl, payload.as_mut_ptr(), pl,
    );
    if rc < 0 { Err(FfiError { code: rc }) } else { Ok(rc as usize) }
}

/// Remove header protection in place using the peer's HP keys (sample = 16
/// bytes starting at `pn_offset + 4` per RFC 9001 §5.4.2).
///
/// Lifted from `#[cfg(test)]` so `drive_handshake_initial` can unprotect
/// server replies.
pub fn remote_header_unprotect(
    keys: &KeysHandle, sample: &[u8], first_byte: &mut u8, pn_bytes: &mut [u8],
) -> Result<(), FfiError> {
    let sl = i32::try_from(sample.len()).map_err(|_| err())?;
    let pl = i32::try_from(pn_bytes.len()).map_err(|_| err())?;
    let rc = librustls_mojo::rlsm_keys_remote_header_unprotect(
        keys.0, sample.as_ptr(), sl, first_byte as *mut u8, pn_bytes.as_mut_ptr(), pl,
    );
    if rc == 0 { Ok(()) } else { Err(FfiError { code: rc }) }
}

/// Encode a varint per RFC 9000 §16, appending to `out`. Panics on values ≥ 2^62.
pub fn encode_varint(v: u64, out: &mut Vec<u8>) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        let b = (v as u16).to_be_bytes();
        out.extend_from_slice(&[b[0] | 0x40, b[1]]);
    } else if v < 1 << 30 {
        let b = (v as u32).to_be_bytes();
        out.extend_from_slice(&[b[0] | 0x80, b[1], b[2], b[3]]);
    } else if v < 1 << 62 {
        let b = v.to_be_bytes();
        out.push(b[0] | 0xC0);
        out.extend_from_slice(&b[1..]);
    } else {
        panic!("varint out of range: {v}");
    }
}

/// Decode a varint. Returns `(value, bytes_consumed)`.
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len { return None; }
    let mut v = (first & 0x3F) as u64;
    for &b in &buf[1..len] { v = (v << 8) | b as u64; }
    Some((v, len))
}

fn varint_width(v: u64) -> usize {
    if v < 1 << 6 { 1 } else if v < 1 << 14 { 2 } else if v < 1 << 30 { 4 } else { 8 }
}

/// Wire-level QUIC packet assembler used by scenario binaries.
/// `packet_number` increments after each successful encode so AEAD nonces
/// stay unique per key (the FFI rejects reuse with rc = -1).
pub struct PacketBuilder {
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub packet_number: u64,
}

impl PacketBuilder {
    pub fn new(dcid: Vec<u8>, scid: Vec<u8>) -> Self {
        debug_assert!(dcid.len() <= MAX_CID_LEN);
        debug_assert!(scid.len() <= MAX_CID_LEN);
        Self { dcid, scid, packet_number: 0 }
    }

    /// Encode an Initial packet (RFC 9000 §17.2.2). Wraps `crypto_payload` in
    /// a CRYPTO frame at offset 0, pads to ≥1200 bytes, AEAD-encrypts, and
    /// applies header protection. PN length is fixed at 4 bytes.
    pub fn encode_initial(&mut self, crypto_payload: &[u8], keys: &KeysHandle) -> Vec<u8> {
        self.encode_long(0b00, crypto_payload, keys, true)
    }

    /// Encode a Handshake packet (RFC 9000 §17.2.4). Same shape as Initial
    /// minus the Token Length field and the 1200-byte anti-amp padding.
    pub fn encode_handshake(&mut self, crypto_payload: &[u8], keys: &KeysHandle) -> Vec<u8> {
        self.encode_long(0b10, crypto_payload, keys, false)
    }

    /// Encode a 1-RTT short-header packet (RFC 9000 §17.3.1). First byte is
    /// `0x43` (form=0, fixed=1, spin=0, reserved=00, key phase=0, PN length=4).
    pub fn encode_1rtt(&mut self, payload: &[u8], keys: &KeysHandle) -> Vec<u8> {
        let pn = self.packet_number;
        let (pn_length, tag_len) = (4usize, keys_tag_len(keys).expect("tag len"));
        let mut pkt: Vec<u8> = Vec::new();
        pkt.push(0x40 | ((pn_length as u8) - 1));
        pkt.extend_from_slice(&self.dcid);
        let pn_offset = pkt.len();
        pkt.extend_from_slice(&(pn as u32).to_be_bytes());
        let header_len = pn_offset + pn_length;
        let plaintext_len = payload.len();
        pkt.resize(header_len + plaintext_len + tag_len, 0);
        pkt[header_len..header_len + plaintext_len].copy_from_slice(payload);
        let header_bytes = pkt[..header_len].to_vec();
        let ct = local_encrypt(keys, pn, &header_bytes, &mut pkt[header_len..], plaintext_len)
            .expect("aead encrypt (1-RTT)");
        debug_assert_eq!(ct, plaintext_len + tag_len);
        self.protect_header_in_place(&mut pkt, pn_offset, pn_length, keys);
        self.packet_number = self.packet_number.wrapping_add(1);
        pkt
    }

    /// Shared long-header assembler. `is_initial` toggles Token Length + the
    /// 1200-byte anti-amplification padding.
    fn encode_long(
        &mut self, packet_type: u8, crypto_payload: &[u8], keys: &KeysHandle, is_initial: bool,
    ) -> Vec<u8> {
        let pn = self.packet_number;
        let (pn_length, tag_len) = (4usize, keys_tag_len(keys).expect("tag len"));
        // QUIC payload: CRYPTO frame (type=0x06, off=0, len, data) + PADDING.
        let mut qp: Vec<u8> = Vec::new();
        qp.push(0x06);
        encode_varint(0, &mut qp);
        encode_varint(crypto_payload.len() as u64, &mut qp);
        qp.extend_from_slice(crypto_payload);
        // Header up to (but not including) the Length field.
        let mut h: Vec<u8> = Vec::new();
        h.push(0b1100_0000 | (packet_type << 4) | ((pn_length as u8) - 1));
        h.extend_from_slice(&1u32.to_be_bytes()); // QUIC v1
        h.push(self.dcid.len() as u8); h.extend_from_slice(&self.dcid);
        h.push(self.scid.len() as u8); h.extend_from_slice(&self.scid);
        if is_initial { encode_varint(0, &mut h); } // Token Length = 0
        // Pad QUIC payload for the 1200-byte anti-amp minimum (Initial only).
        // Force a 2-byte Length varint so header offsets stay predictable.
        let unpadded = pn_length + qp.len() + tag_len;
        let lvw = if is_initial { 2 } else { varint_width(unpadded as u64) };
        if is_initial {
            let total = h.len() + lvw + unpadded;
            if total < INITIAL_MIN_BYTES { qp.resize(qp.len() + (INITIAL_MIN_BYTES - total), 0); }
        }
        let length = pn_length + qp.len() + tag_len;
        if is_initial {
            assert!((length as u64) < 1 << 14, "Initial Length too large");
            let b = (length as u16).to_be_bytes();
            h.extend_from_slice(&[b[0] | 0x40, b[1]]);
        } else {
            encode_varint(length as u64, &mut h);
        }
        let pn_offset = h.len();
        h.extend_from_slice(&(pn as u32).to_be_bytes());
        let header_len = h.len();
        let mut pkt: Vec<u8> = Vec::with_capacity(header_len + qp.len() + tag_len);
        pkt.extend_from_slice(&h); pkt.extend_from_slice(&qp);
        pkt.resize(header_len + qp.len() + tag_len, 0);
        let plaintext_len = qp.len();
        let header_bytes = pkt[..header_len].to_vec();
        let ct = local_encrypt(keys, pn, &header_bytes, &mut pkt[header_len..], plaintext_len)
            .expect("aead encrypt (long header)");
        debug_assert_eq!(ct, plaintext_len + tag_len);
        self.protect_header_in_place(&mut pkt, pn_offset, pn_length, keys);
        self.packet_number = self.packet_number.wrapping_add(1);
        pkt
    }

    /// HP-protect in place; split-borrow so sample[16] is read before the
    /// mutable aliases on first_byte + pn_bytes are taken.
    fn protect_header_in_place(&self, pkt: &mut [u8], pn_offset: usize, pn_length: usize, keys: &KeysHandle) {
        let so = pn_offset + 4;
        let sample: [u8; 16] = pkt[so..so + 16].try_into().expect("HP sample 16B");
        let (head, rest) = pkt.split_at_mut(pn_offset);
        local_header_protect(keys, &sample, &mut head[0], &mut rest[..pn_length]).expect("HP");
    }
}

/// Parse a QUIC long header (RFC 9000 §17.2). Returns None on truncation or
/// short-header form.
pub fn parse_long_header(buf: &[u8]) -> Option<LongHeader> {
    if buf.len() < 7 || buf[0] & 0x80 == 0 { return None; }
    let packet_type = (buf[0] >> 4) & 0x03;
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let mut i = 5;
    let dcil = *buf.get(i)? as usize; i += 1;
    if dcil > MAX_CID_LEN || buf.len() < i + dcil { return None; }
    let dcid = buf[i..i + dcil].to_vec(); i += dcil;
    let scil = *buf.get(i)? as usize; i += 1;
    if scil > MAX_CID_LEN || buf.len() < i + scil { return None; }
    let scid = buf[i..i + scil].to_vec(); i += scil;
    let token = if packet_type == 0 {
        let (tl, c) = decode_varint(&buf[i..])?; i += c;
        let tl = tl as usize;
        if buf.len() < i + tl { return None; }
        let t = buf[i..i + tl].to_vec(); i += tl; t
    } else { Vec::new() };
    let (length, c) = decode_varint(&buf[i..])?; i += c;
    let length = length as usize;
    if buf.len() < i + length { return None; }
    Some(LongHeader { version, packet_type, dcid, scid, token, payload_offset: i, length })
}

/// Parse a QUIC short header (RFC 9000 §17.3.1). `dcid_len` must come from
/// the peer's `initial_source_connection_id` transport parameter — short
/// headers do not encode the DCID length on the wire.
pub fn parse_short_header(buf: &[u8], dcid_len: usize) -> Option<ShortHeader> {
    if buf.is_empty() || buf[0] & 0x80 != 0 || buf.len() < 1 + dcid_len { return None; }
    Some(ShortHeader { dcid: buf[1..1 + dcid_len].to_vec(), packet_number_offset: 1 + dcid_len })
}

/// Parse a CONNECTION_CLOSE frame starting at the frame-type byte. Accepts
/// 0x1c (transport CC) and 0x1d (application CC).
pub fn parse_connection_close(payload: &[u8]) -> Option<ConnectionClose> {
    let frame_type = *payload.first()?;
    if frame_type != 0x1c && frame_type != 0x1d { return None; }
    let mut i = 1;
    let (error_code, c) = decode_varint(&payload[i..])?; i += c;
    if frame_type == 0x1c {
        let (_, c) = decode_varint(&payload[i..])?; i += c; // skip Frame Type
    }
    let (rl, c) = decode_varint(&payload[i..])?; i += c;
    let rl = rl as usize;
    if payload.len() < i + rl { return None; }
    let reason = String::from_utf8_lossy(&payload[i..i + rl]).into_owned();
    Some(ConnectionClose { error_code, frame_type, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// Mirror of `encode_initial`'s decryption side for the round-trip test.
    fn decrypt_initial_for_test(pkt: &[u8], header: &LongHeader, keys: &KeysHandle) -> Result<Vec<u8>, FfiError> {
        let mut buf = pkt.to_vec();
        let pn_offset = header.payload_offset;
        let so = pn_offset + 4;
        if buf.len() < so + 16 { return Err(err()); }
        let sample: [u8; 16] = buf[so..so + 16].try_into().unwrap();
        let (head, rest) = buf.split_at_mut(pn_offset);
        let first_byte = &mut head[0];
        remote_header_unprotect(keys, &sample, first_byte, &mut rest[..4])?;
        let pn_length = ((*first_byte & 0x03) + 1) as usize;
        let header_len = pn_offset + pn_length;
        let mut pn: u64 = 0;
        for i in 0..pn_length { pn = (pn << 8) | buf[pn_offset + i] as u64; }
        let header_bytes = buf[..header_len].to_vec();
        let end = pn_offset + header.length;
        let pt = remote_decrypt(keys, pn, &header_bytes, &mut buf[header_len..end])?;
        Ok(buf[header_len..header_len + pt].to_vec())
    }

    #[test]
    fn initial_packet_round_trips_through_keys() {
        let mut dcid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut dcid);
        let mut builder = PacketBuilder::new(dcid.to_vec(), vec![0u8; 8]);
        let mut crypto = vec![0u8; 256];
        rand::thread_rng().fill_bytes(&mut crypto);
        let client_keys = initial_keys(Role::Client, &dcid).expect("client keys");
        let pkt = builder.encode_initial(&crypto, &client_keys);
        assert!(pkt.len() >= INITIAL_MIN_BYTES, "padded to anti-amp min, got {}", pkt.len());
        let server_keys = initial_keys(Role::Server, &dcid).expect("server keys");
        let header = parse_long_header(&pkt).expect("long header parses");
        assert_eq!(header.packet_type, 0); assert_eq!(header.version, 1);
        assert_eq!(header.dcid, dcid.to_vec(), "DCID round-trips");
        let plaintext = decrypt_initial_for_test(&pkt, &header, &server_keys).expect("decrypt");
        // CRYPTO frame: 0x06 | varint(0) | varint(256) → data at offset 1+1+2 = 4.
        assert_eq!(plaintext[0], 0x06, "CRYPTO frame type");
        assert_eq!(&plaintext[4..4 + crypto.len()], &crypto[..], "AEAD round-trip");
    }

    #[test]
    fn varint_round_trip() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1 << 29, (1 << 30) - 1, 1 << 30] {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            assert_eq!(decode_varint(&buf).expect("decode").0, v, "round-trip for {v}");
        }
    }

    #[test]
    fn connection_close_parses_both_variants() {
        let mut buf = vec![0x1c];
        encode_varint(0x0a, &mut buf); encode_varint(0x06, &mut buf); encode_varint(5, &mut buf);
        buf.extend_from_slice(b"hello");
        let cc = parse_connection_close(&buf).expect("transport cc");
        assert_eq!((cc.error_code, cc.frame_type, cc.reason.as_str()), (0x0a, 0x1c, "hello"));
        let mut buf = vec![0x1d];
        encode_varint(0x0103, &mut buf); encode_varint(3, &mut buf);
        buf.extend_from_slice(b"bye");
        let cc = parse_connection_close(&buf).expect("application cc");
        assert_eq!((cc.error_code, cc.frame_type, cc.reason.as_str()), (0x0103, 0x1d, "bye"));
    }
}
