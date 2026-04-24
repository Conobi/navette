//! QUIC Initial keys, AEAD encrypt/decrypt, and header protection.
//!
//! All 10 FFI functions for QUIC key derivation and packet protection.

use std::sync::OnceLock;

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hmac;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls::crypto::tls13::{HkdfExpander, OkmBlock};
use rustls::quic::{DirectionalKeys, Keys, Version as QuicVersion};
use rustls::Side;

use crate::error::{clear_last_error, set_last_error};
use crate::handles::HandleTable;
use crate::rlsm_err;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

pub(crate) struct KeysEntry {
    pub(crate) local: DirectionalKeys,
    pub(crate) remote: DirectionalKeys,
    /// Monotonic nonce-reuse check for local encryption.
    pub(crate) last_local_pn: Option<u64>,
}

static KEYS_TABLE: OnceLock<HandleTable<KeysEntry>> = OnceLock::new();

pub(crate) fn keys_table() -> &'static HandleTable<KeysEntry> {
    KEYS_TABLE.get_or_init(HandleTable::new)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map integer version to rustls `QuicVersion`.
fn to_quic_version(v: i32) -> Result<QuicVersion, String> {
    match v {
        1 => Ok(QuicVersion::V1),
        2 => Ok(QuicVersion::V2),
        _ => Err(format!("unsupported QUIC version: {v}")),
    }
}

/// Get the TLS 1.3 cipher suite for QUIC Initial keys (AES-128-GCM-SHA256).
fn initial_suite() -> &'static rustls::Tls13CipherSuite {
    TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 must be a TLS 1.3 suite")
}

// ---------------------------------------------------------------------------
// HKDF-based raw key derivation (for rlsm_initial_keys_raw)
// ---------------------------------------------------------------------------

const QUIC_V1_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_V2_SALT: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

/// HKDF-Expand-Label as defined in RFC 8446 / RFC 9001.
fn expand_with_label(expander: &dyn HkdfExpander, label: &[u8], output: &mut [u8]) {
    let output_len_be = (output.len() as u16).to_be_bytes();
    let prefix: &[u8] = b"tls13 ";
    let label_len: u8 = (prefix.len() + label.len()) as u8;
    let context_len: u8 = 0;
    let info: &[&[u8]] = &[
        &output_len_be,
        core::slice::from_ref(&label_len),
        prefix,
        label,
        core::slice::from_ref(&context_len),
    ];
    expander
        .expand_slice(info, output)
        .expect("HKDF-Expand-Label failed");
}

/// Derive raw QUIC Initial key, IV, and HP key bytes using HKDF.
fn derive_raw_keys(
    version: i32,
    dcid: &[u8],
    is_client: bool,
) -> Result<([u8; 16], [u8; 12], [u8; 16]), String> {
    let salt = match version {
        1 => QUIC_V1_SALT,
        2 => QUIC_V2_SALT,
        _ => return Err(format!("unsupported QUIC version: {version}")),
    };

    let hkdf = initial_suite().hkdf_provider;
    let hs_expander = hkdf.extract_from_secret(Some(salt), dcid);

    let label: &[u8] = if is_client {
        b"client in"
    } else {
        b"server in"
    };
    let mut secret_bytes = [0u8; 32]; // SHA-256 hash length
    expand_with_label(hs_expander.as_ref(), label, &mut secret_bytes);

    let okm = OkmBlock::new(&secret_bytes);
    let secret_expander = hkdf.expander_for_okm(&okm);

    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];

    // QUIC v1 uses "quic key" / "quic iv" / "quic hp"
    // QUIC v2 uses "quicv2 key" / "quicv2 iv" / "quicv2 hp"
    let (key_label, iv_label, hp_label) = match version {
        2 => (
            b"quicv2 key" as &[u8],
            b"quicv2 iv" as &[u8],
            b"quicv2 hp" as &[u8],
        ),
        _ => (
            b"quic key" as &[u8],
            b"quic iv" as &[u8],
            b"quic hp" as &[u8],
        ),
    };

    expand_with_label(secret_expander.as_ref(), key_label, &mut key);
    expand_with_label(secret_expander.as_ref(), iv_label, &mut iv);
    expand_with_label(secret_expander.as_ref(), hp_label, &mut hp);

    Ok((key, iv, hp))
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Derive QUIC Initial keys and return a handle to the `KeysEntry`.
///
/// Returns a positive handle on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_initial_keys(
    version: i32,
    dcid_ptr: *const u8,
    dcid_len: i32,
    is_client: i32,
) -> i32 {
    clear_last_error();

    if dcid_len < 0 {
        rlsm_err!("rlsm_initial_keys: negative dcid_len"; return -1);
    }
    if dcid_ptr.is_null() {
        rlsm_err!("rlsm_initial_keys: null dcid pointer"; return -1);
    }

    let dcid = unsafe { std::slice::from_raw_parts(dcid_ptr, dcid_len as usize) };

    let qv = match to_quic_version(version) {
        Ok(v) => v,
        Err(msg) => {
            set_last_error(msg);
            return -1;
        }
    };

    let suite = initial_suite();
    let quic_algo = match suite.quic {
        Some(algo) => algo,
        None => {
            rlsm_err!("rlsm_initial_keys: cipher suite has no QUIC algorithm"; return -1);
        }
    };

    let side = if is_client != 0 {
        Side::Client
    } else {
        Side::Server
    };

    let keys = Keys::initial(qv, suite, quic_algo, dcid, side);

    let entry = KeysEntry {
        local: keys.local,
        remote: keys.remote,
        last_local_pn: None,
    };

    match keys_table().insert(entry) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "rlsm_initial_keys: handle counter exhausted"; return -1
            );
        }
    }
}

/// Derive raw QUIC Initial key material (key, IV, HP key) and write into caller buffers.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_initial_keys_raw(
    version: i32,
    dcid_ptr: *const u8,
    dcid_len: i32,
    is_client: i32,
    out_key: *mut u8,
    out_key_len: *mut i32,
    out_iv: *mut u8,
    out_iv_len: *mut i32,
    out_hp: *mut u8,
    out_hp_len: *mut i32,
) -> i32 {
    clear_last_error();

    if dcid_len < 0 {
        rlsm_err!("rlsm_initial_keys_raw: negative dcid_len"; return -1);
    }
    if dcid_ptr.is_null() {
        rlsm_err!("rlsm_initial_keys_raw: null dcid pointer"; return -1);
    }
    if out_key.is_null() || out_key_len.is_null() {
        rlsm_err!("rlsm_initial_keys_raw: null out_key or out_key_len"; return -1);
    }
    if out_iv.is_null() || out_iv_len.is_null() {
        rlsm_err!("rlsm_initial_keys_raw: null out_iv or out_iv_len"; return -1);
    }
    if out_hp.is_null() || out_hp_len.is_null() {
        rlsm_err!("rlsm_initial_keys_raw: null out_hp or out_hp_len"; return -1);
    }

    // Treat *out_*_len as in/out: incoming value is the buffer capacity,
    // outgoing value is the bytes actually written. Validate capacities
    // BEFORE doing any work or any writes.
    let key_cap = unsafe { *out_key_len };
    let iv_cap = unsafe { *out_iv_len };
    let hp_cap = unsafe { *out_hp_len };
    if key_cap < 16 {
        rlsm_err!(
            "rlsm_initial_keys_raw: out_key capacity must be >= 16";
            return -1
        );
    }
    if iv_cap < 12 {
        rlsm_err!(
            "rlsm_initial_keys_raw: out_iv capacity must be >= 12";
            return -1
        );
    }
    if hp_cap < 16 {
        rlsm_err!(
            "rlsm_initial_keys_raw: out_hp capacity must be >= 16";
            return -1
        );
    }

    let dcid = unsafe { std::slice::from_raw_parts(dcid_ptr, dcid_len as usize) };

    let (key, iv, hp) = match derive_raw_keys(version, dcid, is_client != 0) {
        Ok(v) => v,
        Err(msg) => {
            set_last_error(msg);
            return -1;
        }
    };

    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), out_key, key.len());
        *out_key_len = key.len() as i32;
        std::ptr::copy_nonoverlapping(iv.as_ptr(), out_iv, iv.len());
        *out_iv_len = iv.len() as i32;
        std::ptr::copy_nonoverlapping(hp.as_ptr(), out_hp, hp.len());
        *out_hp_len = hp.len() as i32;
    }

    0
}

/// Encrypt a QUIC packet payload in-place using the local (sending) keys.
///
/// `payload_ptr` points to a buffer that contains `payload_len` bytes of plaintext
/// followed by enough space for the AEAD tag (total capacity = `buf_capacity`).
///
/// Returns the ciphertext length (plaintext + tag) on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_keys_local_encrypt(
    keys_handle: i32,
    packet_number: u64,
    header_ptr: *const u8,
    header_len: i32,
    payload_ptr: *mut u8,
    payload_len: i32,
    buf_capacity: i32,
) -> i32 {
    clear_last_error();

    if header_len < 0 {
        rlsm_err!("rlsm_keys_local_encrypt: negative header_len"; return -1);
    }
    if payload_len < 0 {
        rlsm_err!("rlsm_keys_local_encrypt: negative payload_len"; return -1);
    }
    if buf_capacity < 0 {
        rlsm_err!("rlsm_keys_local_encrypt: negative buf_capacity"; return -1);
    }
    if header_ptr.is_null() {
        rlsm_err!("rlsm_keys_local_encrypt: null header pointer"; return -1);
    }
    if payload_ptr.is_null() {
        rlsm_err!("rlsm_keys_local_encrypt: null payload pointer"; return -1);
    }

    let header_len = header_len as usize;
    let payload_len = payload_len as usize;
    let buf_capacity = buf_capacity as usize;

    if payload_len > buf_capacity {
        rlsm_err!(
            "rlsm_keys_local_encrypt: payload_len > buf_capacity";
            return -1
        );
    }

    let header = unsafe { std::slice::from_raw_parts(header_ptr, header_len) };
    let buf = unsafe { std::slice::from_raw_parts_mut(payload_ptr, buf_capacity) };

    match keys_table().with_mut(keys_handle, |entry: &mut KeysEntry| {
        // Nonce reuse check
        if let Some(last) = entry.last_local_pn {
            if packet_number <= last {
                return Err("nonce reuse: packet_number must be strictly increasing".into());
            }
        }
        entry.last_local_pn = Some(packet_number);

        let tag = entry
            .local
            .packet
            .encrypt_in_place(packet_number, header, &mut buf[..payload_len])
            .map_err(|e| format!("encrypt: {e}"))?;

        let tag_bytes = tag.as_ref();
        let total = payload_len + tag_bytes.len();
        if total > buf_capacity {
            return Err(format!(
                "buffer too small: need {total}, have {buf_capacity}"
            ));
        }
        buf[payload_len..total].copy_from_slice(tag_bytes);
        Ok(total as i32)
    }) {
        Some(Ok(result)) => result,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_keys_local_encrypt: invalid keys handle"; return -1);
        }
    }
}

/// Decrypt a QUIC packet payload in-place using the remote (receiving) keys.
///
/// `payload_ptr` points to `payload_len` bytes of ciphertext (including the AEAD tag).
///
/// Returns the plaintext length on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_keys_remote_decrypt(
    keys_handle: i32,
    packet_number: u64,
    header_ptr: *const u8,
    header_len: i32,
    payload_ptr: *mut u8,
    payload_len: i32,
) -> i32 {
    clear_last_error();

    if header_len < 0 {
        rlsm_err!("rlsm_keys_remote_decrypt: negative header_len"; return -1);
    }
    if payload_len < 0 {
        rlsm_err!("rlsm_keys_remote_decrypt: negative payload_len"; return -1);
    }
    if header_ptr.is_null() {
        rlsm_err!("rlsm_keys_remote_decrypt: null header pointer"; return -1);
    }
    if payload_ptr.is_null() {
        rlsm_err!("rlsm_keys_remote_decrypt: null payload pointer"; return -1);
    }

    let header_len = header_len as usize;
    let payload_len = payload_len as usize;

    let header = unsafe { std::slice::from_raw_parts(header_ptr, header_len) };
    let payload = unsafe { std::slice::from_raw_parts_mut(payload_ptr, payload_len) };

    match keys_table().with_mut(keys_handle, |entry: &mut KeysEntry| -> Result<i32, String> {
        let plaintext = entry
            .remote
            .packet
            .decrypt_in_place(packet_number, header, payload)
            .map_err(|e| format!("decrypt: {e}"))?;
        Ok(plaintext.len() as i32)
    }) {
        Some(Ok(result)) => result,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_keys_remote_decrypt: invalid keys handle"; return -1);
        }
    }
}

/// Apply QUIC header protection using the local (sending) header keys.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_keys_local_header_protect(
    keys_handle: i32,
    sample_ptr: *const u8,
    sample_len: i32,
    first_byte_ptr: *mut u8,
    pn_bytes_ptr: *mut u8,
    pn_len: i32,
) -> i32 {
    clear_last_error();

    if sample_len < 0 {
        rlsm_err!("rlsm_keys_local_header_protect: negative sample_len"; return -1);
    }
    if pn_len < 0 {
        rlsm_err!("rlsm_keys_local_header_protect: negative pn_len"; return -1);
    }
    if sample_ptr.is_null() {
        rlsm_err!("rlsm_keys_local_header_protect: null sample pointer"; return -1);
    }
    if first_byte_ptr.is_null() {
        rlsm_err!("rlsm_keys_local_header_protect: null first_byte pointer"; return -1);
    }
    if pn_bytes_ptr.is_null() {
        rlsm_err!("rlsm_keys_local_header_protect: null pn_bytes pointer"; return -1);
    }

    let sample = unsafe { std::slice::from_raw_parts(sample_ptr, sample_len as usize) };
    let first_byte = unsafe { &mut *first_byte_ptr };
    let pn_bytes = unsafe { std::slice::from_raw_parts_mut(pn_bytes_ptr, pn_len as usize) };

    match keys_table().with(keys_handle, |entry: &KeysEntry| {
        entry
            .local
            .header
            .encrypt_in_place(sample, first_byte, pn_bytes)
            .map_err(|e| format!("header protect: {e}"))
    }) {
        Some(Ok(())) => 0,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_keys_local_header_protect: invalid keys handle"; return -1);
        }
    }
}

/// Remove QUIC header protection using the remote (receiving) header keys.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_keys_remote_header_unprotect(
    keys_handle: i32,
    sample_ptr: *const u8,
    sample_len: i32,
    first_byte_ptr: *mut u8,
    pn_bytes_ptr: *mut u8,
    pn_len: i32,
) -> i32 {
    clear_last_error();

    if sample_len < 0 {
        rlsm_err!("rlsm_keys_remote_header_unprotect: negative sample_len"; return -1);
    }
    if pn_len < 0 {
        rlsm_err!("rlsm_keys_remote_header_unprotect: negative pn_len"; return -1);
    }
    if sample_ptr.is_null() {
        rlsm_err!("rlsm_keys_remote_header_unprotect: null sample pointer"; return -1);
    }
    if first_byte_ptr.is_null() {
        rlsm_err!("rlsm_keys_remote_header_unprotect: null first_byte pointer"; return -1);
    }
    if pn_bytes_ptr.is_null() {
        rlsm_err!("rlsm_keys_remote_header_unprotect: null pn_bytes pointer"; return -1);
    }

    let sample = unsafe { std::slice::from_raw_parts(sample_ptr, sample_len as usize) };
    let first_byte = unsafe { &mut *first_byte_ptr };
    let pn_bytes = unsafe { std::slice::from_raw_parts_mut(pn_bytes_ptr, pn_len as usize) };

    match keys_table().with(keys_handle, |entry: &KeysEntry| {
        entry
            .remote
            .header
            .decrypt_in_place(sample, first_byte, pn_bytes)
            .map_err(|e| format!("header unprotect: {e}"))
    }) {
        Some(Ok(())) => 0,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_keys_remote_header_unprotect: invalid keys handle"; return -1);
        }
    }
}

/// Batch header unprotection for N packets using the same keys.
///
/// Each packet buffer is modified in-place (first byte + PN bytes unmasked).
/// out_first_bytes[i] receives the unprotected first byte.
/// out_pn_lengths[i] = PN length (1..4) on success, -1 on per-packet failure.
///
/// Returns count of successfully unprotected packets, or -1 on fatal error
/// (invalid handle).
#[no_mangle]
pub extern "C" fn rlsm_keys_batch_header_unprotect(
    keys_handle: i32,
    count: i32,
    packet_ptrs: *const *mut u8,
    packet_lens: *const i32,
    pn_offsets: *const i32,
    out_first_bytes: *mut u8,
    out_pn_lengths: *mut i32,
) -> i32 {
    clear_last_error();

    if count <= 0 {
        return 0;
    }
    if packet_ptrs.is_null() || packet_lens.is_null() || pn_offsets.is_null()
        || out_first_bytes.is_null() || out_pn_lengths.is_null()
    {
        rlsm_err!("rlsm_keys_batch_header_unprotect: null pointer"; return -1);
    }

    let n = count as usize;

    match keys_table().with(keys_handle, |entry: &KeysEntry| {
        let mut ok_count: i32 = 0;
        for i in 0..n {
            let pkt_ptr = unsafe { *packet_ptrs.add(i) };
            let pkt_len = unsafe { *packet_lens.add(i) } as usize;
            let pn_off = unsafe { *pn_offsets.add(i) } as usize;

            if pn_off + 4 + 16 > pkt_len || pkt_ptr.is_null() {
                unsafe { *out_pn_lengths.add(i) = -1 };
                continue;
            }

            let sample = unsafe { std::slice::from_raw_parts(pkt_ptr.add(pn_off + 4), 16) };
            let first_byte = unsafe { &mut *pkt_ptr };
            let pn_bytes = unsafe { std::slice::from_raw_parts_mut(pkt_ptr.add(pn_off), 4) };

            match entry.remote.header.decrypt_in_place(sample, first_byte, pn_bytes) {
                Ok(()) => {
                    let pn_length = (*first_byte & 0x03) as i32 + 1;
                    unsafe {
                        *out_first_bytes.add(i) = *first_byte;
                        *out_pn_lengths.add(i) = pn_length;
                    }
                    ok_count += 1;
                }
                Err(_) => {
                    unsafe { *out_pn_lengths.add(i) = -1 };
                }
            }
        }
        ok_count
    }) {
        Some(count) => count,
        None => {
            rlsm_err!("rlsm_keys_batch_header_unprotect: invalid keys handle"; return -1);
        }
    }
}

/// Batch AEAD decryption for N packets using the same keys.
///
/// Each packet's payload region is decrypted in-place.
/// out_plaintext_lens[i] = plaintext length on success, -1 on failure.
///
/// Returns count of successful decryptions, or -1 on fatal error.
#[no_mangle]
pub extern "C" fn rlsm_keys_batch_decrypt(
    keys_handle: i32,
    count: i32,
    packet_numbers: *const u64,
    packet_ptrs: *const *mut u8,
    packet_lens: *const i32,
    header_lens: *const i32,
    out_plaintext_lens: *mut i32,
) -> i32 {
    clear_last_error();

    if count <= 0 {
        return 0;
    }
    if packet_numbers.is_null() || packet_ptrs.is_null() || packet_lens.is_null()
        || header_lens.is_null() || out_plaintext_lens.is_null()
    {
        rlsm_err!("rlsm_keys_batch_decrypt: null pointer"; return -1);
    }

    let n = count as usize;

    match keys_table().with_mut(keys_handle, |entry: &mut KeysEntry| {
        let mut ok_count: i32 = 0;
        for i in 0..n {
            let pkt_ptr = unsafe { *packet_ptrs.add(i) };
            let pkt_len = unsafe { *packet_lens.add(i) } as usize;
            let hdr_len = unsafe { *header_lens.add(i) } as usize;
            let pn = unsafe { *packet_numbers.add(i) };

            if pkt_ptr.is_null() || hdr_len >= pkt_len {
                unsafe { *out_plaintext_lens.add(i) = -1 };
                continue;
            }

            let header = unsafe { std::slice::from_raw_parts(pkt_ptr, hdr_len) };
            let payload_len = pkt_len - hdr_len;
            let payload = unsafe { std::slice::from_raw_parts_mut(pkt_ptr.add(hdr_len), payload_len) };

            match entry.remote.packet.decrypt_in_place(pn, header, payload) {
                Ok(plaintext) => {
                    unsafe { *out_plaintext_lens.add(i) = plaintext.len() as i32 };
                    ok_count += 1;
                }
                Err(_) => {
                    unsafe { *out_plaintext_lens.add(i) = -1 };
                }
            }
        }
        ok_count
    }) {
        Some(count) => count,
        None => {
            rlsm_err!("rlsm_keys_batch_decrypt: invalid keys handle"; return -1);
        }
    }
}

/// Return the AEAD tag length for the keys identified by `keys_handle`.
///
/// Returns the tag length (positive) on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_keys_tag_len(keys_handle: i32) -> i32 {
    clear_last_error();

    match keys_table().with(keys_handle, |entry: &KeysEntry| {
        entry.local.packet.tag_len() as i32
    }) {
        Some(tag_len) => tag_len,
        None => {
            rlsm_err!("rlsm_keys_tag_len: invalid keys handle"; return -1);
        }
    }
}

/// Free the keys identified by `keys_handle`.
///
/// Returns 0 on success, -1 if the handle was not found.
#[no_mangle]
pub extern "C" fn rlsm_keys_free(keys_handle: i32) -> i32 {
    clear_last_error();

    match keys_table().remove(keys_handle) {
        Some(_) => 0,
        None => {
            rlsm_err!("rlsm_keys_free: invalid keys handle"; return -1);
        }
    }
}

// ---------------------------------------------------------------------------
// Raw AES-GCM-128 seal / open (for Retry tokens, etc.)
// ---------------------------------------------------------------------------

/// Encrypt with raw AES-128-GCM. Output is ciphertext || 16-byte tag.
///
/// `out_ptr` must have capacity >= `plaintext_len + 16`.
/// `*out_len_ptr` is set to the number of bytes written on success.
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_aes_gcm_128_seal(
    key_ptr: *const u8,
    key_len: i32,
    nonce_ptr: *const u8,
    nonce_len: i32,
    aad_ptr: *const u8,
    aad_len: i32,
    plaintext_ptr: *const u8,
    plaintext_len: i32,
    out_ptr: *mut u8,
    out_len_ptr: *mut i32,
) -> i32 {
    clear_last_error();

    // --- parameter validation ---
    if key_len != 16 {
        rlsm_err!("rlsm_aes_gcm_128_seal: key_len must be 16"; return -1);
    }
    if key_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null key pointer"; return -1);
    }
    if nonce_len != 12 {
        rlsm_err!("rlsm_aes_gcm_128_seal: nonce_len must be 12"; return -1);
    }
    if nonce_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null nonce pointer"; return -1);
    }
    if aad_len < 0 {
        rlsm_err!("rlsm_aes_gcm_128_seal: negative aad_len"; return -1);
    }
    if aad_len > 0 && aad_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null aad pointer with non-zero aad_len"; return -1);
    }
    if plaintext_len < 0 {
        rlsm_err!("rlsm_aes_gcm_128_seal: negative plaintext_len"; return -1);
    }
    if plaintext_len > 0 && plaintext_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null plaintext pointer with non-zero plaintext_len"; return -1);
    }
    if out_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null out pointer"; return -1);
    }
    if out_len_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_seal: null out_len pointer"; return -1);
    }

    let key_bytes = unsafe { std::slice::from_raw_parts(key_ptr, 16) };
    let nonce_bytes = unsafe { std::slice::from_raw_parts(nonce_ptr, 12) };
    let aad_bytes = if aad_len > 0 {
        unsafe { std::slice::from_raw_parts(aad_ptr, aad_len as usize) }
    } else {
        &[]
    };
    let plaintext_bytes = if plaintext_len > 0 {
        unsafe { std::slice::from_raw_parts(plaintext_ptr, plaintext_len as usize) }
    } else {
        &[]
    };

    // Build the key
    let unbound = match UnboundKey::new(&aead::AES_128_GCM, key_bytes) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_seal: UnboundKey::new failed: {e}"));
            return -1;
        }
    };
    let less_safe = LessSafeKey::new(unbound);

    let nonce = match Nonce::try_assume_unique_for_key(nonce_bytes) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_seal: bad nonce: {e}"));
            return -1;
        }
    };

    // Copy plaintext into a Vec, then seal in place (appends tag)
    let mut buf = Vec::with_capacity(plaintext_bytes.len() + aead::AES_128_GCM.tag_len());
    buf.extend_from_slice(plaintext_bytes);

    match less_safe.seal_in_place_append_tag(nonce, Aad::from(aad_bytes), &mut buf) {
        Ok(()) => {}
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_seal: seal failed: {e}"));
            return -1;
        }
    }

    // Copy result to caller's buffer
    let total = buf.len(); // plaintext_len + 16
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr, total);
        *out_len_ptr = total as i32;
    }

    0
}

/// Decrypt with raw AES-128-GCM. `ciphertext` includes the 16-byte tag.
///
/// `out_ptr` must have capacity >= `ciphertext_len - 16`.
/// `*out_len_ptr` is set to the plaintext length on success.
///
/// Returns 0 on success, -1 on error (including authentication failure).
#[no_mangle]
pub extern "C" fn rlsm_aes_gcm_128_open(
    key_ptr: *const u8,
    key_len: i32,
    nonce_ptr: *const u8,
    nonce_len: i32,
    aad_ptr: *const u8,
    aad_len: i32,
    ciphertext_ptr: *const u8,
    ciphertext_len: i32,
    out_ptr: *mut u8,
    out_len_ptr: *mut i32,
) -> i32 {
    clear_last_error();

    // --- parameter validation ---
    if key_len != 16 {
        rlsm_err!("rlsm_aes_gcm_128_open: key_len must be 16"; return -1);
    }
    if key_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null key pointer"; return -1);
    }
    if nonce_len != 12 {
        rlsm_err!("rlsm_aes_gcm_128_open: nonce_len must be 12"; return -1);
    }
    if nonce_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null nonce pointer"; return -1);
    }
    if aad_len < 0 {
        rlsm_err!("rlsm_aes_gcm_128_open: negative aad_len"; return -1);
    }
    if aad_len > 0 && aad_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null aad pointer with non-zero aad_len"; return -1);
    }
    if ciphertext_len < 16 {
        rlsm_err!("rlsm_aes_gcm_128_open: ciphertext_len must be >= 16 (tag size)"; return -1);
    }
    if ciphertext_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null ciphertext pointer"; return -1);
    }
    if out_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null out pointer"; return -1);
    }
    if out_len_ptr.is_null() {
        rlsm_err!("rlsm_aes_gcm_128_open: null out_len pointer"; return -1);
    }

    let key_bytes = unsafe { std::slice::from_raw_parts(key_ptr, 16) };
    let nonce_bytes = unsafe { std::slice::from_raw_parts(nonce_ptr, 12) };
    let aad_bytes = if aad_len > 0 {
        unsafe { std::slice::from_raw_parts(aad_ptr, aad_len as usize) }
    } else {
        &[]
    };
    let ciphertext_bytes =
        unsafe { std::slice::from_raw_parts(ciphertext_ptr, ciphertext_len as usize) };

    // Build the key
    let unbound = match UnboundKey::new(&aead::AES_128_GCM, key_bytes) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_open: UnboundKey::new failed: {e}"));
            return -1;
        }
    };
    let less_safe = LessSafeKey::new(unbound);

    let nonce = match Nonce::try_assume_unique_for_key(nonce_bytes) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_open: bad nonce: {e}"));
            return -1;
        }
    };

    // Copy ciphertext into a Vec, then open in place
    let mut buf = ciphertext_bytes.to_vec();

    let plaintext = match less_safe.open_in_place(nonce, Aad::from(aad_bytes), &mut buf) {
        Ok(pt) => pt,
        Err(e) => {
            set_last_error(format!("rlsm_aes_gcm_128_open: open failed: {e}"));
            return -1;
        }
    };

    let pt_len = plaintext.len();
    unsafe {
        std::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_ptr, pt_len);
        *out_len_ptr = pt_len as i32;
    }

    0
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, msg) and write the 32-byte tag to `out_ptr`.
///
/// `out_ptr` must have capacity >= 32 bytes.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_hmac_sha256(
    key_ptr: *const u8,
    key_len: i32,
    msg_ptr: *const u8,
    msg_len: i32,
    out_ptr: *mut u8,
) -> i32 {
    clear_last_error();

    if key_len < 0 {
        rlsm_err!("rlsm_hmac_sha256: negative key_len"; return -1);
    }
    if key_len > 0 && key_ptr.is_null() {
        rlsm_err!("rlsm_hmac_sha256: null key pointer with non-zero key_len"; return -1);
    }
    if msg_len < 0 {
        rlsm_err!("rlsm_hmac_sha256: negative msg_len"; return -1);
    }
    if msg_len > 0 && msg_ptr.is_null() {
        rlsm_err!("rlsm_hmac_sha256: null msg pointer with non-zero msg_len"; return -1);
    }
    if out_ptr.is_null() {
        rlsm_err!("rlsm_hmac_sha256: null out pointer"; return -1);
    }

    let key_bytes = if key_len > 0 {
        unsafe { std::slice::from_raw_parts(key_ptr, key_len as usize) }
    } else {
        &[]
    };
    let msg_bytes = if msg_len > 0 {
        unsafe { std::slice::from_raw_parts(msg_ptr, msg_len as usize) }
    } else {
        &[]
    };

    let s_key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    let tag = hmac::sign(&s_key, msg_bytes);
    let tag_bytes = tag.as_ref();

    // HMAC-SHA256 always produces 32 bytes
    unsafe {
        std::ptr::copy_nonoverlapping(tag_bytes.as_ptr(), out_ptr, 32);
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create Initial keys and return the handle.
    fn make_initial_keys(is_client: bool) -> i32 {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let h = rlsm_initial_keys(
            1,
            dcid.as_ptr(),
            dcid.len() as i32,
            if is_client { 1 } else { 0 },
        );
        assert!(h > 0, "rlsm_initial_keys failed");
        h
    }

    /// Build a minimal Initial packet for testing batch operations.
    /// Returns (packet_bytes, pn_offset).
    fn make_test_initial_packet(keys_handle: i32) -> (Vec<u8>, i32) {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let pn_offset: i32 = 18;
        let pn_length = 4;
        let payload_len = 32;
        let aead_tag_len = 16;
        let header_len = pn_offset as usize + pn_length;
        let total = header_len + payload_len + aead_tag_len;
        let pl_field = (pn_length + payload_len + aead_tag_len) as u16;

        let mut pkt = vec![0u8; total];
        pkt[0] = 0xC3;
        pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x00; pkt[4] = 0x01;
        pkt[5] = 8;
        pkt[6..14].copy_from_slice(&dcid);
        pkt[14] = 0;
        pkt[15] = 0;
        pkt[16] = 0x40 | ((pl_field >> 8) as u8);
        pkt[17] = (pl_field & 0xFF) as u8;

        let header = &pkt[..header_len].to_vec();
        let rc = rlsm_keys_local_encrypt(
            keys_handle, 0,
            header.as_ptr(), header_len as i32,
            pkt[header_len..].as_mut_ptr(), payload_len as i32,
            (payload_len + aead_tag_len) as i32,
        );
        assert!(rc > 0, "encrypt failed: {rc}");

        let sample_offset = pn_offset as usize + 4;
        let rc = rlsm_keys_local_header_protect(
            keys_handle,
            pkt[sample_offset..].as_ptr(), 16,
            &mut pkt[0] as *mut u8,
            pkt[pn_offset as usize..].as_mut_ptr(), pn_length as i32,
        );
        assert_eq!(rc, 0, "header protect failed");

        (pkt, pn_offset)
    }

    #[test]
    fn test_batch_header_unprotect_single() {
        let server_h = make_initial_keys(false);
        let client_h = make_initial_keys(true);

        let (mut pkt, pn_offset) = make_test_initial_packet(server_h);

        let mut ptrs = [pkt.as_mut_ptr()];
        let lens = [pkt.len() as i32];
        let offsets = [pn_offset];
        let mut out_fb = [0u8; 1];
        let mut out_pnl = [0i32; 1];

        let rc = rlsm_keys_batch_header_unprotect(
            client_h, 1,
            ptrs.as_ptr(), lens.as_ptr(), offsets.as_ptr(),
            out_fb.as_mut_ptr(), out_pnl.as_mut_ptr(),
        );
        assert_eq!(rc, 1, "expected 1 success, got {rc}");
        assert_eq!(out_fb[0] & 0x80, 0x80, "long header bit not set");
        assert!(out_pnl[0] >= 1 && out_pnl[0] <= 4, "bad pn_length: {}", out_pnl[0]);

        rlsm_keys_free(server_h);
        rlsm_keys_free(client_h);
    }

    #[test]
    fn test_batch_decrypt_single() {
        let server_h = make_initial_keys(false);
        let client_h = make_initial_keys(true);

        let (mut pkt, pn_offset) = make_test_initial_packet(server_h);
        let pn_offset = pn_offset as usize;

        // Unprotect header first
        let mut fb = [0u8; 1];
        let mut pnl = [0i32; 1];
        let mut ptrs = [pkt.as_mut_ptr()];
        let lens = [pkt.len() as i32];
        let offsets = [pn_offset as i32];
        let rc = rlsm_keys_batch_header_unprotect(
            client_h, 1,
            ptrs.as_ptr(), lens.as_ptr(), offsets.as_ptr(),
            fb.as_mut_ptr(), pnl.as_mut_ptr(),
        );
        assert_eq!(rc, 1);
        let pn_length = pnl[0] as usize;
        let header_len = pn_offset + pn_length;

        // Batch decrypt
        let pns = [0u64];
        let hdr_lens = [header_len as i32];
        let mut out_pt_lens = [0i32; 1];

        let rc = rlsm_keys_batch_decrypt(
            client_h, 1,
            pns.as_ptr(),
            ptrs.as_ptr(), lens.as_ptr(), hdr_lens.as_ptr(),
            out_pt_lens.as_mut_ptr(),
        );
        assert_eq!(rc, 1, "expected 1 success, got {rc}");
        assert!(out_pt_lens[0] > 0, "plaintext length should be positive");

        rlsm_keys_free(server_h);
        rlsm_keys_free(client_h);
    }
}
