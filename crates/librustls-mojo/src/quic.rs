//! QUIC Initial keys, AEAD encrypt/decrypt, and header protection.
//!
//! All 10 FFI functions for QUIC key derivation and packet protection.

use std::sync::OnceLock;

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

struct KeysEntry {
    local: DirectionalKeys,
    remote: DirectionalKeys,
    /// Monotonic nonce-reuse check for local encryption.
    last_local_pn: Option<u64>,
}

static KEYS_TABLE: OnceLock<HandleTable<KeysEntry>> = OnceLock::new();

fn keys_table() -> &'static HandleTable<KeysEntry> {
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

    keys_table().insert(entry)
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
