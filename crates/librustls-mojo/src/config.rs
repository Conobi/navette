//! TLS config handle table.
//!
//! Manages `ClientConfig` and `ServerConfig` objects behind integer handles.
//! Task 5 of librustls-mojo.

use std::io::BufReader;
use std::sync::{Arc, OnceLock};

use rustls::client::ClientConfig;
use rustls::server::ServerConfig;
use rustls::KeyLogFile;
use rustls::RootCertStore;

use crate::error::{clear_last_error, set_last_error};
use crate::handles::HandleTable;
use crate::rlsm_err;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[allow(dead_code)] // fields read via pattern matching; variants used by Task 6
enum ConfigEntry {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

static CONFIG_TABLE: OnceLock<HandleTable<ConfigEntry>> = OnceLock::new();

fn config_table() -> &'static HandleTable<ConfigEntry> {
    CONFIG_TABLE.get_or_init(HandleTable::new)
}

// ---------------------------------------------------------------------------
// Internal helpers (used by tcp.rs in Task 6)
// ---------------------------------------------------------------------------

/// Insert a `ClientConfig` directly and return a handle.
/// Used by the `insecure` feature in `tcp.rs`.
#[allow(dead_code)]
pub(crate) fn _insert_client_config(cfg: Arc<ClientConfig>) -> i32 {
    match config_table().insert(ConfigEntry::Client(cfg)) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "_insert_client_config: handle counter exhausted"; return -1
            );
        }
    }
}

/// Retrieve a `ClientConfig` from the handle table.
#[allow(dead_code)] // used by tcp.rs (Task 6)
pub(crate) fn get_client_config(handle: i32) -> Option<Arc<ClientConfig>> {
    config_table().with(handle, |entry| {
        if let ConfigEntry::Client(cfg) = entry {
            Some(Arc::clone(cfg))
        } else {
            None
        }
    })
    .flatten()
}

/// Retrieve a `ServerConfig` from the handle table.
#[allow(dead_code)] // used by tcp.rs (Task 6)
pub(crate) fn get_server_config(handle: i32) -> Option<Arc<ServerConfig>> {
    config_table().with(handle, |entry| {
        if let ConfigEntry::Server(cfg) = entry {
            Some(Arc::clone(cfg))
        } else {
            None
        }
    })
    .flatten()
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Create a TLS client config using Mozilla root CAs (webpki-roots).
///
/// Returns a positive config handle on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_client_config_new() -> i32 {
    clear_last_error();

    let root_store =
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.key_log = Arc::new(KeyLogFile::new());

    match config_table().insert(ConfigEntry::Client(Arc::new(config))) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "rlsm_client_config_new: handle counter exhausted"; return -1
            );
        }
    }
}

/// Create a TLS server config from a PEM certificate chain and PEM private key.
///
/// `cert_pem` / `cert_len` — PEM-encoded certificate chain (may contain multiple certs).
/// `key_pem`  / `key_len`  — PEM-encoded private key (PKCS#1, PKCS#8, or SEC1).
///
/// Returns a positive config handle on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_server_config_new(
    cert_pem: *const u8,
    cert_len: i32,
    key_pem: *const u8,
    key_len: i32,
) -> i32 {
    clear_last_error();

    // --- validate inputs ---
    if cert_pem.is_null() {
        rlsm_err!("rlsm_server_config_new: null cert_pem pointer"; return -1);
    }
    if key_pem.is_null() {
        rlsm_err!("rlsm_server_config_new: null key_pem pointer"; return -1);
    }
    if cert_len < 0 {
        rlsm_err!("rlsm_server_config_new: negative cert_len"; return -1);
    }
    if key_len < 0 {
        rlsm_err!("rlsm_server_config_new: negative key_len"; return -1);
    }

    // SAFETY: caller guarantees the pointers are valid for the given lengths.
    let cert_bytes = unsafe { std::slice::from_raw_parts(cert_pem, cert_len as usize) };
    let key_bytes  = unsafe { std::slice::from_raw_parts(key_pem,  key_len  as usize) };

    // --- parse certificates ---
    let certs: Vec<_> = {
        let mut reader = BufReader::new(cert_bytes);
        match rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() {
            Ok(v) => v,
            Err(e) => {
                set_last_error(format!("rlsm_server_config_new: failed to parse cert PEM: {e}"));
                return -1;
            }
        }
    };

    if certs.is_empty() {
        rlsm_err!("rlsm_server_config_new: no certificates found in cert_pem"; return -1);
    }

    // --- parse private key ---
    let key = {
        let mut reader = BufReader::new(key_bytes);
        match rustls_pemfile::private_key(&mut reader) {
            Ok(Some(k)) => k,
            Ok(None) => {
                rlsm_err!("rlsm_server_config_new: no private key found in key_pem"; return -1);
            }
            Err(e) => {
                set_last_error(format!("rlsm_server_config_new: failed to parse key PEM: {e}"));
                return -1;
            }
        }
    };

    // --- build ServerConfig ---
    let mut config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
    {
        Ok(cfg) => cfg,
        Err(e) => {
            set_last_error(format!("rlsm_server_config_new: failed to build server config: {e}"));
            return -1;
        }
    };
    config.key_log = Arc::new(KeyLogFile::new());

    match config_table().insert(ConfigEntry::Server(Arc::new(config))) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "rlsm_server_config_new: handle counter exhausted"; return -1
            );
        }
    }
}

/// Free a config handle.
///
/// Returns 0 on success, or -1 if the handle was not found.
#[no_mangle]
pub extern "C" fn rlsm_config_free(handle: i32) -> i32 {
    clear_last_error();

    match config_table().remove(handle) {
        Some(_) => 0,
        None => {
            rlsm_err!("rlsm_config_free: invalid config handle"; return -1);
        }
    }
}

/// Set ALPN protocol preferences on a config.
///
/// `protocols` is a length-prefixed wire format buffer:
///   `[len1, proto1_bytes..., len2, proto2_bytes..., ...]`
/// For example, `["h2", "http/1.1"]` encodes as:
///   `[2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']`
///
/// Must be called before any connection is created from this config.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_config_set_alpn_protocols(
    config_handle: i32,
    protocols: *const u8,
    protocols_len: i32,
) -> i32 {
    clear_last_error();

    if protocols.is_null() {
        rlsm_err!("rlsm_config_set_alpn_protocols: null protocols pointer"; return -1);
    }
    if protocols_len < 0 {
        rlsm_err!("rlsm_config_set_alpn_protocols: negative protocols_len"; return -1);
    }

    // SAFETY: caller guarantees the pointer is valid for `protocols_len` bytes.
    let raw = unsafe { std::slice::from_raw_parts(protocols, protocols_len as usize) };

    // Parse length-prefixed protocol list.
    let mut alpn_list: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let proto_len = raw[pos] as usize;
        pos += 1;
        if pos + proto_len > raw.len() {
            rlsm_err!("rlsm_config_set_alpn_protocols: truncated protocol entry"; return -1);
        }
        alpn_list.push(raw[pos..pos + proto_len].to_vec());
        pos += proto_len;
    }

    // Modify the config entry to set ALPN protocols.
    config_table()
        .with_mut(config_handle, |entry| match entry {
            ConfigEntry::Client(arc) => {
                if let Some(cfg) = Arc::get_mut(arc) {
                    cfg.alpn_protocols = alpn_list.clone();
                    0
                } else {
                    set_last_error(
                        "rlsm_config_set_alpn_protocols: config already shared (connection created?)"
                            .to_string(),
                    );
                    -1
                }
            }
            ConfigEntry::Server(arc) => {
                if let Some(cfg) = Arc::get_mut(arc) {
                    cfg.alpn_protocols = alpn_list;
                    0
                } else {
                    set_last_error(
                        "rlsm_config_set_alpn_protocols: config already shared (connection created?)"
                            .to_string(),
                    );
                    -1
                }
            }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_config_set_alpn_protocols: invalid config handle"; return -1);
        })
}
