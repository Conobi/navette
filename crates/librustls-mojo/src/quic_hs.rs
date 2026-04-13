//! QUIC TLS 1.3 handshake lifecycle — Wave 2.
//!
//! 15 FFI functions: config creation, connection lifecycle, CRYPTO frame
//! exchange, key materialization into Wave 1's KEYS_TABLE, state queries,
//! and 0-RTT stubs.

use std::io::BufReader;
use std::sync::{Arc, OnceLock};

use rustls::client::ClientConfig;
use rustls::quic::{ClientConnection, DirectionalKeys, KeyChange, Keys, Secrets,
                   ServerConnection, Version as QuicVersion};
use rustls::server::ServerConfig;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;

use crate::error::{clear_last_error, set_last_error};
use crate::handles::HandleTable;
use crate::quic::{keys_table, KeysEntry};
use crate::rlsm_err;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

enum QuicConn {
    Client(ClientConnection),
    Server(ServerConnection),
}

/// Pending key change buffered between write_hs and take_keys.
/// kind: 1 = Handshake, 2 = OneRtt. Atomically coupled with key material.
struct QuicConnEntry {
    conn: QuicConn,
    pending: Option<(u8, Keys)>,        // (kind, keys) — None when no pending change
    next_secrets: Option<Secrets>,      // 1-RTT Secrets from OneRtt; used by take_next_keys
    alert_cache: Option<u8>,            // cached AlertDescription code; cleared on read
}

// ---------------------------------------------------------------------------
// Handle tables
// ---------------------------------------------------------------------------

static QUIC_CLIENT_CFG_TABLE: OnceLock<HandleTable<Arc<ClientConfig>>> = OnceLock::new();
static QUIC_SERVER_CFG_TABLE: OnceLock<HandleTable<Arc<ServerConfig>>> = OnceLock::new();
static QUIC_CONN_TABLE:       OnceLock<HandleTable<QuicConnEntry>>     = OnceLock::new();

fn quic_client_cfg_table() -> &'static HandleTable<Arc<ClientConfig>> {
    QUIC_CLIENT_CFG_TABLE.get_or_init(HandleTable::new)
}

fn quic_server_cfg_table() -> &'static HandleTable<Arc<ServerConfig>> {
    QUIC_SERVER_CFG_TABLE.get_or_init(HandleTable::new)
}

fn quic_conn_table() -> &'static HandleTable<QuicConnEntry> {
    QUIC_CONN_TABLE.get_or_init(HandleTable::new)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn to_quic_version(v: i32) -> Result<QuicVersion, String> {
    match v {
        1 => Ok(QuicVersion::V1),
        2 => Ok(QuicVersion::V2),
        _ => Err(format!("unsupported QUIC version: {v}")),
    }
}

// ---------------------------------------------------------------------------
// §1 Config lifecycle
// ---------------------------------------------------------------------------

/// Create a QUIC server TLS config (TLS 1.3 only).
///
/// cert_pem/cert_len: PEM certificate chain.
/// key_pem/key_len:   PEM private key.
/// alpn_ptr/alpn_len: raw protocol bytes (e.g. b"h3" → 2 bytes, no length prefix).
/// On success: *out_handle is a positive config handle.
#[no_mangle]
pub extern "C" fn rlsm_quic_server_config_new(
    cert_pem:  *const u8, cert_len:  i32,
    key_pem:   *const u8, key_len:   i32,
    alpn_ptr:  *const u8, alpn_len:  i32,
    out_handle: *mut i32,
) -> i32 {
    clear_last_error();

    if cert_pem.is_null()  { rlsm_err!("rlsm_quic_server_config_new: null cert_pem"; return -1); }
    if key_pem.is_null()   { rlsm_err!("rlsm_quic_server_config_new: null key_pem";  return -1); }
    if alpn_ptr.is_null()  { rlsm_err!("rlsm_quic_server_config_new: null alpn_ptr"; return -1); }
    if out_handle.is_null(){ rlsm_err!("rlsm_quic_server_config_new: null out_handle"; return -1); }
    if cert_len < 0 { rlsm_err!("rlsm_quic_server_config_new: negative cert_len"; return -1); }
    if key_len  < 0 { rlsm_err!("rlsm_quic_server_config_new: negative key_len";  return -1); }
    if alpn_len < 0 { rlsm_err!("rlsm_quic_server_config_new: negative alpn_len"; return -1); }

    let cert_bytes = unsafe { std::slice::from_raw_parts(cert_pem, cert_len as usize) };
    let key_bytes  = unsafe { std::slice::from_raw_parts(key_pem,  key_len  as usize) };
    let alpn_bytes = unsafe { std::slice::from_raw_parts(alpn_ptr, alpn_len as usize) };

    let certs: Vec<_> = {
        let mut r = BufReader::new(cert_bytes);
        match rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>() {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => { rlsm_err!("rlsm_quic_server_config_new: no certs in cert_pem"; return -1); }
            Err(e) => {
                set_last_error(format!("rlsm_quic_server_config_new: cert parse error: {e}"));
                return -1;
            }
        }
    };

    let key = {
        let mut r = BufReader::new(key_bytes);
        match rustls_pemfile::private_key(&mut r) {
            Ok(Some(k)) => k,
            Ok(None) => { rlsm_err!("rlsm_quic_server_config_new: no key in key_pem"; return -1); }
            Err(e) => {
                set_last_error(format!("rlsm_quic_server_config_new: key parse error: {e}"));
                return -1;
            }
        }
    };

    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);

    let mut config = match builder.with_no_client_auth().with_single_cert(certs, key) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("rlsm_quic_server_config_new: config build error: {e}"));
            return -1;
        }
    };

    config.alpn_protocols = vec![alpn_bytes.to_vec()];

    match quic_server_cfg_table().insert(Arc::new(config)) {
        Some(h) => { unsafe { *out_handle = h; } 0 }
        None => { rlsm_err!("rlsm_quic_server_config_new: handle counter exhausted"; return -1); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed cert for "localhost" using rcgen.
    /// Returns (cert_pem_bytes, key_pem_bytes, cert_der_bytes).
    fn gen_test_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.serialize_pem().unwrap().into_bytes();
        let key_pem  = cert.serialize_private_key_pem().into_bytes();
        let cert_der = cert.serialize_der().unwrap();
        (cert_pem, key_pem, cert_der)
    }

    #[test]
    fn test_server_config_new_returns_handle() {
        let (cert_pem, key_pem, _) = gen_test_cert();
        let alpn = b"h3";
        let mut handle_out: i32 = -1;
        let rc = rlsm_quic_server_config_new(
            cert_pem.as_ptr(), cert_pem.len() as i32,
            key_pem.as_ptr(),  key_pem.len()  as i32,
            alpn.as_ptr(),     alpn.len()      as i32,
            &mut handle_out,
        );
        assert_eq!(rc, 0, "server config creation failed");
        assert!(handle_out > 0, "expected positive handle");
    }
}
