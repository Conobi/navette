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

/// Create a QUIC client TLS config (TLS 1.3 only, webpki-roots CA bundle).
///
/// alpn_ptr/alpn_len: raw protocol bytes (e.g. b"h3").
/// On success: *out_handle is a positive config handle.
#[no_mangle]
pub extern "C" fn rlsm_quic_client_config_new(
    alpn_ptr:   *const u8, alpn_len:   i32,
    out_handle: *mut i32,
) -> i32 {
    clear_last_error();

    if alpn_ptr.is_null()  { rlsm_err!("rlsm_quic_client_config_new: null alpn_ptr";  return -1); }
    if out_handle.is_null(){ rlsm_err!("rlsm_quic_client_config_new: null out_handle"; return -1); }
    if alpn_len < 0        { rlsm_err!("rlsm_quic_client_config_new: negative alpn_len"; return -1); }

    let alpn_bytes = unsafe { std::slice::from_raw_parts(alpn_ptr, alpn_len as usize) };

    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn_bytes.to_vec()];

    match quic_client_cfg_table().insert(Arc::new(config)) {
        Some(h) => { unsafe { *out_handle = h; } 0 }
        None => { rlsm_err!("rlsm_quic_client_config_new: handle counter exhausted"; return -1); }
    }
}

// ---------------------------------------------------------------------------
// §2 Connection lifecycle
// ---------------------------------------------------------------------------

/// Create a new QUIC client connection.
///
/// config_handle: from rlsm_quic_client_config_new.
/// version: 1=QUIC v1, 2=QUIC v2.
/// server_name/name_len: UTF-8 SNI hostname (no NUL terminator).
/// transport_params/tp_len: RFC 9000 §18 wire-encoded transport parameters.
/// On success: *out_handle is a positive connection handle.
#[no_mangle]
pub extern "C" fn rlsm_quic_client_conn_new(
    config_handle: i32,
    version:       i32,
    server_name:   *const u8, name_len: i32,
    transport_params: *const u8, tp_len: i32,
    out_handle:    *mut i32,
) -> i32 {
    clear_last_error();

    if server_name.is_null() { rlsm_err!("rlsm_quic_client_conn_new: null server_name"; return -1); }
    if out_handle.is_null()  { rlsm_err!("rlsm_quic_client_conn_new: null out_handle";  return -1); }
    if name_len < 0          { rlsm_err!("rlsm_quic_client_conn_new: negative name_len"; return -1); }
    if tp_len < 0            { rlsm_err!("rlsm_quic_client_conn_new: negative tp_len";  return -1); }
    if tp_len > 0 && transport_params.is_null() {
        rlsm_err!("rlsm_quic_client_conn_new: null transport_params with tp_len > 0"; return -1);
    }

    let ver = match to_quic_version(version) {
        Ok(v) => v,
        Err(e) => { set_last_error(e); return -1; }
    };

    let name_bytes = unsafe { std::slice::from_raw_parts(server_name, name_len as usize) };
    let tp_bytes   = if tp_len == 0 { &[] } else {
        unsafe { std::slice::from_raw_parts(transport_params, tp_len as usize) }
    };

    let name_str = match std::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("rlsm_quic_client_conn_new: invalid UTF-8 in server_name: {e}"));
            return -1;
        }
    };

    let sni = match ServerName::try_from(name_str.to_owned()) {
        Ok(n) => n,
        Err(e) => {
            set_last_error(format!("rlsm_quic_client_conn_new: invalid server name '{name_str}': {e}"));
            return -1;
        }
    };

    let config = match quic_client_cfg_table().with(config_handle, Arc::clone) {
        Some(c) => c,
        None => { rlsm_err!("rlsm_quic_client_conn_new: invalid config handle"; return -1); }
    };

    let conn = match ClientConnection::new(config, ver, sni, tp_bytes.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("rlsm_quic_client_conn_new: connection error: {e}"));
            return -1;
        }
    };

    let entry = QuicConnEntry {
        conn: QuicConn::Client(conn),
        pending: None,
        next_secrets: None,
        alert_cache: None,
    };

    match quic_conn_table().insert(entry) {
        Some(h) => { unsafe { *out_handle = h; } 0 }
        None => { rlsm_err!("rlsm_quic_client_conn_new: handle counter exhausted"; return -1); }
    }
}

/// Create a new QUIC server connection.
///
/// config_handle: from rlsm_quic_server_config_new.
/// transport_params/tp_len: RFC 9000 §18 wire-encoded transport parameters.
/// On success: *out_handle is a positive connection handle.
#[no_mangle]
pub extern "C" fn rlsm_quic_server_conn_new(
    config_handle: i32,
    version:       i32,
    transport_params: *const u8, tp_len: i32,
    out_handle:    *mut i32,
) -> i32 {
    clear_last_error();

    if out_handle.is_null() { rlsm_err!("rlsm_quic_server_conn_new: null out_handle"; return -1); }
    if tp_len < 0           { rlsm_err!("rlsm_quic_server_conn_new: negative tp_len"; return -1); }
    if tp_len > 0 && transport_params.is_null() {
        rlsm_err!("rlsm_quic_server_conn_new: null transport_params with tp_len > 0"; return -1);
    }

    let ver = match to_quic_version(version) {
        Ok(v) => v,
        Err(e) => { set_last_error(e); return -1; }
    };

    let tp_bytes = if tp_len == 0 { &[] } else {
        unsafe { std::slice::from_raw_parts(transport_params, tp_len as usize) }
    };

    let config = match quic_server_cfg_table().with(config_handle, Arc::clone) {
        Some(c) => c,
        None => { rlsm_err!("rlsm_quic_server_conn_new: invalid config handle"; return -1); }
    };

    let conn = match ServerConnection::new(config, ver, tp_bytes.to_vec()) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("rlsm_quic_server_conn_new: connection error: {e}"));
            return -1;
        }
    };

    let entry = QuicConnEntry {
        conn: QuicConn::Server(conn),
        pending: None,
        next_secrets: None,
        alert_cache: None,
    };

    match quic_conn_table().insert(entry) {
        Some(h) => { unsafe { *out_handle = h; } 0 }
        None => { rlsm_err!("rlsm_quic_server_conn_new: handle counter exhausted"; return -1); }
    }
}

/// Free a QUIC connection handle. Drops any buffered pending key change.
/// Returns 0 on success, -1 if the handle is not found.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_free(conn_handle: i32) -> i32 {
    clear_last_error();
    match quic_conn_table().remove(conn_handle) {
        Some(_) => 0,
        None => { rlsm_err!("rlsm_quic_conn_free: invalid conn handle"; return -1); }
    }
}

// ---------------------------------------------------------------------------
// §3 Handshake data exchange
// ---------------------------------------------------------------------------

/// Drain outgoing TLS bytes into caller's buffer.
///
/// *out_key_change_type: 0=none, 1=Handshake, 2=OneRtt.
/// After non-zero kind, caller MUST call rlsm_quic_conn_take_keys before
/// the next write_hs call. Calling write_hs with a pending key change → -1.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_write_hs(
    conn_handle:        i32,
    out_buf:            *mut u8,  out_capacity:    i32,
    out_written:        *mut i32,
    out_key_change_type: *mut u8,
) -> i32 {
    clear_last_error();

    if out_buf.is_null()            { rlsm_err!("rlsm_quic_conn_write_hs: null out_buf";            return -1); }
    if out_written.is_null()        { rlsm_err!("rlsm_quic_conn_write_hs: null out_written";        return -1); }
    if out_key_change_type.is_null(){ rlsm_err!("rlsm_quic_conn_write_hs: null out_key_change_type"; return -1); }
    if out_capacity < 0             { rlsm_err!("rlsm_quic_conn_write_hs: negative out_capacity";   return -1); }

    quic_conn_table().with_mut(conn_handle, |entry| {
        // Guard: pending key change must be consumed before writing more
        if entry.pending.is_some() {
            set_last_error(
                "rlsm_quic_conn_write_hs: pending key change not consumed — call take_keys first"
            );
            return -1;
        }

        let mut vec: Vec<u8> = Vec::new();
        let key_change = match &mut entry.conn {
            QuicConn::Client(c) => c.write_hs(&mut vec),
            QuicConn::Server(c) => c.write_hs(&mut vec),
        };

        if vec.len() > out_capacity as usize {
            set_last_error(format!(
                "rlsm_quic_conn_write_hs: output buffer too small (need {}, have {})",
                vec.len(), out_capacity
            ));
            return -1;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(vec.as_ptr(), out_buf, vec.len());
            *out_written = vec.len() as i32;
        }

        let kind: u8 = match key_change {
            None => 0,
            Some(KeyChange::Handshake { keys }) => {
                entry.pending = Some((1, keys));
                1
            }
            Some(KeyChange::OneRtt { keys, next }) => {
                entry.pending = Some((2, keys));
                entry.next_secrets = Some(next);
                2
            }
        };

        unsafe { *out_key_change_type = kind; }
        0
    })
    .unwrap_or_else(|| {
        rlsm_err!("rlsm_quic_conn_write_hs: invalid conn handle"; return -1)
    })
}

/// Feed CRYPTO frame payload to the TLS state machine.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_read_hs(
    conn_handle: i32,
    data:        *const u8, len: i32,
) -> i32 {
    clear_last_error();

    if data.is_null() && len > 0 {
        rlsm_err!("rlsm_quic_conn_read_hs: null data with len > 0"; return -1);
    }
    if len < 0 { rlsm_err!("rlsm_quic_conn_read_hs: negative len"; return -1); }

    let slice = if len == 0 { &[] } else {
        unsafe { std::slice::from_raw_parts(data, len as usize) }
    };

    quic_conn_table().with_mut(conn_handle, |entry| {
        let result = match &mut entry.conn {
            QuicConn::Client(c) => c.read_hs(slice),
            QuicConn::Server(c) => c.read_hs(slice),
        };
        match result {
            Ok(()) => 0,
            Err(e) => {
                // Cache the alert code for rlsm_quic_conn_alert.
                // NOTE: QUIC connections don't send TLS Alert records (RFC 9001 uses CONNECTION_CLOSE
                // instead), so conn.alert() often returns None even on genuine TLS errors.
                // When None, we fall back to decode_error (50) so the caller always receives a
                // non-negative code. The returned code may be synthetic — use rlsm_last_error()
                // for the authoritative error string.
                let alert_code = match &entry.conn {
                    QuicConn::Client(c) => c.alert().map(|a| u8::from(a)),
                    QuicConn::Server(c) => c.alert().map(|a| u8::from(a)),
                };
                entry.alert_cache = Some(alert_code.unwrap_or(50));
                set_last_error(format!("rlsm_quic_conn_read_hs: TLS error: {e}"));
                -1
            }
        }
    })
    .unwrap_or_else(|| {
        rlsm_err!("rlsm_quic_conn_read_hs: invalid conn handle"; return -1)
    })
}

/// Return the cached TLS AlertDescription code set by the last read_hs failure.
/// The code may be synthetic (decode_error/50) when the underlying rustls connection
/// did not emit a TLS Alert record (common for QUIC). Use rlsm_last_error() for the
/// authoritative error message. Clears the cache on read.
/// Returns -1 if no alert is cached or handle is invalid.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_alert(conn_handle: i32) -> i32 {
    clear_last_error();
    quic_conn_table()
        .with_mut(conn_handle, |entry| {
            entry.alert_cache.take().map(|a| a as i32).unwrap_or(-1)
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_alert: invalid conn handle"; return -1)
        })
}

// ---------------------------------------------------------------------------
// §4 Key materialization
// ---------------------------------------------------------------------------

/// Move the pending Keys into Wave 1's KEYS_TABLE.
/// Returns the new keys handle in *out_keys_handle.
/// Returns -1 if no pending key change exists or handle is invalid.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_take_keys(
    conn_handle:    i32,
    out_keys_handle: *mut i32,
) -> i32 {
    clear_last_error();

    if out_keys_handle.is_null() {
        rlsm_err!("rlsm_quic_conn_take_keys: null out_keys_handle"; return -1);
    }

    quic_conn_table().with_mut(conn_handle, |entry| {
        let (_kind, keys) = match entry.pending.take() {
            Some(p) => p,
            None => {
                set_last_error("rlsm_quic_conn_take_keys: no pending key change");
                return -1;
            }
        };

        let new_entry = KeysEntry {
            local: keys.local,
            remote: keys.remote,
            last_local_pn: None,
        };

        match keys_table().insert(new_entry) {
            Some(kh) => {
                unsafe { *out_keys_handle = kh; }
                0
            }
            None => {
                set_last_error("rlsm_quic_conn_take_keys: KEYS_TABLE handle counter exhausted");
                -1
            }
        }
    })
    .unwrap_or_else(|| {
        rlsm_err!("rlsm_quic_conn_take_keys: invalid conn handle"; return -1)
    })
}

/// Derive next 1-RTT packet keys from the stored Secrets (RFC 9001 §6).
/// Returns -1 if no OneRtt key change has been processed yet.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_take_next_keys(
    conn_handle:    i32,
    out_keys_handle: *mut i32,
) -> i32 {
    clear_last_error();

    if out_keys_handle.is_null() {
        rlsm_err!("rlsm_quic_conn_take_next_keys: null out_keys_handle"; return -1);
    }

    quic_conn_table().with_mut(conn_handle, |entry| {
        let mut secrets = match entry.next_secrets.take() {
            Some(s) => s,
            None => {
                set_last_error(
                    "rlsm_quic_conn_take_next_keys: no 1-RTT Secrets available \
                     (OneRtt key change not yet processed, or already consumed)"
                );
                return -1;
            }
        };

        let pks = secrets.next_packet_keys();

        // PacketKeySet has only packet keys (no header protection keys).
        // Wrap in a no-op HeaderProtectionKey that errors loudly if called.
        struct NoOpHpKey;
        impl rustls::quic::HeaderProtectionKey for NoOpHpKey {
            fn encrypt_in_place(
                &self, _sample: &[u8], _first: &mut u8, _packet_number: &mut [u8],
            ) -> Result<(), rustls::Error> {
                Err(rustls::Error::General(
                    "key update: header protection key not available — \
                     HP keys do not rotate (RFC 9001 §6.3)".into()
                ))
            }
            fn decrypt_in_place(
                &self, _sample: &[u8], _first: &mut u8, _packet_number: &mut [u8],
            ) -> Result<(), rustls::Error> {
                Err(rustls::Error::General(
                    "key update: header protection key not available — \
                     HP keys do not rotate (RFC 9001 §6.3)".into()
                ))
            }
            fn sample_len(&self) -> usize { 16 }
        }

        let new_entry = KeysEntry {
            local: DirectionalKeys {
                header: Box::new(NoOpHpKey),
                packet: pks.local,
            },
            remote: DirectionalKeys {
                header: Box::new(NoOpHpKey),
                packet: pks.remote,
            },
            last_local_pn: None,
        };

        match keys_table().insert(new_entry) {
            Some(kh) => { unsafe { *out_keys_handle = kh; } 0 }
            None => {
                set_last_error("rlsm_quic_conn_take_next_keys: KEYS_TABLE handle counter exhausted");
                -1
            }
        }
    })
    .unwrap_or_else(|| {
        rlsm_err!("rlsm_quic_conn_take_next_keys: invalid conn handle"; return -1)
    })
}

// ---------------------------------------------------------------------------
// §5 State queries
// ---------------------------------------------------------------------------

/// Returns 1 if handshaking, 0 if complete, -1 on invalid handle.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_is_handshaking(conn_handle: i32) -> i32 {
    clear_last_error();
    quic_conn_table()
        .with(conn_handle, |entry| {
            let v = match &entry.conn {
                QuicConn::Client(c) => c.is_handshaking(),
                QuicConn::Server(c) => c.is_handshaking(),
            };
            if v { 1 } else { 0 }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_is_handshaking: invalid conn handle"; return -1)
        })
}

/// Copy peer's transport parameters into out_buf.
/// Returns 0=available, 1=not yet available, -1=error.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_transport_params(
    conn_handle:  i32,
    out_buf:      *mut u8,  out_capacity: i32,
    out_written:  *mut i32,
) -> i32 {
    clear_last_error();

    if out_buf.is_null()     { rlsm_err!("rlsm_quic_conn_transport_params: null out_buf";    return -1); }
    if out_written.is_null() { rlsm_err!("rlsm_quic_conn_transport_params: null out_written"; return -1); }
    if out_capacity < 0      { rlsm_err!("rlsm_quic_conn_transport_params: negative capacity"; return -1); }

    quic_conn_table()
        .with(conn_handle, |entry| {
            let params = match &entry.conn {
                QuicConn::Client(c) => c.quic_transport_parameters(),
                QuicConn::Server(c) => c.quic_transport_parameters(),
            };
            match params {
                None => { unsafe { *out_written = 0; } 1 }
                Some(p) => {
                    if p.len() > out_capacity as usize {
                        set_last_error(format!(
                            "rlsm_quic_conn_transport_params: buffer too small \
                             (need {}, have {})", p.len(), out_capacity
                        ));
                        return -1;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(p.as_ptr(), out_buf, p.len());
                        *out_written = p.len() as i32;
                    }
                    0
                }
            }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_transport_params: invalid conn handle"; return -1)
        })
}

/// Copy negotiated ALPN bytes into out_buf.
/// Returns 0=available, 1=not yet available, -1=error.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_alpn(
    conn_handle:  i32,
    out_buf:      *mut u8,  out_capacity: i32,
    out_written:  *mut i32,
) -> i32 {
    clear_last_error();

    if out_buf.is_null()     { rlsm_err!("rlsm_quic_conn_alpn: null out_buf";    return -1); }
    if out_written.is_null() { rlsm_err!("rlsm_quic_conn_alpn: null out_written"; return -1); }
    if out_capacity < 0      { rlsm_err!("rlsm_quic_conn_alpn: negative capacity"; return -1); }

    quic_conn_table()
        .with(conn_handle, |entry| {
            let proto = match &entry.conn {
                QuicConn::Client(c) => c.alpn_protocol(),
                QuicConn::Server(c) => c.alpn_protocol(),
            };
            match proto {
                None => { unsafe { *out_written = 0; } 1 }
                Some(p) => {
                    if p.len() > out_capacity as usize {
                        set_last_error(format!(
                            "rlsm_quic_conn_alpn: buffer too small (need {}, have {})",
                            p.len(), out_capacity
                        ));
                        return -1;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(p.as_ptr(), out_buf, p.len());
                        *out_written = p.len() as i32;
                    }
                    0
                }
            }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_alpn: invalid conn handle"; return -1)
        })
}

// ---------------------------------------------------------------------------
// §6 0-RTT stubs (not exercised in M3)
// ---------------------------------------------------------------------------

/// Write client-side 0-RTT DirectionalKeys into KEYS_TABLE if available.
/// Returns 0=available, 1=not available (fresh session), -1=error.
/// Only valid on client connections before any write_hs calls.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_zero_rtt_keys(
    conn_handle:    i32,
    out_keys_handle: *mut i32,
) -> i32 {
    clear_last_error();

    if out_keys_handle.is_null() {
        rlsm_err!("rlsm_quic_conn_zero_rtt_keys: null out_keys_handle"; return -1);
    }

    quic_conn_table()
        .with(conn_handle, |entry| {
            let dk: Option<DirectionalKeys> = match &entry.conn {
                QuicConn::Client(c) => c.zero_rtt_keys(),
                QuicConn::Server(_) => {
                    set_last_error("rlsm_quic_conn_zero_rtt_keys: not supported on server connections");
                    return -1;
                }
            };
            match dk {
                None => { unsafe { *out_keys_handle = 0; } 1 }
                Some(local_dk) => {
                    // 0-RTT only has local (encrypt) keys; remote keys are not provided.
                    // Wrap remote in a no-op that errors if used.
                    struct NoOpPacketKey;
                    impl rustls::quic::PacketKey for NoOpPacketKey {
                        fn encrypt_in_place(
                            &self, _pn: u64, _hdr: &[u8], _payload: &mut [u8],
                        ) -> Result<rustls::quic::Tag, rustls::Error> {
                            Err(rustls::Error::General("0-RTT: no remote packet key".into()))
                        }
                        fn decrypt_in_place<'a>(
                            &self, _pn: u64, _hdr: &[u8], _payload: &'a mut [u8],
                        ) -> Result<&'a [u8], rustls::Error> {
                            Err(rustls::Error::General("0-RTT: no remote packet key".into()))
                        }
                        fn tag_len(&self) -> usize { 16 }
                        fn confidentiality_limit(&self) -> u64 { 0 }
                        fn integrity_limit(&self) -> u64 { 0 }
                    }
                    struct NoOpHpKey2;
                    impl rustls::quic::HeaderProtectionKey for NoOpHpKey2 {
                        fn encrypt_in_place(&self, _: &[u8], _: &mut u8, _: &mut [u8]) -> Result<(), rustls::Error> {
                            Err(rustls::Error::General("0-RTT: no remote HP key".into()))
                        }
                        fn decrypt_in_place(&self, _: &[u8], _: &mut u8, _: &mut [u8]) -> Result<(), rustls::Error> {
                            Err(rustls::Error::General("0-RTT: no remote HP key".into()))
                        }
                        fn sample_len(&self) -> usize { 16 }
                    }
                    let new_entry = KeysEntry {
                        local: local_dk,
                        remote: DirectionalKeys {
                            header: Box::new(NoOpHpKey2),
                            packet: Box::new(NoOpPacketKey),
                        },
                        last_local_pn: None,
                    };
                    match keys_table().insert(new_entry) {
                        Some(kh) => { unsafe { *out_keys_handle = kh; } 0 }
                        None => {
                            set_last_error("rlsm_quic_conn_zero_rtt_keys: handle exhausted");
                            -1
                        }
                    }
                }
            }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_zero_rtt_keys: invalid conn handle"; return -1)
        })
}

/// Returns 1 if server accepted early data (0-RTT), 0 otherwise, -1 on error.
/// Valid only on client connections after the handshake completes.
#[no_mangle]
pub extern "C" fn rlsm_quic_conn_is_early_data_accepted(conn_handle: i32) -> i32 {
    clear_last_error();
    quic_conn_table()
        .with(conn_handle, |entry| match &entry.conn {
            QuicConn::Client(c) => if c.is_early_data_accepted() { 1 } else { 0 },
            QuicConn::Server(_) => {
                set_last_error(
                    "rlsm_quic_conn_is_early_data_accepted: not applicable to server connections"
                );
                -1
            }
        })
        .unwrap_or_else(|| {
            rlsm_err!("rlsm_quic_conn_is_early_data_accepted: invalid conn handle"; return -1)
        })
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

    /// Create a client config that trusts a specific root cert DER.
    /// Inserts directly into the handle table (bypasses production FFI
    /// which uses webpki-roots — not useful for self-signed test certs).
    fn make_test_client_config(root_cert_der: &[u8], alpn: &[u8]) -> i32 {
        let mut root_store = RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(root_cert_der.to_vec()))
            .unwrap();

        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];

        quic_client_cfg_table()
            .insert(Arc::new(config))
            .expect("handle counter exhausted")
    }

    /// Shared setup: server config handle + root DER for client trust.
    fn make_server_cfg(alpn: &[u8]) -> (i32, Vec<u8>) {
        let (cert_pem, key_pem, cert_der) = gen_test_cert();
        let mut h: i32 = 0;
        let rc = rlsm_quic_server_config_new(
            cert_pem.as_ptr(), cert_pem.len() as i32,
            key_pem.as_ptr(),  key_pem.len()  as i32,
            alpn.as_ptr(),     alpn.len()      as i32,
            &mut h,
        );
        assert_eq!(rc, 0);
        (h, cert_der)
    }

    fn make_conn_pair(alpn: &[u8]) -> (i32, i32) {
        let (server_cfg, root_der) = make_server_cfg(alpn);
        let client_cfg = make_test_client_config(&root_der, alpn);
        let tp: &[u8] = &[];
        let server_name = b"localhost";
        let mut client_h: i32 = 0;
        let mut server_h: i32 = 0;
        let rc = rlsm_quic_client_conn_new(
            client_cfg, 1,
            server_name.as_ptr(), server_name.len() as i32,
            tp.as_ptr(), 0,
            &mut client_h,
        );
        assert_eq!(rc, 0, "client conn new failed");
        let rc = rlsm_quic_server_conn_new(
            server_cfg, 1,
            tp.as_ptr(), 0,
            &mut server_h,
        );
        assert_eq!(rc, 0, "server conn new failed");
        (client_h, server_h)
    }

    fn make_conn_pair_with_tp(alpn: &[u8], tp: &[u8]) -> (i32, i32) {
        let (server_cfg, root_der) = make_server_cfg(alpn);
        let client_cfg = make_test_client_config(&root_der, alpn);
        let server_name = b"localhost";
        let mut client_h: i32 = 0;
        let mut server_h: i32 = 0;
        let rc = rlsm_quic_client_conn_new(
            client_cfg, 1,
            server_name.as_ptr(), server_name.len() as i32,
            tp.as_ptr(), tp.len() as i32,
            &mut client_h,
        );
        assert_eq!(rc, 0, "client conn new (with tp) failed");
        let rc = rlsm_quic_server_conn_new(
            server_cfg, 1,
            tp.as_ptr(), tp.len() as i32,
            &mut server_h,
        );
        assert_eq!(rc, 0, "server conn new (with tp) failed");
        (client_h, server_h)
    }

    // T5: write_hs with a pending key returns -1
    #[test]
    fn test_write_hs_with_pending_key_returns_error() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut buf = vec![0u8; 4096];
        let mut written: i32 = 0;
        let mut kc: u8 = 0;

        // Client writes ClientHello (no key change)
        let rc = rlsm_quic_conn_write_hs(client_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc);
        assert_eq!(rc, 0);
        let client_hello = buf[..written as usize].to_vec();

        // Server reads ClientHello, then writes (should produce key_change=1)
        let rc = rlsm_quic_conn_read_hs(server_h, client_hello.as_ptr(), client_hello.len() as i32);
        assert_eq!(rc, 0);
        written = 0; kc = 0;
        let rc = rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc);
        assert_eq!(rc, 0);
        assert_eq!(kc, 1, "expected Handshake key change after ClientHello");

        // Now write_hs again WITHOUT calling take_keys → must return -1
        written = 0; kc = 0;
        let rc = rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc);
        assert_eq!(rc, -1, "write_hs with pending key should fail");

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    // T10: freeing a connection with a buffered pending key change drops it cleanly
    #[test]
    fn test_conn_free_with_pending_key_returns_ok() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut buf = vec![0u8; 4096];
        let mut written: i32 = 0;
        let mut kc: u8 = 0;

        // Client writes ClientHello
        assert_eq!(
            rlsm_quic_conn_write_hs(client_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
            0, "client write_hs failed"
        );
        let client_hello = buf[..written as usize].to_vec();

        // Server reads ClientHello
        assert_eq!(
            rlsm_quic_conn_read_hs(server_h, client_hello.as_ptr(), client_hello.len() as i32),
            0, "server read_hs failed"
        );

        // Server writes → kc=1 (Handshake key change pending)
        written = 0; kc = 0;
        assert_eq!(
            rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
            0, "server write_hs failed"
        );
        assert_eq!(kc, 1, "expected Handshake key change");

        // Free the server with a pending key change — must return 0 (drop is safe)
        assert_eq!(rlsm_quic_conn_free(server_h), 0);
        // Double-free returns -1
        assert_eq!(rlsm_quic_conn_free(server_h), -1);

        // Free client normally
        assert_eq!(rlsm_quic_conn_free(client_h), 0);
    }

    // T6: bad data → read_hs returns -1, alert returns a non-negative code
    #[test]
    fn test_alert_on_bad_read_hs() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        // Feed garbage to server before it has seen ClientHello
        let garbage = b"not valid TLS handshake data at all \x00\xff";
        let rc = rlsm_quic_conn_read_hs(server_h, garbage.as_ptr(), garbage.len() as i32);
        assert_eq!(rc, -1, "read_hs should fail on garbage input");

        // Alert must be available
        let alert = rlsm_quic_conn_alert(server_h);
        assert!(alert >= 0, "expected a non-negative alert code, got {alert}");

        // Alert is cleared on read — second call returns -1
        let alert2 = rlsm_quic_conn_alert(server_h);
        assert_eq!(alert2, -1, "alert should be cleared after reading");

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    // T4: calling take_keys twice without an intervening key change → -1
    #[test]
    fn test_double_take_keys_returns_error() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut buf = vec![0u8; 4096];
        let mut written: i32 = 0;
        let mut kc: u8 = 0;

        // Generate ClientHello from client, feed to server
        rlsm_quic_conn_write_hs(client_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc);
        let client_hello = buf[..written as usize].to_vec();
        rlsm_quic_conn_read_hs(server_h, client_hello.as_ptr(), client_hello.len() as i32);

        // Server writes → key_change=1
        written = 0; kc = 0;
        rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc);
        assert_eq!(kc, 1);

        // First take_keys → ok
        let mut keys_h: i32 = 0;
        assert_eq!(rlsm_quic_conn_take_keys(server_h, &mut keys_h), 0);
        assert!(keys_h > 0);

        // Second take_keys without a new key change → -1
        let mut keys_h2: i32 = 0;
        assert_eq!(rlsm_quic_conn_take_keys(server_h, &mut keys_h2), -1);

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    /// Drive a full in-memory handshake to completion.
    /// Returns (client_1rtt_keys, server_1rtt_keys) handles.
    fn run_handshake(client_h: i32, server_h: i32) -> (i32, i32) {
        let mut buf = vec![0u8; 4096];
        let mut written: i32;
        let mut kc: u8;
        let mut client_1rtt: i32 = 0;
        let mut server_1rtt: i32 = 0;

        for _round in 0..20 {
            let mut progress = false;

            // Client → Server
            written = 0; kc = 0;
            assert_eq!(
                rlsm_quic_conn_write_hs(client_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
                0, "client write_hs failed"
            );
            if kc != 0 {
                let mut kh: i32 = 0;
                assert_eq!(rlsm_quic_conn_take_keys(client_h, &mut kh), 0);
                if kc == 2 {
                    client_1rtt = kh;
                } else {
                    // Handshake keys — not needed after handshake; free from KEYS_TABLE
                    crate::quic::rlsm_keys_free(kh);
                }
            }
            if written > 0 {
                progress = true;
                assert_eq!(
                    rlsm_quic_conn_read_hs(server_h, buf.as_ptr(), written),
                    0, "server read_hs failed"
                );
            }

            // Server → Client
            written = 0; kc = 0;
            assert_eq!(
                rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
                0, "server write_hs failed"
            );
            if kc != 0 {
                let mut kh: i32 = 0;
                assert_eq!(rlsm_quic_conn_take_keys(server_h, &mut kh), 0);
                if kc == 2 {
                    server_1rtt = kh;
                } else {
                    // Handshake keys — not needed after handshake; free from KEYS_TABLE
                    crate::quic::rlsm_keys_free(kh);
                }
            }
            if written > 0 {
                progress = true;
                assert_eq!(
                    rlsm_quic_conn_read_hs(client_h, buf.as_ptr(), written),
                    0, "client read_hs failed"
                );
            }

            let client_done = rlsm_quic_conn_is_handshaking(client_h) == 0;
            let server_done = rlsm_quic_conn_is_handshaking(server_h) == 0;
            if client_done && server_done {
                return (client_1rtt, server_1rtt);
            }
            assert!(progress, "handshake stalled with no progress");
        }
        panic!("handshake did not complete in 20 rounds");
    }

    // T7: transport_params returns 1 (unavailable) before peer's hello
    #[test]
    fn test_transport_params_unavailable_before_hello() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut tp_buf = [0u8; 256];
        let mut tp_written: i32 = 0;
        // Before any handshake data — server has not seen ClientHello
        let rc = rlsm_quic_conn_transport_params(server_h, tp_buf.as_mut_ptr(), 256, &mut tp_written);
        assert_eq!(rc, 1, "expected 1 (unavailable) before hello");
        assert_eq!(tp_written, 0);
        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    // T1/T8: full handshake completes + transport_params available
    #[test]
    fn test_full_handshake_client_server() {
        // Use non-empty transport params so T8 can verify they are available post-handshake
        let tp = [0x01u8, 0x02, 0x40, 0x64]; // max_idle_timeout = 100ms
        let (client_h, server_h) = make_conn_pair_with_tp(b"h3", &tp);

        let (client_1rtt, server_1rtt) = run_handshake(client_h, server_h);

        assert!(client_1rtt > 0, "client 1-RTT keys not materialized");
        assert!(server_1rtt > 0, "server 1-RTT keys not materialized");

        // Both done
        assert_eq!(rlsm_quic_conn_is_handshaking(client_h), 0);
        assert_eq!(rlsm_quic_conn_is_handshaking(server_h), 0);

        // ALPN = "h3" on both sides
        let mut alpn_buf = [0u8; 32];
        let mut alpn_written: i32 = 0;
        assert_eq!(rlsm_quic_conn_alpn(client_h, alpn_buf.as_mut_ptr(), 32, &mut alpn_written), 0);
        assert_eq!(&alpn_buf[..alpn_written as usize], b"h3");
        alpn_written = 0;
        assert_eq!(rlsm_quic_conn_alpn(server_h, alpn_buf.as_mut_ptr(), 32, &mut alpn_written), 0);
        assert_eq!(&alpn_buf[..alpn_written as usize], b"h3");

        // Transport params available (T8) — both peers echoed the non-empty tp bytes
        let mut tp_buf = [0u8; 1024];
        let mut tp_written: i32 = 0;
        assert_eq!(rlsm_quic_conn_transport_params(client_h, tp_buf.as_mut_ptr(), 1024, &mut tp_written), 0);
        assert!(tp_written > 0, "client should see non-empty server transport params");
        tp_written = 0;
        assert_eq!(rlsm_quic_conn_transport_params(server_h, tp_buf.as_mut_ptr(), 1024, &mut tp_written), 0);
        assert!(tp_written > 0, "server should see non-empty client transport params");

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    // T2: Handshake keys from take_keys work with Wave 1 encrypt
    #[test]
    fn test_handshake_keys_available() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut buf = vec![0u8; 4096];
        let mut written: i32 = 0;
        let mut kc: u8 = 0;

        // Client writes ClientHello
        assert_eq!(
            rlsm_quic_conn_write_hs(client_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
            0, "client write_hs (ClientHello) failed"
        );
        let client_hello = buf[..written as usize].to_vec();

        // Server reads ClientHello
        assert_eq!(
            rlsm_quic_conn_read_hs(server_h, client_hello.as_ptr(), client_hello.len() as i32),
            0, "server read_hs (ClientHello) failed"
        );

        // Server writes → key_change=1
        written = 0; kc = 0;
        assert_eq!(
            rlsm_quic_conn_write_hs(server_h, buf.as_mut_ptr(), 4096, &mut written, &mut kc),
            0, "server write_hs failed"
        );
        assert_eq!(kc, 1, "expected Handshake key change");

        // take_keys → handle is positive
        let mut hs_keys: i32 = 0;
        assert_eq!(rlsm_quic_conn_take_keys(server_h, &mut hs_keys), 0);
        assert!(hs_keys > 0, "expected positive keys handle");

        // Wave 1 encrypt succeeds with this handle
        let header = b"\xc0\x00\x00\x00\x01";
        let mut payload = vec![0xAAu8; 32];
        let tag_space = vec![0u8; 16];
        let full_len = payload.len() + tag_space.len();
        payload.extend_from_slice(&tag_space);
        let rc = crate::quic::rlsm_keys_local_encrypt(
            hs_keys, 0,
            header.as_ptr(), header.len() as i32,
            payload.as_mut_ptr(), 32,
            full_len as i32,
        );
        assert!(rc > 0, "Wave 1 encrypt should succeed with Handshake keys, got {rc}");

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    // T3: 1-RTT keys from take_keys work with Wave 1 encrypt
    #[test]
    fn test_1rtt_keys_available() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let (client_1rtt, _server_1rtt) = run_handshake(client_h, server_h);
        assert!(client_1rtt > 0, "expected client 1-RTT keys handle");

        let header = b"\x40\x00";
        let mut payload = vec![0xBBu8; 16];
        let tag_space = vec![0u8; 16];
        let full_len = payload.len() + tag_space.len();
        payload.extend_from_slice(&tag_space);
        let rc = crate::quic::rlsm_keys_local_encrypt(
            client_1rtt, 0,
            header.as_ptr(), header.len() as i32,
            payload.as_mut_ptr(), 16,
            full_len as i32,
        );
        assert!(rc > 0, "Wave 1 encrypt should succeed with 1-RTT keys, got {rc}");

        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }

    #[test]
    fn test_client_config_new_returns_handle() {
        let alpn = b"h3";
        let mut handle_out: i32 = -1;
        let rc = rlsm_quic_client_config_new(
            alpn.as_ptr(), alpn.len() as i32,
            &mut handle_out,
        );
        assert_eq!(rc, 0, "client config creation failed");
        assert!(handle_out > 0, "expected positive handle");
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

    // T9: zero_rtt_keys returns 1 (unavailable) on a fresh (non-resumed) session
    #[test]
    fn test_0rtt_keys_unavailable_fresh_session() {
        let (client_h, server_h) = make_conn_pair(b"h3");
        let mut keys_h: i32 = 0;
        let rc = rlsm_quic_conn_zero_rtt_keys(client_h, &mut keys_h);
        assert_eq!(rc, 1, "expected 1 (unavailable) on fresh session, got {rc}");
        assert_eq!(keys_h, 0, "keys handle should remain 0 when unavailable");
        let _ = rlsm_quic_conn_free(client_h);
        let _ = rlsm_quic_conn_free(server_h);
    }
}
