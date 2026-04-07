//! TCP-TLS connection handle table.
//!
//! Manages `ClientConnection` and `ServerConnection` objects behind integer
//! handles.  The caller owns the transport (TCP socket); this module handles
//! only the TLS state machine.
//!
//! Task 6 of librustls-mojo.

use std::io::{Read as _, Write as _};
use std::sync::OnceLock;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};

use crate::error::{clear_last_error, set_last_error};
use crate::handles::HandleTable;
use crate::rlsm_err;
use crate::config::{get_client_config, get_server_config};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

enum TlsConn {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl TlsConn {
    /// Feed ciphertext into the state machine.
    fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> std::io::Result<usize> {
        match self {
            TlsConn::Client(c) => c.read_tls(rd),
            TlsConn::Server(s) => s.read_tls(rd),
        }
    }

    /// Drain pending ciphertext to send.
    fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> std::io::Result<usize> {
        match self {
            TlsConn::Client(c) => c.write_tls(wr),
            TlsConn::Server(s) => s.write_tls(wr),
        }
    }

    /// Advance the state machine after feeding ciphertext.
    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            TlsConn::Client(c) => c.process_new_packets(),
            TlsConn::Server(s) => s.process_new_packets(),
        }
    }

    /// Read decrypted application data.
    fn read_plaintext(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsConn::Client(c) => c.reader().read(buf),
            TlsConn::Server(s) => s.reader().read(buf),
        }
    }

    /// Write application data to be encrypted.
    fn write_plaintext(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self {
            TlsConn::Client(c) => c.writer().write(data),
            TlsConn::Server(s) => s.writer().write(data),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            TlsConn::Client(c) => c.is_handshaking(),
            TlsConn::Server(s) => s.is_handshaking(),
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            TlsConn::Client(c) => c.alpn_protocol(),
            TlsConn::Server(s) => s.alpn_protocol(),
        }
    }
}

static CONN_TABLE: OnceLock<HandleTable<TlsConn>> = OnceLock::new();

fn conn_table() -> &'static HandleTable<TlsConn> {
    CONN_TABLE.get_or_init(HandleTable::new)
}

// ---------------------------------------------------------------------------
// I/O wrappers
// ---------------------------------------------------------------------------

struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> std::io::Read for SliceReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let available = &self.data[self.pos..];
        let to_copy = available.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&available[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> std::io::Write for SliceWriter<'a> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let space = &mut self.buf[self.pos..];
        let to_copy = space.len().min(data.len());
        space[..to_copy].copy_from_slice(&data[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Insecure client config (feature-gated)
// ---------------------------------------------------------------------------

/// Create a TLS client config that accepts any server certificate (insecure).
///
/// Only available when the `insecure` feature is enabled.
/// Returns a positive config handle on success, or -1 on error.
#[cfg(feature = "insecure")]
#[no_mangle]
pub extern "C" fn rlsm_client_config_new_insecure() -> i32 {
    use rustls::client::ClientConfig;
    use rustls::crypto::aws_lc_rs;

    clear_last_error();

    #[derive(Debug)]
    struct NoCertVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    use std::sync::Arc;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();

    crate::config::_insert_client_config(Arc::new(config))
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Create a new TLS client connection.
///
/// `config_handle` — handle returned by `rlsm_client_config_new`.
/// `server_name_ptr` / `server_name_len` — UTF-8 server hostname.
///
/// Returns a positive connection handle on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_client_new(
    config_handle: i32,
    server_name_ptr: *const u8,
    server_name_len: i32,
) -> i32 {
    clear_last_error();

    if server_name_ptr.is_null() {
        rlsm_err!("rlsm_tls_client_new: null server_name pointer"; return -1);
    }
    if server_name_len < 0 {
        rlsm_err!("rlsm_tls_client_new: negative server_name_len"; return -1);
    }

    let cfg = match get_client_config(config_handle) {
        Some(c) => c,
        None => {
            rlsm_err!("rlsm_tls_client_new: invalid client config handle"; return -1);
        }
    };

    let name_bytes =
        unsafe { std::slice::from_raw_parts(server_name_ptr, server_name_len as usize) };

    let name_str = match std::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("rlsm_tls_client_new: server_name is not valid UTF-8: {e}"));
            return -1;
        }
    };

    let server_name: ServerName<'static> = match ServerName::try_from(name_str) {
        Ok(n) => n.to_owned(),
        Err(e) => {
            set_last_error(format!("rlsm_tls_client_new: invalid server name '{name_str}': {e}"));
            return -1;
        }
    };

    let conn = match ClientConnection::new(cfg, server_name) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("rlsm_tls_client_new: failed to create client connection: {e}"));
            return -1;
        }
    };

    match conn_table().insert(TlsConn::Client(conn)) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "rlsm_tls_client_new: handle counter exhausted"; return -1
            );
        }
    }
}

/// Create a new TLS server connection.
///
/// `config_handle` — handle returned by `rlsm_server_config_new`.
///
/// Returns a positive connection handle on success, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_server_new(config_handle: i32) -> i32 {
    clear_last_error();

    let cfg = match get_server_config(config_handle) {
        Some(c) => c,
        None => {
            rlsm_err!("rlsm_tls_server_new: invalid server config handle"; return -1);
        }
    };

    let conn = match ServerConnection::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("rlsm_tls_server_new: failed to create server connection: {e}"));
            return -1;
        }
    };

    match conn_table().insert(TlsConn::Server(conn)) {
        Some(h) => h,
        None => {
            rlsm_err!(
                "rlsm_tls_server_new: handle counter exhausted"; return -1
            );
        }
    }
}

/// Free a TLS connection handle.
///
/// Returns 0 on success, or -1 if the handle was not found.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_free(handle: i32) -> i32 {
    clear_last_error();

    match conn_table().remove(handle) {
        Some(_) => 0,
        None => {
            rlsm_err!("rlsm_tls_conn_free: invalid connection handle"; return -1);
        }
    }
}

/// Feed ciphertext received from the peer into rustls.
///
/// After calling this, the state machine is advanced via `process_new_packets`.
///
/// Returns the number of ciphertext bytes consumed, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_read_tls(
    handle: i32,
    ciphertext_ptr: *const u8,
    ct_len: i32,
) -> i32 {
    clear_last_error();

    if ciphertext_ptr.is_null() {
        rlsm_err!("rlsm_tls_conn_read_tls: null ciphertext pointer"; return -1);
    }
    if ct_len < 0 {
        rlsm_err!("rlsm_tls_conn_read_tls: negative ct_len"; return -1);
    }

    let data = unsafe { std::slice::from_raw_parts(ciphertext_ptr, ct_len as usize) };

    match conn_table().with_mut(handle, |conn: &mut TlsConn| -> Result<i32, String> {
        // Loop read_tls + process_new_packets until either the input slice is
        // fully consumed or rustls' deframer makes no progress (returns 0).
        // This pulls the partial-consumption handling into the FFI so callers
        // get atomic semantics: a single call processes all bytes possible.
        let mut reader = SliceReader { data, pos: 0 };
        loop {
            let consumed = conn
                .read_tls(&mut reader)
                .map_err(|e| format!("rlsm_tls_conn_read_tls: read_tls failed: {e}"))?;
            // Always advance the state machine after buffering bytes so the
            // deframer can release space for the next iteration.
            conn.process_new_packets()
                .map_err(|e| format!("rlsm_tls_conn_read_tls: process_new_packets failed: {e}"))?;
            if consumed == 0 {
                // Either the SliceReader is exhausted or the deframer is full
                // and could not make progress — bail out.
                break;
            }
            if reader.pos >= reader.data.len() {
                break;
            }
        }
        Ok(reader.pos as i32)
    }) {
        Some(Ok(n)) => n,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_tls_conn_read_tls: invalid connection handle"; return -1);
        }
    }
}

/// Drain ciphertext from rustls into `out_buf` to send to the peer.
///
/// Returns the number of bytes written into `out_buf`, 0 if nothing to send,
/// or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_write_tls(
    handle: i32,
    out_buf: *mut u8,
    buf_len: i32,
) -> i32 {
    clear_last_error();

    if out_buf.is_null() {
        rlsm_err!("rlsm_tls_conn_write_tls: null out_buf pointer"; return -1);
    }
    if buf_len < 0 {
        rlsm_err!("rlsm_tls_conn_write_tls: negative buf_len"; return -1);
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, buf_len as usize) };

    match conn_table().with_mut(handle, |conn: &mut TlsConn| -> Result<i32, String> {
        let mut writer = SliceWriter { buf, pos: 0 };
        let written = conn
            .write_tls(&mut writer)
            .map_err(|e| format!("rlsm_tls_conn_write_tls: write_tls failed: {e}"))?;
        Ok(written as i32)
    }) {
        Some(Ok(n)) => n,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_tls_conn_write_tls: invalid connection handle"; return -1);
        }
    }
}

/// Read decrypted application data from the connection.
///
/// Returns the number of bytes written into `out_buf`, 0 if no data is
/// currently available, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_read_plaintext(
    handle: i32,
    out_buf: *mut u8,
    buf_len: i32,
) -> i32 {
    clear_last_error();

    if out_buf.is_null() {
        rlsm_err!("rlsm_tls_conn_read_plaintext: null out_buf pointer"; return -1);
    }
    if buf_len < 0 {
        rlsm_err!("rlsm_tls_conn_read_plaintext: negative buf_len"; return -1);
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, buf_len as usize) };

    match conn_table().with_mut(handle, |conn: &mut TlsConn| -> Result<i32, String> {
        match conn.read_plaintext(buf) {
            Ok(n) => Ok(n as i32),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(format!("rlsm_tls_conn_read_plaintext: reader failed: {e}")),
        }
    }) {
        Some(Ok(n)) => n,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_tls_conn_read_plaintext: invalid connection handle"; return -1);
        }
    }
}

/// Write application data into the connection to be encrypted.
///
/// Returns the number of bytes consumed from `data_ptr`, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_write_plaintext(
    handle: i32,
    data_ptr: *const u8,
    data_len: i32,
) -> i32 {
    clear_last_error();

    if data_ptr.is_null() {
        rlsm_err!("rlsm_tls_conn_write_plaintext: null data pointer"; return -1);
    }
    if data_len < 0 {
        rlsm_err!("rlsm_tls_conn_write_plaintext: negative data_len"; return -1);
    }

    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len as usize) };

    match conn_table().with_mut(handle, |conn: &mut TlsConn| -> Result<i32, String> {
        // Loop write_plaintext until all bytes are consumed or the writer
        // refuses further input (returns 0). This gives callers atomic
        // "all or fail" semantics for plaintext writes.
        let mut total: usize = 0;
        while total < data.len() {
            let n = conn
                .write_plaintext(&data[total..])
                .map_err(|e| format!("rlsm_tls_conn_write_plaintext: writer failed: {e}"))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        // Drive the state machine even on a write-only path so any
        // post-handshake messages already buffered in rustls' deframer
        // (NewSessionTicket, KeyUpdate, alerts, ...) are processed and
        // acknowledged. Without this a long-lived write-only connection
        // could drift out of sync with the peer's key schedule.
        conn.process_new_packets()
            .map_err(|e| format!(
                "rlsm_tls_conn_write_plaintext: process_new_packets failed: {e}"
            ))?;
        Ok(total as i32)
    }) {
        Some(Ok(n)) => n,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_tls_conn_write_plaintext: invalid connection handle"; return -1);
        }
    }
}

/// Check whether the TLS handshake is still in progress.
///
/// Returns 1 if handshaking, 0 if the handshake is complete, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_is_handshaking(handle: i32) -> i32 {
    clear_last_error();

    match conn_table().with(handle, |conn: &TlsConn| conn.is_handshaking() as i32) {
        Some(v) => v,
        None => {
            rlsm_err!("rlsm_tls_conn_is_handshaking: invalid connection handle"; return -1);
        }
    }
}

/// Get the negotiated ALPN protocol identifier.
///
/// Returns the number of bytes written into `out_buf`, 0 if no ALPN was
/// negotiated, or -1 on error.
#[no_mangle]
pub extern "C" fn rlsm_tls_conn_alpn(
    handle: i32,
    out_buf: *mut u8,
    buf_len: i32,
) -> i32 {
    clear_last_error();

    if out_buf.is_null() {
        rlsm_err!("rlsm_tls_conn_alpn: null out_buf pointer"; return -1);
    }
    if buf_len < 0 {
        rlsm_err!("rlsm_tls_conn_alpn: negative buf_len"; return -1);
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(out_buf, buf_len as usize) };

    match conn_table().with(handle, |conn: &TlsConn| -> Result<i32, String> {
        match conn.alpn_protocol() {
            None => Ok(0),
            Some(proto) => {
                if proto.len() > buf.len() {
                    return Err(format!(
                        "rlsm_tls_conn_alpn: buffer too small; need {} bytes",
                        proto.len()
                    ));
                }
                buf[..proto.len()].copy_from_slice(proto);
                Ok(proto.len() as i32)
            }
        }
    }) {
        Some(Ok(n)) => n,
        Some(Err(msg)) => {
            set_last_error(msg);
            -1
        }
        None => {
            rlsm_err!("rlsm_tls_conn_alpn: invalid connection handle"; return -1);
        }
    }
}
