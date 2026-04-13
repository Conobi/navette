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
