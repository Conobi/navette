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
