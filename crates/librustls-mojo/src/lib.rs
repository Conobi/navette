//! librustls-mojo: Rustls C FFI for Mojo
//!
//! Exposes rustls QUIC-TLS and TCP-TLS functionality through integer handles.
//! Misuse-resistant: no raw pointers cross the FFI boundary.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod handles;
pub mod error;
// `decode` module (gzip/brotli) moved to crates/libcompress-mojo per
// spec 2026-05-17-compress-shim-split.md. Removing the module makes
// AC1's "zero compression symbols in librustls_mojo.so" provable via
// `nm -D` (enforced in scripts/check_integrations.sh §2.5).
mod quic;
mod quic_hs;
mod config;
mod tcp;

pub use error::rlsm_last_error;
pub use quic::{
    rlsm_initial_keys,
    rlsm_initial_keys_raw,
    rlsm_keys_local_encrypt,
    rlsm_keys_remote_decrypt,
    rlsm_keys_local_header_protect,
    rlsm_keys_remote_header_unprotect,
    rlsm_keys_tag_len,
    rlsm_keys_free,
    rlsm_aes_gcm_128_seal,
    rlsm_aes_gcm_128_open,
    rlsm_hmac_sha256,
};
#[cfg(any(test, feature = "test-instrumentation"))]
pub use quic::{rlsm_test_keys_free_count, rlsm_test_keys_free_reset};
pub use config::{
    rlsm_client_config_new,
    rlsm_server_config_new,
    rlsm_config_free,
};
pub use tcp::{
    rlsm_tls_client_new,
    rlsm_tls_server_new,
    rlsm_tls_conn_free,
    rlsm_tls_conn_read_tls,
    rlsm_tls_conn_write_tls,
    rlsm_tls_conn_read_plaintext,
    rlsm_tls_conn_write_plaintext,
    rlsm_tls_conn_is_handshaking,
    rlsm_tls_conn_alpn,
};

pub use quic_hs::{
    rlsm_quic_client_config_new,
    rlsm_quic_client_config_with_ca,
    rlsm_quic_server_config_new,
    rlsm_quic_client_conn_new,
    rlsm_quic_server_conn_new,
    rlsm_quic_conn_free,
    rlsm_quic_conn_write_hs,
    rlsm_quic_conn_read_hs,
    rlsm_quic_conn_alert,
    rlsm_quic_conn_take_keys,
    rlsm_quic_conn_take_next_keys,
    rlsm_quic_conn_is_handshaking,
    rlsm_quic_conn_handshake_kind,
    rlsm_quic_conn_transport_params,
    rlsm_quic_conn_alpn,
    rlsm_quic_conn_zero_rtt_keys,
    rlsm_quic_conn_is_early_data_accepted,
};

#[cfg(feature = "insecure")]
pub use tcp::rlsm_client_config_new_insecure;

/// No-op FFI function for thunk-overhead microbench.
/// Returns 0 immediately. Used to isolate Mojo↔Rust FFI crossing cost
/// from the work done inside any specific FFI call body.
#[no_mangle]
pub extern "C" fn rlsm_noop() -> i32 {
    0
}
