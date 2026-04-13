//! librustls-mojo: Rustls C FFI for Mojo
//!
//! Exposes rustls QUIC-TLS and TCP-TLS functionality through integer handles.
//! Misuse-resistant: no raw pointers cross the FFI boundary.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod handles;
pub mod error;
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
};
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
    rlsm_quic_conn_transport_params,
    rlsm_quic_conn_alpn,
    rlsm_quic_conn_zero_rtt_keys,
    rlsm_quic_conn_is_early_data_accepted,
};

#[cfg(feature = "insecure")]
pub use tcp::rlsm_client_config_new_insecure;
