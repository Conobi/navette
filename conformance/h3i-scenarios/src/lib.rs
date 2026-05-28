//! Shared helpers for h3i scenarios in the navette conformance suite.

use h3i::config::Config;

/// Build an h3i `Config` targeting the local hello_h3_server on the given port.
///
/// Loopback usage, so cert verification is disabled. Idle timeout kept short
/// so failing scenarios fail fast (2s).
pub fn default_local_config(port: u16) -> Config {
    Config::new()
        .with_host_port(format!("127.0.0.1:{port}"))
        .with_idle_timeout(2000)
        .verify_peer(false)
        .build()
        .expect("h3i config build failed")
}
