//! Shared helpers for h3i scenarios in the navette conformance suite.

use h3i::config::Config;

/// Build an h3i `Config` targeting `127.0.0.1:<port>` with peer
/// verification DISABLED. Suitable only for loopback testing against
/// a server using a self-signed cert — never use this against a
/// non-loopback target.
pub fn loopback_config(port: u16) -> Config {
    Config::new()
        .with_host_port(format!("127.0.0.1:{port}"))
        .with_idle_timeout(2000)
        .verify_peer(false)
        .build()
        .expect("h3i config build failed")
}
