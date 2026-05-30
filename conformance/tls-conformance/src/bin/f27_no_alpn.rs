//! F27 — client offers no ALPN.
//! GUARD-TAG: [TLS-NO-ALPN]
//!
//! Phase α RED stub: exits 1 to feed the RED-log capture.
//! Phase β fills in adversarial 1-RTT injection + assertion.

fn main() {
    eprintln!("RED stub: F27 — TLS-conformance Phase α");
    std::process::exit(1);
}
