//! F29 — unexpected EndOfEarlyData (0-RTT rejection path).
//! GUARD-TAG: [TLS-END-OF-EARLY-DATA]
//!
//! Phase α RED stub: exits 1 to feed the RED-log capture.
//! Phase β fills in adversarial 1-RTT injection + assertion.

fn main() {
    eprintln!("RED stub: F29 — TLS-conformance Phase α");
    std::process::exit(1);
}
