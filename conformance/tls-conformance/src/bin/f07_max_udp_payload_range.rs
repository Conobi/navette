//! F07 — max_udp_payload_size < 1200.
//! GUARD-TAG: [QUIC-TP-MAX-UDP-PAYLOAD-RANGE]
//!
//! Phase α RED stub: exits 1 to feed the AC-2 RED-log capture.
//! Phase β fills in adversarial TP construction + assertion.

fn main() {
    eprintln!("RED stub: F07 — TLS-conformance Phase α");
    std::process::exit(1);
}
