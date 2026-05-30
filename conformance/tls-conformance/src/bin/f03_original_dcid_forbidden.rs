//! F03 — original_destination_connection_id forbidden on client.
//! GUARD-TAG: [QUIC-TP-ORIGINAL-DCID-FORBIDDEN]
//!
//! Phase α RED stub: exits 1 to feed the AC-2 RED-log capture.
//! Phase β fills in adversarial TP construction + assertion.

fn main() {
    eprintln!("RED stub: F03 — TLS-conformance Phase α");
    std::process::exit(1);
}
