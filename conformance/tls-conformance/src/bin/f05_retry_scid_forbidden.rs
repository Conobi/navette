//! F05 — retry_source_connection_id forbidden on client.
//! GUARD-TAG: [QUIC-TP-RETRY-SCID-FORBIDDEN]
//!
//! Phase α RED stub: exits 1 to feed the AC-2 RED-log capture.
//! Phase β fills in adversarial TP construction + assertion.

fn main() {
    eprintln!("RED stub: F05 — TLS-conformance Phase α");
    std::process::exit(1);
}
