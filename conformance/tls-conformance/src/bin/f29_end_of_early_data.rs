//! F29 — unexpected `EndOfEarlyData` (RFC 9001 §8.3).
//! GUARD-TAG: [TLS-END-OF-EARLY-DATA]
//!
//! RFC 9001 §8.3 forbids `EndOfEarlyData` on a QUIC connection (early-data
//! framing is a TCP-only TLS message). A client that sends one must trigger
//! `unexpected_message` (alert 10), surfaced as a CRYPTO_ERROR
//! CONNECTION_CLOSE. We accept low bytes 10, 47, and 50 (per the same
//! tolerance as F25/F26) to absorb minor rustls behavioural shifts.
//!
//! Driver: substitution mode — Handshake-epoch CRYPTO at offset 0 carrying
//! the 4-byte EndOfEarlyData record `05 00 00 00` (TLS handshake type 0x05,
//! length 0 per RFC 8446 §4.5).

use rand::RngCore;
use tls_conformance_scenarios::{
    assert_crypto_error_low_byte, drive_handshake_with_injection, server_tp_bytes_well_formed,
    Injection, InjectionEpoch, PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = server_tp_bytes_well_formed();

    let inj = Injection {
        epoch: InjectionEpoch::Handshake,
        // TLS handshake type 0x05 (EndOfEarlyData, RFC 8446 §4.5), length 0.
        bytes: vec![0x05, 0x00, 0x00, 0x00],
    };
    match drive_handshake_with_injection(builder, &tp, inj) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[10, 47, 50]) {
            Ok(()) => std::process::exit(0),
            Err(diag) => {
                eprintln!("f29: assertion failed: {}", diag);
                eprintln!(
                    "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                    cc.error_code, cc.frame_type, cc.reason,
                );
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "f29: handshake completed without CC; expected unexpected_message alert",
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f29: driver error: {}", e);
            std::process::exit(1);
        }
    }
}
