//! F29 — unexpected `EndOfEarlyData` (RFC 9001 §8.3).
//! GUARD-TAG: [TLS-END-OF-EARLY-DATA]
//!
//! RFC 9001 §8.3 forbids `EndOfEarlyData` on a QUIC connection (early-data
//! framing is a TCP-only TLS message). A client that sends one must trigger
//! `unexpected_message` (alert 10), surfaced as a CRYPTO_ERROR
//! CONNECTION_CLOSE with low byte 10 (or 50 fallback per RFC 9001 §4.8).
//!
//! Driver mode (β.5): BEST-EFFORT. Drives the Initial flight only; injecting
//! `EndOfEarlyData` requires:
//!   * a session-resumption-capable Initial that advertises early-data, and
//!   * Handshake-epoch CRYPTO injection (the EndOfEarlyData message is
//!     emitted between the server's encrypted_extensions and the client's
//!     Finished — i.e. Handshake-space CRYPTO frames),
//!   * 0-RTT key derivation + Handshake-epoch key transfer from rustls
//!     through `librustls-mojo` to the harness's `PacketBuilder`.
//!
//! All of that is deferred from β.5; the binary fails with the diagnostic
//! below until the epoch plumbing lands.

use rand::RngCore;
use tls_conformance_scenarios::{
    assert_crypto_error_low_byte, drive_handshake_initial, server_tp_bytes_well_formed,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = server_tp_bytes_well_formed();

    match drive_handshake_initial(builder, &tp) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[10, 50]) {
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
                "f29: DEFERRED — Handshake-epoch CRYPTO injection not yet \
                 supported. Driver only sent the Initial flight; the server \
                 has not yet surfaced an unexpected_message alert because the \
                 adversarial EndOfEarlyData record was never injected. \
                 Requires 0-RTT session resumption + Handshake-epoch key \
                 extraction from rustls KeyChange + a CRYPTO-aware \
                 PacketBuilder::encode_handshake."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f29: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
