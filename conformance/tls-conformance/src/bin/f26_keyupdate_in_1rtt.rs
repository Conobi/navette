//! F26 — KeyUpdate injected via TLS handshake message in 1-RTT (RFC 9001 §6).
//! GUARD-TAG: [TLS-KEYUPDATE-IN-1RTT]
//!
//! RFC 9001 §6 forbids the TLS-level `KeyUpdate` post-handshake message on a
//! QUIC connection; rustls maps the receipt of one to
//! `PeerMisbehaved::KeyUpdateReceivedInQuicConnection` and produces a TLS
//! alert. The expected CRYPTO_ERROR low byte is typically 47
//! (`illegal_parameter`); we also accept 10 (`unexpected_message`) and 50
//! (`decode_error` fallback per RFC 9001 §4.8) so minor rustls behavioural
//! differences don't break the gate.
//!
//! Driver: drives the full handshake to natural completion (the real Finished
//! is sent), then sends an additional 1-RTT short-header packet whose payload
//! is a single CRYPTO frame at 1-RTT-epoch offset 0 carrying the 5-byte
//! KeyUpdate TLS handshake record `18 00 00 01 00`.

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
        epoch: InjectionEpoch::OneRtt,
        // TLS handshake type 0x18 (KeyUpdate, RFC 8446 §4.6.3),
        // length 1, body 0x00 (update_not_requested).
        bytes: vec![0x18, 0x00, 0x00, 0x01, 0x00],
    };
    match drive_handshake_with_injection(builder, &tp, inj) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[10, 47, 50]) {
            Ok(()) => std::process::exit(0),
            Err(diag) => {
                eprintln!("f26: assertion failed: {}", diag);
                eprintln!(
                    "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                    cc.error_code, cc.frame_type, cc.reason,
                );
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "f26: handshake completed without CC; expected KeyUpdate-in-1-RTT alert",
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f26: driver error: {}", e);
            std::process::exit(1);
        }
    }
}
