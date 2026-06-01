//! F25 — KeyUpdate injected during TLS handshake (RFC 9001 §6).
//! GUARD-TAG: [TLS-KEYUPDATE-IN-HANDSHAKE]
//!
//! RFC 9001 §6 forbids `KeyUpdate` TLS messages on a QUIC connection in any
//! TLS state; in particular, an unsolicited KeyUpdate during the Handshake
//! must trigger `unexpected_message` (alert 10) surfaced as a CRYPTO_ERROR
//! CONNECTION_CLOSE. Empirically navette / rustls may surface alert 10, 47
//! (`illegal_parameter`), or 50 (`decode_error` fallback per RFC 9001 §4.8);
//! we accept all three so minor rustls behavioural shifts don't tip the gate.
//!
//! Driver: substitution mode — the harness pumps rustls's write_hs to
//! materialise the Handshake-epoch keys, DISCARDS the natural Finished, and
//! sends a single Handshake-epoch CRYPTO frame at offset 0 carrying the
//! 5-byte KeyUpdate TLS handshake record `18 00 00 01 00`
//! (type=0x18 KeyUpdate, length=1, body=0x00 update_not_requested per
//! RFC 8446 §4.6.3).

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
        // TLS handshake type 0x18 (KeyUpdate, RFC 8446 §4.6.3),
        // length 1, body 0x00 (update_not_requested).
        bytes: vec![0x18, 0x00, 0x00, 0x01, 0x00],
    };
    match drive_handshake_with_injection(builder, &tp, inj) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[10, 47, 50]) {
            Ok(()) => std::process::exit(0),
            Err(diag) => {
                eprintln!("f25: assertion failed: {}", diag);
                eprintln!(
                    "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                    cc.error_code, cc.frame_type, cc.reason,
                );
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "f25: handshake completed without CC; expected unexpected_message alert",
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f25: driver error: {}", e);
            std::process::exit(1);
        }
    }
}
