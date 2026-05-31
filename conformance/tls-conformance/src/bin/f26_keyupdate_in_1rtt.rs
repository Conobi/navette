//! F26 — KeyUpdate injected via TLS handshake message in 1-RTT (RFC 9001 §6).
//! GUARD-TAG: [TLS-KEYUPDATE-IN-1RTT]
//!
//! RFC 9001 §6 forbids the TLS-level `KeyUpdate` post-handshake message on a
//! QUIC connection; rustls maps the receipt of one to
//! `PeerMisbehaved::KeyUpdateReceivedInQuicConnection` and produces a TLS
//! alert. The expected CRYPTO_ERROR low byte is 47 (`illegal_parameter`) per
//! rustls 0.23, with 50 as the fallback when no specific AlertDescription
//! is available.
//!
//! Driver mode (β.5): BEST-EFFORT. Drives the Initial flight only; injecting
//! the adversarial KeyUpdate inside a 1-RTT short-header packet requires:
//!   * completing the full handshake (Initial → Handshake → 1-RTT) so the
//!     server has 1-RTT read keys available,
//!   * extracting `KeyChange::OneRtt` secrets from rustls and threading them
//!     to `librustls-mojo`, and
//!   * extending `PacketBuilder::encode_1rtt` to embed a CRYPTO-frame-bearing
//!     short-header packet (it currently treats the payload as opaque bytes).
//!
//! All three steps are deferred from β.5; the binary fails with the
//! diagnostic below until the full epoch plumbing lands.

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
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[47, 50]) {
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
                "f26: DEFERRED — 1-RTT-epoch CRYPTO injection not yet \
                 supported. Driver only sent the Initial flight; the server \
                 has not yet surfaced a KeyUpdateReceivedInQuicConnection \
                 alert because the adversarial KeyUpdate record was never \
                 injected post-handshake. Requires full Initial→Handshake→1-RTT \
                 progression, 1-RTT key extraction from rustls KeyChange, and \
                 a CRYPTO-aware PacketBuilder::encode_1rtt."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f26: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
