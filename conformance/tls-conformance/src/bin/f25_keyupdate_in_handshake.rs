//! F25 — KeyUpdate injected during TLS handshake (RFC 9001 §6).
//! GUARD-TAG: [TLS-KEYUPDATE-IN-HANDSHAKE]
//!
//! RFC 9001 §6 forbids `KeyUpdate` TLS messages on a QUIC connection in any
//! TLS state; in particular, an unsolicited KeyUpdate during the Handshake
//! must trigger `unexpected_message` (alert 10) surfaced as a CRYPTO_ERROR
//! CONNECTION_CLOSE whose low byte is 10 (or 50 fallback per RFC 9001 §4.8).
//!
//! Driver mode (β.5): BEST-EFFORT. Constructs the well-formed Initial flight,
//! sends it, and inspects the server's Initial-space reply. Injecting the
//! adversarial KeyUpdate record requires Handshake-epoch CRYPTO frame
//! construction, which depends on:
//!   * extracting `KeyChange::Handshake` secrets from rustls
//!     (`ClientConnection::write_hs` returns `Option<KeyChange>` only after
//!     the server's ServerHello is processed),
//!   * wiring those secrets back through `librustls-mojo`'s `rlsm_initial_keys`
//!     analogue for Handshake-epoch keys, and
//!   * extending `PacketBuilder::encode_handshake` to embed a CRYPTO frame
//!     payload (it currently encodes raw payload bytes).
//!
//! All three pieces are out of scope for β.5; the binary exits 1 with the
//! deferral diagnostic below until that plumbing lands. Once present, replace
//! the post-Initial branch with a real Handshake-epoch injection driver.

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
        Ok(Some(cc)) => {
            // If the server happens to close at the Initial epoch with alert 10
            // (or fallback 50) we accept it; otherwise log + fail.
            match assert_crypto_error_low_byte(&cc, &[10]) {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f25: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!(
                "f25: DEFERRED — Handshake-epoch CRYPTO injection not yet \
                 supported. Driver only sent the Initial flight; the server \
                 has not yet surfaced an unexpected_message alert because the \
                 adversarial KeyUpdate record was never injected. Requires \
                 Handshake-epoch key extraction from rustls KeyChange plus a \
                 CRYPTO-aware PacketBuilder::encode_handshake."
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f25: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
