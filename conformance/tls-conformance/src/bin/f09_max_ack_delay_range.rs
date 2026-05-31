//! F09 — max_ack_delay at or above 2^14 (16384 ≥ 2^14).
//! GUARD-TAG: [QUIC-TP-MAX-ACK-DELAY-RANGE]
//!
//! Drives navette with a TP block that appends max_ack_delay (0x0b) = 16384,
//! violating the RFC 9000 §18.2 requirement that the value MUST be strictly
//! less than 2^14 = 16384. Expects the server to close with
//! TRANSPORT_PARAMETER_ERROR (0x08) and a reason phrase containing
//! [QUIC-TP-MAX-ACK-DELAY-RANGE].

use rand::RngCore;
use tls_conformance_scenarios::{
    adversarial_tp::f09_max_ack_delay_above_threshold,
    assert_transport_param_error_with_tag,
    drive_handshake_initial,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = f09_max_ack_delay_above_threshold();

    match drive_handshake_initial(builder, &tp) {
        Ok(Some(cc)) => {
            match assert_transport_param_error_with_tag(&cc, "[QUIC-TP-MAX-ACK-DELAY-RANGE]") {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f09: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!("f09: no CONNECTION_CLOSE received (server silently dropped or timed out)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f09: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
