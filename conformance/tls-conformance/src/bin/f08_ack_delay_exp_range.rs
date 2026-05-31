//! F08 — ack_delay_exponent above RFC 9000 §7.4 maximum (21 > 20).
//! GUARD-TAG: [QUIC-TP-ACK-DELAY-EXP-RANGE]
//!
//! Drives navette with a TP block that appends ack_delay_exponent (0x0a) = 21,
//! violating the RFC 9000 §18.2 requirement that the value MUST NOT exceed 20.
//! Expects the server to close with TRANSPORT_PARAMETER_ERROR (0x08) and a
//! reason phrase containing [QUIC-TP-ACK-DELAY-EXP-RANGE].

use rand::RngCore;
use tls_conformance_scenarios::{
    adversarial_tp::f08_ack_delay_exponent_above_max,
    assert_transport_param_error_with_tag,
    drive_handshake_full,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = f08_ack_delay_exponent_above_max();

    match drive_handshake_full(builder, &tp) {
        Ok(Some(cc)) => {
            match assert_transport_param_error_with_tag(&cc, "[QUIC-TP-ACK-DELAY-EXP-RANGE]") {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f08: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!("f08: no CONNECTION_CLOSE received (server silently dropped or timed out)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f08: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
