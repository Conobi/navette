//! F07 — max_udp_payload_size below RFC 9000 §7.4 minimum (1100 < 1200).
//! GUARD-TAG: [QUIC-TP-MAX-UDP-PAYLOAD-RANGE]
//!
//! Drives navette with a TP block where max_udp_payload_size (0x03) = 1100,
//! violating the RFC 9000 §7.4 requirement that the value MUST be at least
//! 1200. Expects the server to close with TRANSPORT_PARAMETER_ERROR (0x08)
//! and a reason phrase containing [QUIC-TP-MAX-UDP-PAYLOAD-RANGE].

use rand::RngCore;
use tls_conformance_scenarios::{
    adversarial_tp::f07_max_udp_payload_below_min,
    assert_transport_param_error_with_tag,
    drive_handshake_full,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = f07_max_udp_payload_below_min();

    match drive_handshake_full(builder, &tp) {
        Ok(Some(cc)) => {
            match assert_transport_param_error_with_tag(&cc, "[QUIC-TP-MAX-UDP-PAYLOAD-RANGE]") {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f07: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!("f07: no CONNECTION_CLOSE received (server silently dropped or timed out)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f07: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
