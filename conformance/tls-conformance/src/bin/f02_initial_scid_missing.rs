//! F02 — initial_source_connection_id missing.
//! GUARD-TAG: [QUIC-TP-INITIAL-SCID-MISSING]
//!
//! RFC 9000 §7.3 requires every client to advertise
//! `initial_source_connection_id` (0x0f) in its transport-parameters extension.
//! This scenario drives navette with a TP block that deliberately omits 0x0f
//! and expects the server to close with TRANSPORT_PARAMETER_ERROR (0x08) plus
//! a reason phrase containing the GUARD-TAG above.

use rand::RngCore;
use tls_conformance_scenarios::{
    adversarial_tp::f02_missing_initial_scid,
    assert_transport_param_error_with_tag,
    drive_handshake_full,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = f02_missing_initial_scid();

    match drive_handshake_full(builder, &tp) {
        Ok(Some(cc)) => {
            match assert_transport_param_error_with_tag(&cc, "[QUIC-TP-INITIAL-SCID-MISSING]") {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f02: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!("f02: no CONNECTION_CLOSE received (server silently dropped or timed out)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f02: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
