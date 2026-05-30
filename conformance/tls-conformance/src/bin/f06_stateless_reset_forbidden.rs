//! F06 — stateless_reset_token forbidden on client.
//! GUARD-TAG: [QUIC-TP-STATELESS-RESET-FORBIDDEN]
//!
//! RFC 9000 §18.2: `stateless_reset_token` (0x02) is server-only — only the
//! server issues the token paired with a server-chosen connection ID. A
//! client emitting it is a protocol violation; the server must close with
//! TRANSPORT_PARAMETER_ERROR (0x08). Reason phrase must contain the GUARD-TAG.

use rand::RngCore;
use tls_conformance_scenarios::{
    adversarial_tp::f06_stateless_reset_forbidden,
    assert_transport_param_error_with_tag,
    drive_handshake_initial,
    PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = f06_stateless_reset_forbidden();

    match drive_handshake_initial(builder, &tp) {
        Ok(Some(cc)) => {
            match assert_transport_param_error_with_tag(&cc, "[QUIC-TP-STATELESS-RESET-FORBIDDEN]") {
                Ok(()) => std::process::exit(0),
                Err(diag) => {
                    eprintln!("f06: assertion failed: {}", diag);
                    eprintln!(
                        "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                        cc.error_code, cc.frame_type, cc.reason,
                    );
                    std::process::exit(1);
                }
            }
        }
        Ok(None) => {
            eprintln!("f06: no CONNECTION_CLOSE received (server silently dropped or timed out)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f06: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
