//! F27 — client offers an empty ALPN list.
//! GUARD-TAG: [TLS-NO-ALPN]
//!
//! RFC 9001 §8.1 makes ALPN mandatory for QUIC connections; the navette
//! server's QUIC config requires `h3`. A client that supplies an empty
//! `alpn_protocols` triggers TLS `no_application_protocol` (alert 120),
//! which the QUIC layer must surface as a CRYPTO_ERROR CONNECTION_CLOSE
//! whose low byte is 120 (or 50 if rustls could not extract a specific
//! AlertDescription — RFC 9001 §4.8).
//!
//! Drives the Initial flight only; the alert is emitted while the server
//! processes the ClientHello, so the CONNECTION_CLOSE arrives in the
//! Initial-space reply.

use rand::RngCore;
use tls_conformance_scenarios::{
    assert_crypto_error_low_byte, drive_handshake_initial_no_alpn,
    server_tp_bytes_well_formed, PacketBuilder,
};

fn main() {
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());
    let tp = server_tp_bytes_well_formed();

    match drive_handshake_initial_no_alpn(builder, &tp) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[120, 50]) {
            Ok(()) => std::process::exit(0),
            Err(diag) => {
                eprintln!("f27: assertion failed: {}", diag);
                eprintln!(
                    "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                    cc.error_code, cc.frame_type, cc.reason,
                );
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "f27: no CONNECTION_CLOSE received — server did not surface \
                 a no_application_protocol alert in its Initial reply"
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f27: handshake driver error: {}", e);
            std::process::exit(1);
        }
    }
}
