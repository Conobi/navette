//! F28 — ClientHello omits the `quic_transport_parameters` extension
//! (RFC 9001 §8.2). The navette TLS stack (rustls 0.23.37 server-side)
//! detects the absence in `process_client_hello` and emits a fatal
//! `MissingExtension` alert (TLS alert byte 109 = 0x6d per RFC 8446 §6),
//! which the QUIC layer routes to the wire as a CRYPTO_ERROR
//! CONNECTION_CLOSE per RFC 9001 §4.8 (error code 0x0100 | alert_code).
//!
//! Because rustls 0.23.37's public API always wraps the QUIC transport
//! parameters in `Some(...)` when they are supplied to
//! `ClientConnection::new`, the missing-extension path is unreachable
//! through the normal handshake driver. This binary uses the
//! `raw_client_hello` builder (hand-assembled TLS 1.3 ClientHello via
//! tls_codec) to construct a CH that DELIBERATELY omits codepoint 0x0039,
//! then drives it through the harness's `drive_handshake_with_raw_clienthello`.
//!
//! Accept-set on the low byte of the CRYPTO_ERROR code:
//!   * 109 (missing_extension)  — RFC 8446 §6 + RFC 9001 §8.2 expected.
//!   * 50  (decode_error)        — rustls fallback when it cannot extract
//!                                 a specific alert from the failure path.
//!   * 47  (illegal_parameter)   — defensive: some TLS stacks substitute
//!                                 this for a missing required extension.

use rand::RngCore;
use tls_conformance_scenarios::{
    assert_crypto_error_low_byte, drive_handshake_with_raw_clienthello,
    raw_client_hello::ClientHelloOmittingQuicTp, PacketBuilder,
};

fn main() {
    // Random 8-byte DCID per RFC 9000 §17.2.5; SCID is fixed for the
    // harness's purposes (server-side records it but does not validate).
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut dcid);
    let scid = [0u8; 8];
    let builder = PacketBuilder::new(dcid.to_vec(), scid.to_vec());

    // Build a ClientHello with every extension required to reach the
    // server-side check except `quic_transport_parameters`.
    let ch = match ClientHelloOmittingQuicTp::default().build() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("f28: failed to build raw ClientHello: {e}");
            std::process::exit(1);
        }
    };

    match drive_handshake_with_raw_clienthello(builder, &ch) {
        Ok(Some(cc)) => match assert_crypto_error_low_byte(&cc, &[109, 50, 47]) {
            Ok(()) => std::process::exit(0),
            Err(diag) => {
                eprintln!("f28: assertion failed: {diag}");
                eprintln!(
                    "  got error_code=0x{:x} frame_type=0x{:02x} reason={:?}",
                    cc.error_code, cc.frame_type, cc.reason,
                );
                std::process::exit(1);
            }
        },
        Ok(None) => {
            eprintln!(
                "f28: no CONNECTION_CLOSE received — server did not reject \
                 the ClientHello that omitted quic_transport_parameters \
                 (RFC 9001 §8.2)"
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("f28: handshake driver error: {e}");
            std::process::exit(1);
        }
    }
}
