//! s_f12_reserved_bits_hs — F12.
//!
//! Injects a Handshake-epoch QUIC packet (long header, type=2) whose
//! cleartext first byte has bits 2 and 3 (mask 0x0C) set. Per RFC 9000
//! §17.2, long-header reserved bits MUST be zero on the wire — receivers
//! that observe them set MUST close with PROTOCOL_VIOLATION (RFC 9000
//! §17.2 / §17.3).
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0A)`, reason
//! contains `[QUIC-RESERVED-BITS-HS]`.
//!
//! # Timing window
//!
//! The vendored `encode_pkt_reserved_bits` needs live Handshake-epoch
//! keys (`crypto_ctx[Epoch::Handshake].crypto_seal`). The quiche client
//! drops those when it receives HANDSHAKE_DONE (vendored
//! `src/lib.rs:8195`). `navette_connect` exits as soon as
//! `is_established()` returns true; on local loopback that window is
//! tight but well-defined. If the scenario hits `InvalidState` here it
//! falls through to a `FAIL F12: setup` line — the gate treats this
//! as a regular RED row (no special exit code).

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, wait_connection_close, CLOSE_DEADLINE_MS,
    MAX_DATAGRAM_SIZE,
};

const FAILURE_ID: &str = "F12";
const GUARD_TAG: &str = "[QUIC-RESERVED-BITS-HS]";
const EXPECTED_CODE: u64 = 0x0A; // PROTOCOL_VIOLATION
const RESERVED_MASK: u8 = 0x0C; // long-header reserved bits (RFC 9000 §17.2)

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    let panic_result = std::panic::catch_unwind(|| navette_connect(port));
    let (mut conn, socket, server) = match panic_result {
        Ok(triple) => triple,
        Err(_) => {
            eprintln!("FAIL {FAILURE_ID}: handshake did not establish");
            return ExitCode::from(1);
        }
    };

    // PING is the smallest ack-eliciting frame; the server still has to
    // walk the header before it processes any frames, so the reserved-bit
    // check fires regardless of payload.
    let frames = [Frame::Ping { mtu_probe: None }];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = match quiche::test_utils::encode_pkt_reserved_bits(
        &mut conn,
        quiche::Type::Handshake,
        &frames,
        RESERVED_MASK,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: encode_pkt_reserved_bits failed: {e:?}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = socket.send_to(&buf[..written], server) {
        eprintln!("FAIL {FAILURE_ID}: send_to failed: {e}");
        return ExitCode::from(1);
    }

    let outcome = wait_connection_close(&mut conn, &socket, server, CLOSE_DEADLINE_MS);
    if assert_close(outcome, EXPECTED_CODE, GUARD_TAG, FAILURE_ID) {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}
