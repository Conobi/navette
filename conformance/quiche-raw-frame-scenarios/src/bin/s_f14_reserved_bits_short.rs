//! s_f14_reserved_bits_short — F14.
//!
//! Injects a 1-RTT (short-header) packet whose cleartext first byte has
//! bits 3 and 4 (mask 0x18) set. Per RFC 9000 §17.3.1, short-header
//! reserved bits MUST be zero on the wire; receivers MUST close with
//! PROTOCOL_VIOLATION when they observe them set.
//!
//! **Mask choice:** 0x18 (bits 3-4) only — NOT 0x04, which is the Key
//! Phase bit (RFC 9001 §6.1) and would trigger a key update rather
//! than the reserved-bits guard.
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0A)`, reason
//! contains `[QUIC-RESERVED-BITS-SHORT]`.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, wait_connection_close, CLOSE_DEADLINE_MS,
    MAX_DATAGRAM_SIZE,
};

const FAILURE_ID: &str = "F14";
const GUARD_TAG: &str = "[QUIC-RESERVED-BITS-SHORT]";
const EXPECTED_CODE: u64 = 0x0A; // PROTOCOL_VIOLATION
const RESERVED_MASK: u8 = 0x18; // short-header reserved bits (RFC 9000 §17.3.1)

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

    let frames = [Frame::Ping { mtu_probe: None }];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = match quiche::test_utils::encode_pkt_reserved_bits(
        &mut conn,
        quiche::Type::Short,
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
