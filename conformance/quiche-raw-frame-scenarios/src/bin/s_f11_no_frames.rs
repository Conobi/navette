//! s_f11_no_frames — F11.
//!
//! Injects a 1-RTT packet whose authenticated payload is zero-length —
//! no frames at all, only the packet header + AEAD tag. Per RFC 9000
//! §12.4 a QUIC packet MUST carry at least one frame; an empty payload
//! is a PROTOCOL_VIOLATION.
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0A)`, reason
//! contains `[QUIC-NO-FRAMES]`.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F11";
const GUARD_TAG: &str = "[QUIC-NO-FRAMES]";
const EXPECTED_CODE: u64 = 0x0A; // PROTOCOL_VIOLATION

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

    // Zero-length frame slice → encode_pkt emits a packet with payload_len=0.
    if let Err(e) = send_raw_1rtt(&mut conn, &socket, server, &[]) {
        eprintln!("FAIL {FAILURE_ID}: send_raw_1rtt failed: {e}");
        return ExitCode::from(1);
    }

    let outcome = wait_connection_close(&mut conn, &socket, server, CLOSE_DEADLINE_MS);
    if assert_close(outcome, EXPECTED_CODE, GUARD_TAG, FAILURE_ID) {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}
