//! s_f17_new_token_server — F17.
//!
//! Sends a `NEW_TOKEN` frame to a server endpoint. Per RFC 9000 §19.7,
//! `NEW_TOKEN` MUST only be sent by a server (so a server endpoint MUST
//! treat receipt as a `PROTOCOL_VIOLATION`).
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0A)`, reason
//! contains `[QUIC-NEW-TOKEN-SERVER]`.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F17";
const GUARD_TAG: &str = "[QUIC-NEW-TOKEN-SERVER]";
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

    let frame = Frame::NewToken {
        token: b"x".to_vec(),
    };
    if let Err(e) = send_raw_1rtt(&mut conn, &socket, server, std::slice::from_ref(&frame)) {
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
