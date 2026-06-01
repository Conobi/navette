//! s_f21_streams_blocked_overflow — F21.
//!
//! Sends a `STREAMS_BLOCKED` frame with a `limit` strictly greater than
//! 2^60. Per RFC 9000 §19.14, the limit field MUST NOT exceed 2^60.
//! Receivers MUST close with `FRAME_ENCODING_ERROR`.
//!
//! Expected: transport-CC, code = `FRAME_ENCODING_ERROR (0x07)`, reason
//! contains `[QUIC-STREAMS-BLOCKED-OVERFLOW]`.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F21";
const GUARD_TAG: &str = "[QUIC-STREAMS-BLOCKED-OVERFLOW]";
const EXPECTED_CODE: u64 = 0x07; // FRAME_ENCODING_ERROR

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

    let frame = Frame::StreamsBlockedBidi {
        limit: (1u64 << 60) + 1,
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
