//! s_f16_stop_sending_local_not_created — F16 (stretch row).
//!
//! Sends a `STOP_SENDING` frame targeting stream id 999 — a server-uni
//! stream (`999 & 3 == 3`) far beyond any stream navette has opened.
//! Per RFC 9000 §19.5, `STOP_SENDING` MUST only target a stream that
//! the receiver has opened; targeting an uncreated local stream is
//! illegal and the receiver MUST close with `STREAM_STATE_ERROR`.
//!
//! Expected: transport-CC, code = `STREAM_STATE_ERROR (0x05)`, reason
//! contains `[QUIC-STOP-LOCAL-NOT-CREATED]`.
//!
//! # Predicate width
//!
//! The navette-side predicate `predicate_f16_stop_sending_local_not_created`
//! already exists at `connection.mojo:1130-1139`. The scenario uses id
//! 999 as a representative case for any unallocated local stream id.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F16";
const GUARD_TAG: &str = "[QUIC-STOP-LOCAL-NOT-CREATED]";
const EXPECTED_CODE: u64 = 0x05; // STREAM_STATE_ERROR

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

    let frame = Frame::StopSending {
        stream_id: 999,
        error_code: 0,
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
