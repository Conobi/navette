//! s_f18_max_stream_data_nonexist — F18.
//!
//! Sends a `MAX_STREAM_DATA` frame referencing a stream id far beyond any
//! stream the peer has opened. Per RFC 9000 §19.10, receiving a
//! `MAX_STREAM_DATA` for a stream that was never created MUST be treated
//! as `STREAM_STATE_ERROR`.
//!
//! Expected: transport-CC, code = `STREAM_STATE_ERROR (0x05)`, reason
//! contains `[QUIC-MAX-STREAM-DATA-NONEXIST]`.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F18";
const GUARD_TAG: &str = "[QUIC-MAX-STREAM-DATA-NONEXIST]";
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

    // Stream id 99999 has never been created on either endpoint; the server
    // MUST reject `MAX_STREAM_DATA` referencing it.
    let frame = Frame::MaxStreamData {
        stream_id: 99999,
        max: 0x10000,
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
