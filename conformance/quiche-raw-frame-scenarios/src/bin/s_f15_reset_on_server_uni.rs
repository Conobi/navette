//! s_f15_reset_on_server_uni — F15 (stretch row).
//!
//! Sends a `RESET_STREAM` frame targeting stream id 3 — navette's
//! server-initiated H3 control stream (server-uni; suffix `0b11` per
//! RFC 9000 §2.1, opened by `navette/h3/connection.mojo:400` via
//! `_bootstrap_local_streams`). Per RFC 9000 §19.4, `RESET_STREAM` MUST
//! only be sent by the stream's initiator; a client-sent RESET on any
//! server-initiated stream is illegal regardless of whether the server
//! has opened that specific id.
//!
//! Expected: transport-CC, code = `STREAM_STATE_ERROR (0x05)`, reason
//! contains `[QUIC-RESET-SEND-ONLY]`.
//!
//! # Predicate width (spec §Risks #6)
//!
//! The navette-side predicate `predicate_f15_reset_on_server_uni` is
//! intentionally broad: it rejects any client-sent RESET_STREAM with
//! `(stream_id & 3) == 3` regardless of whether the stream was opened.
//! Tightening it would let a malicious client probe id-space for
//! "uncreated" vs "created" server-uni streams via the close-vs-no-close
//! oracle. The scenario uses id 3 as a representative case; any other
//! server-uni id would behave identically.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F15";
const GUARD_TAG: &str = "[QUIC-RESET-SEND-ONLY]";
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

    let frame = Frame::ResetStream {
        stream_id: 3,
        error_code: 0,
        final_size: 0,
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
