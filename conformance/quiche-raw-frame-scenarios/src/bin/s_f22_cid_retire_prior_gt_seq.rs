//! s_f22_cid_retire_prior_gt_seq — F22.
//!
//! Sends a `NEW_CONNECTION_ID` frame with `retire_prior_to > seq_num`.
//! Per RFC 9000 §19.15, `retire_prior_to` MUST NOT exceed `seq_num`;
//! receivers MUST close with `FRAME_ENCODING_ERROR`.
//!
//! Expected: transport-CC, code = `FRAME_ENCODING_ERROR (0x07)`, reason
//! contains `[QUIC-CID-RETIRE-PRIOR-GT-SEQ]`.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F22";
const GUARD_TAG: &str = "[QUIC-CID-RETIRE-PRIOR-GT-SEQ]";
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

    let frame = Frame::NewConnectionId {
        seq_num: 5,
        retire_prior_to: 10,
        conn_id: vec![1u8; 8],
        reset_token: [0u8; 16],
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
