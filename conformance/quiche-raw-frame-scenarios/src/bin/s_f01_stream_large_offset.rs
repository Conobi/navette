//! s_f01_stream_large_offset — F01.
//!
//! Injects a STREAM frame on a fresh client-bidi stream (id=4) carrying a
//! zero-length payload at offset `0x3FFF_FFFF_FFFF_FFFF` (~2^62 - 1, well
//! beyond any per-stream flow-control window). Per RFC 9000 §4.1, the
//! receiver MUST close with FLOW_CONTROL_ERROR.
//!
//! Expected: transport-CC, code = `FLOW_CONTROL_ERROR (0x03)`, reason
//! contains `[QUIC-STREAM-LARGE-OFFSET]`.
//!
//! Phase α expectation: FAIL (navette currently raises and the
//! try/except at `connection.mojo:911` swallows the violation). Phase β
//! lifts the guard to a `close_transport` call.

use std::env;
use std::process::ExitCode;

use quiche::range_buf::RangeBuf;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F01";
const GUARD_TAG: &str = "[QUIC-STREAM-LARGE-OFFSET]";
const EXPECTED_CODE: u64 = 0x03; // FLOW_CONTROL_ERROR

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

    // RangeBuf::from(&[], offset, fin=false) builds a zero-length stream
    // chunk at the chosen offset; that's all the receive-side flow-control
    // check needs to trip on (offset + len > peer-advertised limit).
    let offset: u64 = 0x3FFF_FFFF_FFFF_FFFF;
    let data = RangeBuf::from(&[], offset, false);
    let frame = quiche::frame::Frame::Stream { stream_id: 4, data };

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
