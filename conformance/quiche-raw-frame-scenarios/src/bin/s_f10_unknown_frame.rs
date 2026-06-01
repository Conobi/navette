//! s_f10_unknown_frame — F10.
//!
//! Injects a 1-RTT packet whose payload is the raw byte sequence
//! `[0xFE, 0x00]` — the varint 0xFE encodes (an unknown) frame type, with
//! the trailing 0x00 acting as a PADDING frame inside the packet. There
//! is no matching `quiche::frame::Frame` variant for the unknown type
//! byte, so the injection goes through `send_raw_1rtt_bytes` which uses
//! the `encode_pkt_with_payload` vendor helper.
//!
//! Per RFC 9000 §19.21, receivers MUST close with FRAME_ENCODING_ERROR
//! when an unknown frame type is encountered.
//!
//! Expected: transport-CC, code = `FRAME_ENCODING_ERROR (0x07)`, reason
//! contains `[QUIC-UNKNOWN-FRAME]`.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt_bytes, wait_connection_close,
    CLOSE_DEADLINE_MS,
};

const FAILURE_ID: &str = "F10";
const GUARD_TAG: &str = "[QUIC-UNKNOWN-FRAME]";
const EXPECTED_CODE: u64 = 0x07; // FRAME_ENCODING_ERROR
const UNKNOWN_FRAME_PAYLOAD: &[u8] = &[0xFE, 0x00];

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

    if let Err(e) = send_raw_1rtt_bytes(&mut conn, &socket, server, UNKNOWN_FRAME_PAYLOAD) {
        eprintln!("FAIL {FAILURE_ID}: send_raw_1rtt_bytes failed: {e}");
        return ExitCode::from(1);
    }

    let outcome = wait_connection_close(&mut conn, &socket, server, CLOSE_DEADLINE_MS);
    if assert_close(outcome, EXPECTED_CODE, GUARD_TAG, FAILURE_ID) {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}
