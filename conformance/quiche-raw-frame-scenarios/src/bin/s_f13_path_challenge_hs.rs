//! s_f13_path_challenge_hs — F13.
//!
//! Injects a `PATH_CHALLENGE` frame in a Handshake-epoch packet. Per
//! RFC 9000 §8.2 / §17.2.4, PATH_CHALLENGE is only valid in the
//! 1-RTT epoch; receivers MUST close the connection on a
//! PATH_CHALLENGE seen in Initial or Handshake space with
//! PROTOCOL_VIOLATION.
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0A)`, reason
//! contains `[QUIC-PATH-CHALLENGE-HS]`.
//!
//! # Timing window
//!
//! Like F12, this scenario needs live Handshake-epoch keys for
//! `encode_pkt`. The quiche client retires them on `HANDSHAKE_DONE`
//! (RFC 9001 §4.9.1). `navette_connect_until_handshake_keys` returns
//! BEFORE the client's Finished is sent, so the seal is still live and
//! the injection window is deterministic.

use std::env;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect_until_handshake_keys, wait_connection_close,
    CLOSE_DEADLINE_MS, MAX_DATAGRAM_SIZE,
};

const FAILURE_ID: &str = "F13";
const GUARD_TAG: &str = "[QUIC-PATH-CHALLENGE-HS]";
const EXPECTED_CODE: u64 = 0x0A; // PROTOCOL_VIOLATION

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    let (mut conn, socket, server) = navette_connect_until_handshake_keys(port);

    let frames = [Frame::PathChallenge { data: [0u8; 8] }];
    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = match quiche::test_utils::encode_pkt(
        &mut conn,
        quiche::Type::Handshake,
        &frames,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: encode_pkt failed: {e:?}");
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
