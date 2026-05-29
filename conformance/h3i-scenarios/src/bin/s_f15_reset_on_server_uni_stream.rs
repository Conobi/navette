//! F15 — RFC 9000 §19.4 + §3.2 (cluster C4).
//! Sending RESET_STREAM for a stream where the peer is the sender — i.e.,
//! a server-uni stream from the client's perspective — MUST trip
//! STREAM_STATE_ERROR. navette's server control stream is stream id 3
//! (`local_opened_uni*4+3` per stream_map.mojo:214).
//!
//! GUARD-TAG: [QUIC-RESET-SEND-ONLY]
//! Expected close: transport, STREAM_STATE_ERROR (0x05).

use h3i::actions::h3::Action;
use h3i::actions::h3::WaitType;
use h3i::client::sync_client;
use h3i_scenarios::loopback_config;
use std::time::Duration;

const STREAM_STATE_ERROR: u64 = 0x05;
const SERVER_CONTROL_STREAM_ID: u64 = 3;
const EXPECTED_REASON_SUBSTRING: &str = "[QUIC-RESET-SEND-ONLY]";

fn main() {
    let config = loopback_config(4433);
    let actions = vec![
        Action::Wait {
            wait_type: WaitType::WaitDuration(Duration::from_millis(100)),
        },
        Action::ResetStream {
            stream_id: SERVER_CONTROL_STREAM_ID,
            error_code: 0,
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f15: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if !err.is_app && err.error_code == STREAM_STATE_ERROR => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f15: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f15: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f15: FAIL got code=0x{:x} is_app={}, expected STREAM_STATE_ERROR (0x05) transport",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f15: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
