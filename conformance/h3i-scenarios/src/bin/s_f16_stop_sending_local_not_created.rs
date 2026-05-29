//! F16 — RFC 9000 §19.5 (cluster C4).
//! STOP_SENDING for a locally-initiated stream that has not yet been created
//! MUST be STREAM_STATE_ERROR. Stream id 999 (suffix 0b11 = server-uni) sits
//! beyond the reachable `local_opened_uni*4+3` range, so navette has not
//! created it. If `peer_max_streams_uni` ever climbs past ~248, this id
//! becomes reachable and the scenario must be re-pinned.
//!
//! GUARD-TAG: [QUIC-STOP-LOCAL-NOT-CREATED]
//! Expected close: transport, STREAM_STATE_ERROR (0x05).

use h3i::actions::h3::Action;
use h3i::actions::h3::WaitType;
use h3i::client::sync_client;
use h3i_scenarios::loopback_config;
use std::time::Duration;

const STREAM_STATE_ERROR: u64 = 0x05;
const UNCREATED_SERVER_UNI: u64 = 999;
const EXPECTED_REASON_SUBSTRING: &str = "[QUIC-STOP-LOCAL-NOT-CREATED]";

fn main() {
    let config = loopback_config(4433);
    let actions = vec![
        Action::Wait {
            wait_type: WaitType::WaitDuration(Duration::from_millis(100)),
        },
        Action::StopSending {
            stream_id: UNCREATED_SERVER_UNI,
            error_code: 0,
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f16: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if !err.is_app && err.error_code == STREAM_STATE_ERROR => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f16: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f16: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f16: FAIL got code=0x{:x} is_app={}, expected STREAM_STATE_ERROR (0x05) transport",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f16: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
