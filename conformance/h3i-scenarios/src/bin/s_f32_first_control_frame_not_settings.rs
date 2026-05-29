//! F32 — RFC 9114 §6.2.1 (cluster C9).
//! First frame on a client control stream MUST be SETTINGS. Sending GOAWAY
//! first MUST trip H3_MISSING_SETTINGS.
//!
//! GUARD-TAG: [H3-CTRL-NO-SETTINGS]
//! Expected close: application, H3_MISSING_SETTINGS (0x010A).

use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i::quiche::h3::frame::Frame;
use h3i_scenarios::loopback_config;

const H3_MISSING_SETTINGS: u64 = 0x010A;
const CLIENT_CONTROL_STREAM_ID: u64 = 2;
const STREAM_TYPE_CONTROL: u64 = 0x00;
const EXPECTED_REASON_SUBSTRING: &str = "[H3-CTRL-NO-SETTINGS]";

fn main() {
    let config = loopback_config(4433);
    let actions = vec![
        Action::OpenUniStream {
            stream_id: CLIENT_CONTROL_STREAM_ID,
            fin_stream: false,
            stream_type: STREAM_TYPE_CONTROL,
        },
        Action::SendFrame {
            stream_id: CLIENT_CONTROL_STREAM_ID,
            fin_stream: false,
            frame: Frame::GoAway { id: 0 },
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f32: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if err.is_app && err.error_code == H3_MISSING_SETTINGS => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f32: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f32: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f32: FAIL got code=0x{:x} is_app={}, expected H3_MISSING_SETTINGS (0x010A) app",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f32: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
