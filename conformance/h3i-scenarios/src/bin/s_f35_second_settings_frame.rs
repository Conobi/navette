//! F35 — RFC 9114 §7.2.4 (cluster C9).
//! A SECOND SETTINGS frame on the control stream MUST be H3_FRAME_UNEXPECTED.
//!
//! GUARD-TAG: [H3-SECOND-SETTINGS]
//! Expected close: application, H3_FRAME_UNEXPECTED (0x0103).

use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i::quiche::h3::frame::Frame;
use h3i_scenarios::loopback_config;

const H3_FRAME_UNEXPECTED: u64 = 0x0103;
const CLIENT_CONTROL_STREAM_ID: u64 = 2;
const STREAM_TYPE_CONTROL: u64 = 0x00;
const EXPECTED_REASON_SUBSTRING: &str = "[H3-SECOND-SETTINGS]";

fn settings_with(blocked: u64) -> Frame {
    Frame::Settings {
        max_field_section_size: None,
        qpack_max_table_capacity: Some(0),
        qpack_blocked_streams: Some(blocked),
        connect_protocol_enabled: None,
        h3_datagram: None,
        grease: None,
        additional_settings: None,
        raw: Default::default(),
    }
}

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
            frame: settings_with(0),
        },
        Action::SendFrame {
            stream_id: CLIENT_CONTROL_STREAM_ID,
            fin_stream: false,
            frame: settings_with(1),
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f35: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if err.is_app && err.error_code == H3_FRAME_UNEXPECTED => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f35: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f35: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f35: FAIL got code=0x{:x} is_app={}, expected H3_FRAME_UNEXPECTED (0x0103) app",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f35: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
