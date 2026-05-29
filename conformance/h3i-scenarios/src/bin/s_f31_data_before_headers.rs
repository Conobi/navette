//! F31 — RFC 9114 §4.1 (cluster C8).
//! DATA frame before HEADERS on a request stream MUST be H3_FRAME_UNEXPECTED.
//!
//! GUARD-TAG: [H3-DATA-BEFORE-HEADERS]
//! Expected close: application, H3_FRAME_UNEXPECTED (0x0103).

use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i::quiche::h3::frame::Frame;
use h3i_scenarios::loopback_config;

const H3_FRAME_UNEXPECTED: u64 = 0x0103;
const REQUEST_STREAM_ID: u64 = 0;
const EXPECTED_REASON_SUBSTRING: &str = "[H3-DATA-BEFORE-HEADERS]";

fn main() {
    let config = loopback_config(4433);
    let actions = vec![Action::SendFrame {
        stream_id: REQUEST_STREAM_ID,
        fin_stream: false,
        frame: Frame::Data {
            payload: b"oops".to_vec(),
        },
    }];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f31: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if err.is_app && err.error_code == H3_FRAME_UNEXPECTED => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f31: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f31: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f31: FAIL got code=0x{:x} is_app={}, expected H3_FRAME_UNEXPECTED (0x0103) app",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f31: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
