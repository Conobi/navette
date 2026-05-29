//! F36 — RFC 9114 §7.2.3 (cluster C8).
//! CANCEL_PUSH on a request stream MUST be H3_FRAME_UNEXPECTED
//! (CANCEL_PUSH is control-stream-only).
//!
//! GUARD-TAG: [H3-CANCEL-PUSH-REQ]
//! Expected close: application, H3_FRAME_UNEXPECTED (0x0103).

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i::quiche::h3::frame::Frame;
use h3i::quiche::h3::Header;
use h3i_scenarios::loopback_config;

const H3_FRAME_UNEXPECTED: u64 = 0x0103;
const REQUEST_STREAM_ID: u64 = 0;
const EXPECTED_REASON_SUBSTRING: &str = "[H3-CANCEL-PUSH-REQ]";

fn main() {
    let config = loopback_config(4433);
    let actions = vec![
        send_headers_frame(
            REQUEST_STREAM_ID,
            false,
            vec![
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"localhost"),
                Header::new(b":path", b"/"),
            ],
        ),
        Action::SendFrame {
            stream_id: REQUEST_STREAM_ID,
            fin_stream: false,
            frame: Frame::CancelPush { push_id: 0 },
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("s_f36: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    match summary.conn_close_details.peer_error() {
        Some(err) if err.is_app && err.error_code == H3_FRAME_UNEXPECTED => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "s_f36: PASS code=0x{:x} reason={:?}",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "s_f36: FAIL code OK (0x{:x}) but reason {:?} missing {:?}",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "s_f36: FAIL got code=0x{:x} is_app={}, expected H3_FRAME_UNEXPECTED (0x0103) app",
                err.error_code, err.is_app
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("s_f36: FAIL no peer close");
            std::process::exit(1);
        }
    }
}
