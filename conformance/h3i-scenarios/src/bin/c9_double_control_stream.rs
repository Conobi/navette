//! Conformance scenario C9 / RFC 9114 §6.2.1:
//! "Only one control stream per peer is permitted; receipt of a second one
//!  MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR."
//!
//! h3i does NOT auto-open the client control stream — actions must do it
//! explicitly. This scenario opens TWO client-initiated unidirectional
//! streams (stream IDs 2 and 6), both with type byte 0x00 (control), and
//! asserts navette closes the connection with H3_STREAM_CREATION_ERROR
//! (0x0103) on receipt of the second one AND that the close reason names the
//! control-stream guard (so a future refactor that misroutes type-byte 0x00
//! to the qpack-encoder branch fails this scenario instead of silently
//! passing — all three duplicate-uni-stream guards share error code 0x0103).
//!
//! Exits 0 if navette sends the expected error with a control-stream reason;
//! 1 otherwise (no close, wrong error code, wrong reason, peer timeout, etc.).
//!
//! Once the two OpenUniStream actions have been emitted, the scenario does
//! NOT block on a fixed WaitDuration. h3i's sync_client main loop exits
//! naturally as soon as the peer sends CONNECTION_CLOSE (via
//! `conn.is_closed()`), and the 2 s idle timeout from `loopback_config`
//! caps the no-close case. Eliminating the prior 1 s WaitDuration race
//! prevents false FAILs on slow CI hosts.
//!
//! Note: h3i's `CloseTriggerFrames` mechanism watches for incoming H3
//! application frames (HEADERS / DATA / RESET_STREAM) — it does NOT match
//! raw QUIC CONNECTION_CLOSE frames — so it is not the right primitive for
//! "exit as soon as the peer closes". The natural `conn.is_closed()` exit
//! in `sync_client::connect`'s main loop is.
//!
//! Derived from `research/h3spec-failure-triage.md` cluster C9, F32.

use h3i::actions::h3::Action;
use h3i::client::sync_client;
use h3i_scenarios::loopback_config;

/// RFC 9114 §8.1: H3_STREAM_CREATION_ERROR (0x0103).
const H3_STREAM_CREATION_ERROR: u64 = 0x0103;

/// Client-initiated unidirectional stream IDs are 2, 6, 10, ... (RFC 9000 §2.1).
const FIRST_CONTROL_STREAM_ID: u64 = 2;
const SECOND_CONTROL_STREAM_ID: u64 = 6;

/// HTTP/3 control-stream type (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;

/// Substring that must appear in the CONNECTION_CLOSE reason emitted by
/// navette's control-stream duplicate guard (see `_close_duplicate_uni_stream`
/// in `navette/h3/connection.mojo`, called with label `"control"` → reason
/// `"duplicate control stream"`). Uniquely identifies the control branch
/// versus the qpack-encoder / qpack-decoder branches, which share the same
/// error code 0x0103.
const EXPECTED_REASON_SUBSTRING: &str = "control stream";

fn main() {
    let config = loopback_config(4433);

    let actions = vec![
        Action::OpenUniStream {
            stream_id: FIRST_CONTROL_STREAM_ID,
            fin_stream: false,
            stream_type: STREAM_TYPE_CONTROL,
        },
        Action::OpenUniStream {
            stream_id: SECOND_CONTROL_STREAM_ID,
            fin_stream: false,
            stream_type: STREAM_TYPE_CONTROL,
        },
    ];

    let summary = match sync_client::connect(config, actions, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("c9_double_control_stream: connect failed: {e:?}");
            std::process::exit(1);
        }
    };

    // navette MUST close the connection. Inspect `conn_close_details.peer_error`.
    // `reason` is a `Vec<u8>` (see `quiche::ConnectionError`); decode lossily
    // since navette's reason strings are ASCII.
    match summary.conn_close_details.peer_error() {
        Some(err) if err.is_app && err.error_code == H3_STREAM_CREATION_ERROR => {
            let reason = String::from_utf8_lossy(&err.reason);
            if reason.contains(EXPECTED_REASON_SUBSTRING) {
                println!(
                    "c9_double_control_stream: PASS (peer closed with H3_STREAM_CREATION_ERROR 0x{:x}, reason={:?})",
                    err.error_code, reason
                );
                std::process::exit(0);
            }
            eprintln!(
                "c9_double_control_stream: FAIL (peer closed with H3_STREAM_CREATION_ERROR 0x{:x} but reason {:?} does not contain {:?} — guard may be misrouted to the qpack-encoder/decoder branch)",
                err.error_code, reason, EXPECTED_REASON_SUBSTRING
            );
            std::process::exit(1);
        }
        Some(err) => {
            eprintln!(
                "c9_double_control_stream: FAIL (peer closed with code 0x{:x} is_app={}, expected H3_STREAM_CREATION_ERROR 0x{:x})",
                err.error_code, err.is_app, H3_STREAM_CREATION_ERROR
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("c9_double_control_stream: FAIL (no peer connection close — navette did not detect the second control stream)");
            std::process::exit(1);
        }
    }
}
