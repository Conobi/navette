//! s_zero_rtt_http_post_rejected — R04.
//!
//! Phase 1: fresh handshake against navette's hello_h3_server
//! (`HELLO_H3_MAX_EARLY_DATA=max` env) -> capture SessionTicket.
//!
//! Phase 2: resumed handshake with a 0-RTT-bearing POST /echo
//! request carrying a small body. Navette's IdempotentOnly filter
//! MUST reject the POST with 425 Too Early per RFC 8470 §5.2; the
//! handler MUST NOT be invoked.
//!
//! Together with R03 (GET -> 200), this pair verifies the RFC 8470
//! §5.2 filter behaviour end-to-end.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::resumption::{
    drive_to_session_ticket, drive_to_zero_rtt_with_h3_request,
};
use quiche_raw_frame_scenarios::server_addr_with_port;

const FAILURE_ID: &str = "R04";

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    let server = server_addr_with_port(port);

    // ---- Phase 1: fresh handshake -> SessionTicket. ----
    let ticket = match drive_to_session_ticket(server) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 1 (ticket capture) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 1: captured ticket ({} bytes)", ticket.len());

    // ---- Phase 2: resumed handshake with 0-RTT POST. ----
    let body: &[u8] = b"hello-zero-rtt-post";
    let (resumed, status) = match drive_to_zero_rtt_with_h3_request(
        server,
        &ticket,
        "POST",
        "/echo",
        Some(body),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 2 (0-RTT POST) failed: {e}");
            return ExitCode::from(1);
        }
    };
    drop(resumed);

    if status != 425 {
        eprintln!(
            "FAIL {FAILURE_ID}: expected status 425 (filter reject), got {status}"
        );
        return ExitCode::from(1);
    }

    eprintln!(
        "{FAILURE_ID}: PASS — 0-RTT POST /echo returned 425 \
         (IdempotentOnly filter rejected; handler skipped)"
    );
    ExitCode::from(0)
}
