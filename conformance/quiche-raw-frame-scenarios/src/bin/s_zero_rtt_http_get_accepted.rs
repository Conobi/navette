//! s_zero_rtt_http_get_accepted — R03.
//!
//! Phase 1: fresh handshake against navette's hello_h3_server
//! (`HELLO_H3_ENABLE_EARLY_DATA=1` env) -> capture SessionTicket.
//!
//! Phase 2: resumed handshake with a 0-RTT-bearing GET / request.
//! Navette's IdempotentOnly filter MUST accept the GET; the response
//! status code MUST be 200, with `Early-Data: 1` visible to the
//! handler.
//!
//! Together with R04 (POST -> 425), this pair verifies the RFC 8470
//! §5.2 filter behaviour end-to-end through navette's three H3
//! adapter sites + the QUIC-layer is_zero_rtt tagging.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::resumption::{
    drive_to_session_ticket, drive_to_zero_rtt_with_h3_request,
};
use quiche_raw_frame_scenarios::server_addr_with_port;

const FAILURE_ID: &str = "R03";

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

    // ---- Phase 2: resumed handshake with 0-RTT GET. ----
    let (resumed, status) =
        match drive_to_zero_rtt_with_h3_request(server, &ticket, "GET", "/", None) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("FAIL {FAILURE_ID}: phase 2 (0-RTT GET) failed: {e}");
                return ExitCode::from(1);
            }
        };
    drop(resumed);

    if status != 200 {
        eprintln!(
            "FAIL {FAILURE_ID}: expected status 200 (filter accept), got {status}"
        );
        return ExitCode::from(1);
    }

    eprintln!(
        "{FAILURE_ID}: PASS — 0-RTT GET / returned 200 \
         (IdempotentOnly filter accepted; handler dispatched)"
    );
    ExitCode::from(0)
}
