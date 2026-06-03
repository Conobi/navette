//! s_zero_rtt_fresh_resumption — R02.
//!
//! Companion to R01. Guards against over-rejection by the anti-replay
//! path: two LEGITIMATE resumptions, each against a freshly-issued
//! ticket with a freshly-generated quiche client_random, MUST both be
//! accepted.
//!
//! Requires HELLO_H3_ENABLE_EARLY_DATA=1 on the navette server (the
//! QRF runner exports this automatically).
//!
//! Phase ordering:
//!   * Phase 1A — fresh handshake → SessionTicket T1.
//!   * Phase 2  — resume against T1 (consumes T1 from server cache),
//!                expect successful H3 response.
//!   * Phase 1B — fresh handshake → SessionTicket T2.
//!   * Phase 3  — resume against T2, expect successful H3 response.
//!
//! Phase 2 immediately follows 1A and Phase 3 immediately follows 1B so
//! neither ticket churns out of ServerSessionMemoryCache (256-entry
//! default) between issuance and consumption.
//!
//! Expected: both resumptions complete a handshake AND receive at
//! least one server datagram. Each fresh handshake naturally issues a
//! distinct session ticket (different random bytes per ticket) AND
//! quiche generates a fresh ClientHello.random per `connect()`, so the
//! two authenticators differ and both pass the anti-replay check.
//! Either property is independently sufficient to distinguish T1's
//! resumption from T2's; both being present is belt-and-braces.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::resumption::{drive_to_session_ticket, drive_to_zero_rtt_seal};
use quiche_raw_frame_scenarios::server_addr_with_port;

const FAILURE_ID: &str = "R02";

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    let server = server_addr_with_port(port);

    // ---- Phase 1A: fresh handshake → T1. ----
    let t1 = match drive_to_session_ticket(server) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 1A (T1 capture) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 1A: captured T1 ({} bytes)", t1.len());

    // ---- Phase 2: resume against T1; assert acceptance. ----
    let resumed1 = match drive_to_zero_rtt_seal(server, &t1) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 2 (resume T1) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 2: resumed against T1, 0-RTT seal installed");
    drop(resumed1);

    // ---- Phase 1B: fresh handshake → T2. ----
    let t2 = match drive_to_session_ticket(server) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 1B (T2 capture) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 1B: captured T2 ({} bytes)", t2.len());

    if t1 == t2 {
        eprintln!(
            "FAIL {FAILURE_ID}: T1 and T2 are byte-identical — \
             expected distinct ticket blobs"
        );
        return ExitCode::from(1);
    }

    // ---- Phase 3: resume against T2; assert acceptance. ----
    let resumed2 = match drive_to_zero_rtt_seal(server, &t2) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 3 (resume T2) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 3: resumed against T2, 0-RTT seal installed");
    drop(resumed2);

    eprintln!(
        "{FAILURE_ID}: PASS — two distinct resumptions across distinct tickets \
         both accepted (anti-replay does not over-reject legitimate clients)"
    );
    ExitCode::from(0)
}
