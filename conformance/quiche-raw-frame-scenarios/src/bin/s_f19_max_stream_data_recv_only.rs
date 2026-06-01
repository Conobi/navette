//! s_f19_max_stream_data_recv_only — F19.
//!
//! Opens a client-initiated unidirectional stream (id 2, suffix `0b10`)
//! and sends a `MAX_STREAM_DATA` frame targeting it. Client-uni streams
//! are recv-only from the server's perspective; per RFC 9000 §19.10,
//! receiving a `MAX_STREAM_DATA` for a non-send-side stream MUST close
//! the connection with `STREAM_STATE_ERROR`.
//!
//! Expected: transport-CC, code = `STREAM_STATE_ERROR (0x05)`, reason
//! contains `[QUIC-MAX-STREAM-DATA-RECV-ONLY]`.
//!
//! # Setup observability
//!
//! The harness has no introspection into navette's `stream_map`. To
//! confirm the server has processed the initial STREAM frame for id 2
//! (so the stream is registered), we poll UDP traffic with three exits:
//!
//! 1. **Server-emitted frame for stream 2** — strong signal.
//! 2. **250 ms quiet-period heuristic** — no packet from the server for
//!    250 ms after the last received one (loopback latency is sub-ms;
//!    250 ms of silence implies steady state).
//! 3. **500 ms hard cap from initial `stream_send`** — treated as a
//!    setup failure, exit code 2 (distinct from guard-assertion exit 1).
//!
//! # Exit codes
//!
//! * 0 — guard fired with the expected code + tag.
//! * 1 — guard fired with the wrong code/tag, no close, or any I/O error.
//! * 2 — setup failure (hard-cap timeout reached without observable
//!       signal that the server processed the stream).

use std::env;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use quiche::frame::Frame;
use quiche::{Connection, RecvInfo};
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS, MAX_DATAGRAM_SIZE,
};

const FAILURE_ID: &str = "F19";
const GUARD_TAG: &str = "[QUIC-MAX-STREAM-DATA-RECV-ONLY]";
const EXPECTED_CODE: u64 = 0x05; // STREAM_STATE_ERROR
const SETUP_FAIL_EXIT: u8 = 2;

/// Client-uni stream id 2: bits `(id & 3) == 2` per RFC 9000 §2.1.
const STREAM_ID_CLIENT_UNI: u64 = 2;

/// 250 ms of silence after the last server packet — heuristic for
/// "server has finished processing".
const QUIET_PERIOD_MS: u64 = 250;

/// Hard cap from the initial `stream_send` call — setup failure budget.
const HARD_CAP_MS: u64 = 500;

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    let panic_result = std::panic::catch_unwind(|| navette_connect(port));
    let (mut conn, socket, server) = match panic_result {
        Ok(triple) => triple,
        Err(_) => {
            eprintln!("FAIL {FAILURE_ID}: handshake did not establish");
            return ExitCode::from(1);
        }
    };

    // Open client-uni stream 2 by sending one byte; quiche will emit a STREAM
    // frame which navette processes via `get_or_create_peer_stream`.
    if let Err(e) = conn.stream_send(STREAM_ID_CLIENT_UNI, b"x", false) {
        eprintln!("FAIL {FAILURE_ID}: stream_send failed: {e:?}");
        return ExitCode::from(1);
    }
    // Flush the STREAM frame out so the server can see it.
    if let Err(e) = drain_outgoing(&mut conn, &socket) {
        eprintln!("FAIL {FAILURE_ID}: drain after stream_send failed: {e}");
        return ExitCode::from(1);
    }

    // Wait for an observable signal that the server has processed the STREAM
    // frame (250 ms quiet period after a server packet) or hit the 500 ms
    // hard cap (setup failure).
    if !wait_for_server_quiet(&mut conn, &socket, server) {
        eprintln!(
            "FAIL {FAILURE_ID}: server did not reach steady state within {HARD_CAP_MS} ms; \
             marking as setup failure",
        );
        return ExitCode::from(SETUP_FAIL_EXIT);
    }

    // Inject the offending MAX_STREAM_DATA against the recv-only stream.
    let frame = Frame::MaxStreamData {
        stream_id: STREAM_ID_CLIENT_UNI,
        max: 0x10000,
    };
    if let Err(e) = send_raw_1rtt(&mut conn, &socket, server, std::slice::from_ref(&frame)) {
        eprintln!("FAIL {FAILURE_ID}: send_raw_1rtt failed: {e}");
        return ExitCode::from(1);
    }

    let outcome = wait_connection_close(&mut conn, &socket, server, CLOSE_DEADLINE_MS);
    if assert_close(outcome, EXPECTED_CODE, GUARD_TAG, FAILURE_ID) {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

/// Drain quiche's outgoing queue once.
///
/// Loops `conn.send` until `Done`. Mirrors the helper in the shared lib
/// but lives here so we can keep the lib API minimal.
fn drain_outgoing(conn: &mut Connection, socket: &UdpSocket) -> io::Result<()> {
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                socket.send_to(&out[..written], send_info.to)?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(io::Error::other(format!("conn.send: {e:?}"))),
        }
    }
}

/// Poll the server until 250 ms of silence pass, or the 500 ms hard cap
/// is reached. Returns `true` on quiet-period success, `false` on hard
/// cap.
fn wait_for_server_quiet(
    conn: &mut Connection,
    socket: &UdpSocket,
    server: SocketAddr,
) -> bool {
    let local = socket.local_addr().expect("local_addr");
    let mut buf = [0u8; 65_535];
    let start = Instant::now();
    let mut last_recv = Instant::now();
    let mut received_any = false;

    while start.elapsed() < Duration::from_millis(HARD_CAP_MS) {
        if received_any && last_recv.elapsed() >= Duration::from_millis(QUIET_PERIOD_MS) {
            return true;
        }
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                last_recv = Instant::now();
                received_any = true;
                let info = RecvInfo { to: local, from };
                let _ = conn.recv(&mut buf[..len], info);
                let _ = drain_outgoing(conn, socket);
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
                let _ = drain_outgoing(conn, socket);
            }
            Err(_) => return false,
        }
        let _ = server;
    }
    // Hard cap reached. If we never received a server packet, the server is
    // either dead-silent (no PING/ACK) or the STREAM never got through —
    // treat as setup failure.
    received_any && last_recv.elapsed() >= Duration::from_millis(QUIET_PERIOD_MS)
}
