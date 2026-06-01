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
//! No introspection into navette's `stream_map` is needed: we rely on
//! UDP send order being preserved end-to-end on loopback. After
//! `drain_outgoing` flushes the opening STREAM frame, we immediately
//! emit the raw `MAX_STREAM_DATA` packet. The kernel delivers them to
//! the server in send order; the server's io_uring h3 handler is
//! single-threaded, so the STREAM is registered before the
//! MAX_STREAM_DATA arrives and the guard fires deterministically.
//!
//! # Exit codes
//!
//! * 0 — guard fired with the expected code + tag.
//! * 1 — guard fired with the wrong code/tag, no close, or any I/O error.

use std::env;
use std::io;
use std::net::UdpSocket;
use std::process::ExitCode;

use quiche::frame::Frame;
use quiche::Connection;
use quiche_raw_frame_scenarios::{
    assert_close, navette_connect, send_raw_1rtt, wait_connection_close,
    CLOSE_DEADLINE_MS, MAX_DATAGRAM_SIZE,
};

const FAILURE_ID: &str = "F19";
const GUARD_TAG: &str = "[QUIC-MAX-STREAM-DATA-RECV-ONLY]";
const EXPECTED_CODE: u64 = 0x05; // STREAM_STATE_ERROR

/// Client-uni stream id 2: bits `(id & 3) == 2` per RFC 9000 §2.1.
const STREAM_ID_CLIENT_UNI: u64 = 2;

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

    // UDP loopback preserves send order; the server's io_uring h3
    // handler is single-threaded. Send the MAX_STREAM_DATA immediately
    // — the server processes the opening STREAM frame first (registers
    // stream 2 as recv-only), then the MAX_STREAM_DATA (which closes
    // the connection with STREAM_STATE_ERROR).
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
