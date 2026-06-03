//! s_f30_crypto_in_zero_rtt — F30.
//!
//! Per RFC 9001 §8.3, CRYPTO frames MUST NOT be sent in 0-RTT (early-data)
//! packets — the only frames permitted in 0-RTT are those that carry
//! application data (STREAM, RESET_STREAM, STOP_SENDING, etc.). A receiver
//! that observes a CRYPTO frame inside a 0-RTT packet MUST close the
//! connection with PROTOCOL_VIOLATION (0x0a).
//!
//! Requires the navette server to run with HELLO_H3_ENABLE_EARLY_DATA=1
//! (the QRF runner sets this automatically).
//!
//! Driver shape:
//!   * Phase 1 — connect, complete a full handshake against
//!     `hello_h3_server`, and capture the server-issued NewSessionTicket
//!     via `resumption::drive_to_session_ticket`.
//!   * Phase 2 — reconnect with the cached ticket and drive until the
//!     resumed client's Application crypto_seal is installed, via
//!     `resumption::drive_to_zero_rtt_seal`. At that point quiche's
//!     `Type::ZeroRTT` epoch is encrypt-ready.
//!   * Phase 3 — encode a 0-RTT packet whose payload is a single CRYPTO
//!     frame (RFC 9000 §19.6: type 0x06, offset varint, length varint,
//!     opaque data) via the vendored `encode_pkt_with_payload` patch,
//!     send it to navette, and wait for CONNECTION_CLOSE.
//!
//! Expected: transport-CC, code = `PROTOCOL_VIOLATION (0x0a)`, reason
//! contains `[QUIC-CRYPTO-IN-0RTT]`.

use std::env;
use std::process::ExitCode;

use quiche_raw_frame_scenarios::{
    assert_close, server_addr_with_port, wait_connection_close, CLOSE_DEADLINE_MS,
    MAX_DATAGRAM_SIZE,
};
use quiche_raw_frame_scenarios::resumption::{drive_to_session_ticket, drive_to_zero_rtt_seal};

const FAILURE_ID: &str = "F30";
const GUARD_TAG: &str = "[QUIC-CRYPTO-IN-0RTT]";
const EXPECTED_CODE: u64 = 0x0a; // PROTOCOL_VIOLATION

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);
    let server = server_addr_with_port(port);

    // === Phase 1: handshake + session ticket capture. ===
    let ticket = match drive_to_session_ticket(server) {
        Ok(blob) => blob,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 1 (ticket capture) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "{FAILURE_ID} phase 1: captured session ticket ({} bytes)",
        ticket.len(),
    );

    // === Phase 2: resumed handshake → Application crypto_seal ready. ===
    let mut resumed = match drive_to_zero_rtt_seal(server, &ticket) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("FAIL {FAILURE_ID}: phase 2 (0-RTT seal drive) failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("{FAILURE_ID} phase 2: 0-RTT seal installed");

    // === Phase 3: encode + inject a 0-RTT packet carrying a CRYPTO frame. ===
    let payload = build_crypto_frame_payload();

    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = match quiche::test_utils::encode_pkt_with_payload(
        &mut resumed.conn,
        quiche::Type::ZeroRTT,
        &payload,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(e) => {
            eprintln!(
                "FAIL {FAILURE_ID}: encode_pkt_with_payload(ZeroRTT) failed: {e:?}",
            );
            return ExitCode::from(1);
        }
    };
    if let Err(e) = resumed.socket.send_to(&buf[..written], resumed.server_addr) {
        eprintln!("FAIL {FAILURE_ID}: send_to failed: {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "{FAILURE_ID} phase 3: injected 0-RTT CRYPTO packet ({written} bytes)",
    );

    // === Wait for navette's PROTOCOL_VIOLATION + [QUIC-CRYPTO-IN-0RTT]. ===
    let outcome = wait_connection_close(
        &mut resumed.conn,
        &resumed.socket,
        resumed.server_addr,
        CLOSE_DEADLINE_MS,
    );

    if assert_close(outcome, EXPECTED_CODE, GUARD_TAG, FAILURE_ID) {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

/// Build the payload of a single QUIC CRYPTO frame (RFC 9000 §19.6).
///
/// Frame format:
///   * Type   — 0x06 (varint, single byte).
///   * Offset — varint; we use 0 (single-byte varint).
///   * Length — varint; we use 8 (single-byte varint).
///   * Data   — `length` opaque bytes.
///
/// The contents of `Data` are immaterial: the F30 guard fires on the
/// CRYPTO frame TYPE byte appearing inside a 0-RTT packet, before any
/// TLS-stack handoff. Eight zero bytes keep the packet within the
/// minimum datagram size while satisfying length parsers.
fn build_crypto_frame_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(3 + 8);
    payload.push(0x06); // frame type — CRYPTO
    payload.push(0x00); // offset = 0 (single-byte varint)
    payload.push(0x08); // length = 8 (single-byte varint)
    payload.extend_from_slice(&[0u8; 8]);
    payload
}
