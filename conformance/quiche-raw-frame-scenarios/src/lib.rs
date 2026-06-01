//! Shared helpers for the quiche-raw-frame scenario binaries.
//!
//! Each scenario completes a normal QUIC + H3 handshake against a running
//! navette `hello_h3_server`, then injects one (or more) adversarial QUIC
//! frames via the vendored `quiche::test_utils::encode_pkt` path, and
//! asserts that navette emits CONNECTION_CLOSE with the expected error
//! code and `[QUIC-...]` GUARD-TAG substring in the reason phrase.
//!
//! The handshake is driven through the public `quiche::Connection` API
//! (recv/send/timeout); raw injection happens via the vendor-patched
//! `encode_pkt` / `encode_pkt_reserved_bits` helpers, which share the
//! live connection crypto context.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use quiche::{Connection, ConnectionId, RecvInfo};
use ring::rand::{SecureRandom, SystemRandom};

/// Maximum UDP datagram size accepted on both directions.
///
/// Matches the example client in the vendored quiche tree; large enough for
/// any short-conn test reply navette emits in these scenarios.
pub const MAX_DATAGRAM_SIZE: usize = 1350;

/// Default handshake-completion deadline, in milliseconds.
///
/// Local-loopback navette typically completes the QUIC + H3 handshake within
/// 5–10 ms; 2000 ms leaves headroom for cold-start, GC, and noisy hosts.
pub const HANDSHAKE_DEADLINE_MS: u64 = 2_000;

/// Default `wait_connection_close` poll deadline, in milliseconds.
pub const CLOSE_DEADLINE_MS: u64 = 2_000;

/// Returns the navette server's UDP address.
///
/// Reads `QRF_SERVER_PORT` from the environment; defaults to 4433 (matches
/// the `hello_h3_server` example default). Address is always 127.0.0.1.
pub fn server_addr_with_port(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Build the quiche client `Config` used by every scenario.
///
/// * `verify_peer(false)` — the navette server uses a self-signed cert.
/// * ALPN `["h3"]` — required to negotiate HTTP/3 on the established
///   connection.
/// * `set_disable_active_migration(true)` — pin to the bound socket.
/// * Stream / connection windows are generous so the handshake never
///   blocks on flow control.
///
/// The config is intentionally minimal; scenarios that need additional
/// settings (e.g. early_data for a future 0-RTT row) can layer on top of
/// the returned `Config`.
fn build_client_config() -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .expect("quiche::Config::new");

    config.verify_peer(false);
    config
        .set_application_protos(&[b"h3"])
        .expect("set_application_protos h3");

    config.set_max_idle_timeout(5_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config
}

/// Establish a QUIC connection to the navette `hello_h3_server` on `port`.
///
/// Drives the handshake to completion (or `HANDSHAKE_DEADLINE_MS` ms,
/// whichever comes first) via the standard quiche send/recv loop. Returns
/// the live `Connection`, the bound UDP socket, and the server's
/// `SocketAddr` for follow-up raw injection.
///
/// # Panics
///
/// Panics if the UDP socket cannot be bound, the QUIC handshake fails to
/// progress, or the deadline elapses without `is_established()`. Scenarios
/// surface those failures as exit code 1 (assertion-style), not as
/// in-process panics from a flaky network setup.
pub fn navette_connect(port: u16) -> (Connection, UdpSocket, SocketAddr) {
    let server = server_addr_with_port(port);

    // Bind an ephemeral UDP port on loopback, set a short read timeout so
    // the recv loop stays responsive.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    socket
        .set_read_timeout(Some(Duration::from_millis(25)))
        .expect("set_read_timeout");

    let local = socket.local_addr().expect("local_addr");

    // Random 16-byte source connection ID (matches quiche example client).
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new()
        .fill(&mut scid_bytes[..])
        .expect("random scid");
    let scid = ConnectionId::from_ref(&scid_bytes);

    let mut config = build_client_config();
    let mut conn = quiche::connect(Some("localhost"), &scid, local, server, &mut config)
        .expect("quiche::connect");

    let deadline = Instant::now() + Duration::from_millis(HANDSHAKE_DEADLINE_MS);

    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut buf = [0u8; 65_535];

    // === Send loop: flush any pending Initial packets. ===
    flush_send(&mut conn, &socket, &mut out);

    // === Drive handshake to is_established() OR deadline. ===
    while !conn.is_established() && Instant::now() < deadline {
        // Wait for an incoming datagram (with the socket's short timeout).
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = RecvInfo { to: local, from };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    panic!("navette_connect: conn.recv failed: {e:?}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut => {
                // Timer tick — drive on_timeout so loss detection fires.
                conn.on_timeout();
            }
            Err(e) => panic!("navette_connect: recv_from failed: {e:?}"),
        }
        flush_send(&mut conn, &socket, &mut out);
    }

    if !conn.is_established() {
        panic!(
            "navette_connect: handshake did not complete within {} ms",
            HANDSHAKE_DEADLINE_MS,
        );
    }

    (conn, socket, server)
}

/// Drive a navette handshake until the client's Handshake-epoch encrypt
/// keys are LIVE but BEFORE the client's Finished is sent (so quiche has
/// not yet retired the keys per RFC 9001 §4.9.1).
///
/// Detection mechanism: probe `quiche::test_utils::encode_pkt` with
/// `Type::Handshake` and an empty frame slice, wrapped in
/// `panic::catch_unwind`. The vendored `encode_pkt` for long-header types
/// calls `crypto_ctx.crypto_overhead().unwrap()` BEFORE checking
/// `crypto_seal` for `None`, so a missing seal surfaces as a panic
/// (`Option::unwrap() on None`) rather than `Err(InvalidState)`. Once
/// `crypto_seal` is `Some`, `crypto_overhead` returns `Some(tag_len)`,
/// the seal check passes, and the probe returns `Ok(_)`. We probe AFTER
/// each `conn.recv()` round and BEFORE the next `flush_send()` — the
/// latter would send the client's Finished and trigger `HANDSHAKE_DONE`
/// on the server, retiring the keys.
///
/// Per RFC 9001 §4.9.1, the client retires its Handshake-epoch keys on
/// `HANDSHAKE_DONE`. We return BEFORE that point.
///
/// # Probe side-effects
///
/// On success, `encode_pkt` increments `conn.next_pkt_num`. On the
/// missing-seal panic path the increment lives below the panic site, so
/// PN state is unchanged. Either way the probe encodes into a stack
/// buffer that is then discarded — the bytes never reach the wire.
/// Quiche tolerates gaps in the send-side packet-number space, so the
/// natural client Finished (or the scenario's own raw-injection
/// `encode_pkt_reserved_bits` call) simply uses the next PN.
///
/// # Panics
///
/// Same conditions as [`navette_connect`] (socket bind / handshake
/// deadline). If `HANDSHAKE_DEADLINE_MS` elapses before Handshake-epoch
/// encrypt keys materialise, panics with the same message shape.
pub fn navette_connect_until_handshake_keys(
    port: u16,
) -> (Connection, UdpSocket, SocketAddr) {
    let server = server_addr_with_port(port);

    // Bind an ephemeral UDP port on loopback, set a short read timeout so
    // the recv loop stays responsive.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    socket
        .set_read_timeout(Some(Duration::from_millis(25)))
        .expect("set_read_timeout");

    let local = socket.local_addr().expect("local_addr");

    // Random 16-byte source connection ID (matches quiche example client).
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new()
        .fill(&mut scid_bytes[..])
        .expect("random scid");
    let scid = ConnectionId::from_ref(&scid_bytes);

    let mut config = build_client_config();
    let mut conn = quiche::connect(Some("localhost"), &scid, local, server, &mut config)
        .expect("quiche::connect");

    let deadline = Instant::now() + Duration::from_millis(HANDSHAKE_DEADLINE_MS);

    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut buf = [0u8; 65_535];

    // === Send loop: flush any pending Initial packets. ===
    flush_send(&mut conn, &socket, &mut out);

    // Suppress the panic backtrace printed by the default hook while we
    // poll `encode_pkt` for key-liveness — the missing-seal panic is the
    // expected "keys not yet live" signal, not a real failure.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    // === Drive handshake until Handshake-epoch encrypt keys go live. ===
    //
    // We do NOT loop on `is_established()` — that's reached only after
    // the client's Finished has been sent, by which point quiche has
    // already retired the Handshake-epoch crypto_seal.
    let result = loop {
        // Probe BEFORE blocking on recv so we exit as soon as the last
        // `conn.recv()` materialised the keys.
        //
        // `encode_pkt(Handshake, &[], buf)` panics inside
        // `crypto_overhead().unwrap()` when the seal is `None`; we catch
        // the panic and treat it as "keys not yet live". Once the seal
        // is `Some`, the call returns `Ok(_)` and we exit.
        let mut probe_buf = [0u8; MAX_DATAGRAM_SIZE];
        let probed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            quiche::test_utils::encode_pkt(
                &mut conn,
                quiche::Type::Handshake,
                &[],
                &mut probe_buf,
            )
        }));
        match probed {
            Ok(Ok(_)) => break Ok(()),
            Ok(Err(quiche::Error::InvalidState)) | Err(_) => {
                // Keys not live yet — continue handshake.
            }
            Ok(Err(e)) => {
                break Err(format!("probe failed: {e:?}"));
            }
        }

        if Instant::now() >= deadline {
            break Err(format!(
                "handshake-epoch keys did not materialise within {} ms",
                HANDSHAKE_DEADLINE_MS,
            ));
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = RecvInfo { to: local, from };
                if let Err(e) = conn.recv(&mut buf[..len], recv_info) {
                    break Err(format!("conn.recv failed: {e:?}"));
                }
                // Loop back to probe — if the server's Handshake CRYPTO
                // just arrived, the keys are now live and we exit before
                // flush_send would emit the client Finished.
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut => {
                // Timer tick — drive on_timeout so loss detection fires,
                // then flush any retransmissions so the handshake makes
                // progress.
                conn.on_timeout();
                flush_send(&mut conn, &socket, &mut out);
            }
            Err(e) => {
                break Err(format!("recv_from failed: {e:?}"));
            }
        }
    };

    std::panic::set_hook(prev_hook);

    match result {
        Ok(()) => (conn, socket, server),
        Err(msg) => panic!("navette_connect_until_handshake_keys: {msg}"),
    }
}

/// Drain quiche's outgoing packet queue and send each batch to the server.
///
/// Loops `conn.send(&mut out)` until quiche reports `Done`. Any I/O error
/// other than `WouldBlock` panics — these scenarios assume a healthy local
/// UDP loopback.
fn flush_send(conn: &mut Connection, socket: &UdpSocket, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((written, send_info)) => {
                match socket.send_to(&out[..written], send_info.to) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("flush_send: send_to failed: {e:?}"),
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("flush_send: conn.send failed: {e:?}"),
        }
    }
}

/// Encrypt `frames` into a 1-RTT QUIC packet using `conn`'s live crypto
/// context, then send the packet to `server_addr` via `socket`.
///
/// Uses the vendor-patched `quiche::test_utils::encode_pkt`, which bypasses
/// every public API (`stream_send`, `close`, ...) so the harness can inject
/// frames navette would reject if asked via the normal path.
///
/// # Notes
///
/// * Each call increments `conn.next_pkt_num` (test_utils.rs:471 in the
///   vendored tree). If normal quiche-driven traffic is needed after raw
///   injection, call `drain_pending(conn, ...)` first to resync PN state.
/// * Caller-supplied `frames` must be valid for the 1-RTT epoch; quiche
///   will refuse to encode CRYPTO frames at the application level.
///
/// Returns the number of bytes written to the UDP socket.
pub fn send_raw_1rtt(
    conn: &mut Connection,
    socket: &UdpSocket,
    server_addr: SocketAddr,
    frames: &[quiche::frame::Frame],
) -> io::Result<usize> {
    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = quiche::test_utils::encode_pkt(conn, quiche::Type::Short, frames, &mut buf)
        .map_err(|e| io::Error::other(format!("encode_pkt: {e:?}")))?;
    socket.send_to(&buf[..written], server_addr)
}

/// Encrypt raw payload bytes into a 1-RTT QUIC packet and send it.
///
/// Variant of [`send_raw_1rtt`] for scenarios where the desired QUIC packet
/// payload has no matching `quiche::frame::Frame` variant — e.g. an unknown
/// frame-type byte (F10). The bytes in `frame_payload` are treated as the
/// QUIC packet payload (post-header, pre-AEAD-tag); they are not
/// re-validated by quiche.
///
/// Implemented by [`quiche::test_utils::encode_pkt_with_payload`] (vendor
/// patch). The α.2 lib publishes the symbol so scenarios can call it as
/// soon as they're wired; if the vendor helper is absent (older quiche
/// snapshot) the call surfaces as an `io::Error` and the scenario exits
/// non-zero in the gate's RED column.
pub fn send_raw_1rtt_bytes(
    conn: &mut Connection,
    socket: &UdpSocket,
    server_addr: SocketAddr,
    frame_payload: &[u8],
) -> io::Result<usize> {
    let mut buf = [0u8; MAX_DATAGRAM_SIZE];
    let written = quiche::test_utils::encode_pkt_with_payload(
        conn,
        quiche::Type::Short,
        frame_payload,
        &mut buf,
    )
    .map_err(|e| io::Error::other(format!("encode_pkt_with_payload: {e:?}")))?;
    socket.send_to(&buf[..written], server_addr)
}

/// Poll for a CONNECTION_CLOSE frame emitted by navette within `timeout_ms`.
///
/// Drives the standard `recv` / `flush_send` / `is_closed` loop until either
/// `conn.peer_error()` reports a transport-CC, the deadline elapses, or
/// `conn.is_closed()` returns true. The reason phrase is decoded with
/// `String::from_utf8_lossy` so a non-UTF-8 reason still surfaces (with
/// replacement characters); `assert_close` performs a plain `contains`
/// substring match on the decoded reason.
///
/// Returns `Some((error_code, reason))` on close, `None` on timeout.
pub fn wait_connection_close(
    conn: &mut Connection,
    socket: &UdpSocket,
    server_addr: SocketAddr,
    timeout_ms: u64,
) -> Option<(u64, String)> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let local = socket.local_addr().expect("local_addr");
    let mut buf = [0u8; 65_535];
    let mut out = [0u8; MAX_DATAGRAM_SIZE];

    while Instant::now() < deadline {
        // Check for a remote CONNECTION_CLOSE that quiche has already
        // decoded into `peer_error`.
        if let Some(err) = conn.peer_error() {
            let reason = decode_reason(&err.reason);
            return Some((err.error_code, reason));
        }
        if conn.is_closed() {
            // Some quiche versions surface the peer close via local_error
            // when the connection finishes draining without a clean app
            // close. Fall back to local_error so caller still sees the
            // remote close reason.
            if let Some(err) = conn.local_error() {
                let reason = decode_reason(&err.reason);
                return Some((err.error_code, reason));
            }
            return None;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let info = RecvInfo { to: local, from };
                // `conn.recv` may surface InvalidState etc. after navette's
                // CC; we ignore those errors here so the next peer_error
                // poll resolves the outcome.
                let _ = conn.recv(&mut buf[..len], info);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut => {
                conn.on_timeout();
            }
            Err(_) => return None,
        }
        flush_send(conn, socket, &mut out);
        let _ = server_addr; // currently informational; kept for API parity.
    }

    None
}

/// Decode the CONNECTION_CLOSE reason phrase, truncated to 256 bytes.
///
/// Per RFC 9000 §19.19 the reason is UTF-8; we decode lossily so any
/// non-UTF-8 bytes surface as `U+FFFD` rather than failing the assert
/// chain. The 256-byte cap matches the spec and protects against
/// pathological closes (real navette reasons are GUARD-TAG-sized).
fn decode_reason(bytes: &[u8]) -> String {
    let take = bytes.len().min(256);
    String::from_utf8_lossy(&bytes[..take]).into_owned()
}

/// Assert that `result` is a CONNECTION_CLOSE with `expected_code` whose
/// reason phrase contains `guard_tag`.
///
/// Prints a single line to stdout for the gate script to scrape:
/// `PASS <failure_id>` on success, `FAIL <failure_id>: <diagnostic>`
/// otherwise. Returns `true` on success.
///
/// The scenarios use this as the last call before `process::exit(0|1)`.
pub fn assert_close(
    result: Option<(u64, String)>,
    expected_code: u64,
    guard_tag: &str,
    failure_id: &str,
) -> bool {
    match result {
        Some((code, reason)) if code == expected_code && reason.contains(guard_tag) => {
            println!("PASS {failure_id}");
            true
        }
        Some((code, reason)) => {
            eprintln!(
                "FAIL {failure_id}: got code 0x{code:x} reason {reason:?}, \
                 expected code 0x{expected_code:x} containing {guard_tag:?}",
            );
            false
        }
        None => {
            eprintln!(
                "FAIL {failure_id}: no CONNECTION_CLOSE within timeout \
                 (expected code 0x{expected_code:x} containing {guard_tag:?})",
            );
            false
        }
    }
}

/// Discard all pending outgoing quiche packets to resync packet-number state
/// after one or more raw injections.
///
/// `encode_pkt` increments `conn.next_pkt_num` per call (see vendored
/// `src/test_utils.rs`), but the standard quiche send path tracks its own
/// PN counter. When a scenario follows raw injection with normal quiche-
/// driven traffic, the PNs diverge and the next `conn.send` is rejected by
/// the server. This helper flushes all pending traffic so the counter
/// stays consistent. Most scenarios DON'T need this — they inject once
/// and then call `wait_connection_close` — but it's exposed for parity
/// with the spec.
pub fn drain_pending(conn: &mut Connection, socket: &UdpSocket, server_addr: SocketAddr) {
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    flush_send(conn, socket, &mut out);
    let _ = server_addr;
}
