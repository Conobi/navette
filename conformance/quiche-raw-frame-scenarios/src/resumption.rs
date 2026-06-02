//! Resumption fixture for scenarios that need a 0-RTT-capable connection.
//!
//! Phase 1 (`drive_to_session_ticket`): connect to a navette server,
//! complete a handshake, capture the issued NewSessionTicket.
//!
//! Phase 2 (`drive_to_zero_rtt_seal` — added in the next commit)
//! reconnects with the cached blob, drives until quiche's
//! `crypto_seal[Application]` is populated, returns the connection in a
//! state where `encode_pkt(Type::ZeroRTT, ...)` is valid.
//!
//! NOT thread-safe. Single connection per call. Caller owns the
//! returned blob's lifetime; pass it as `&[u8]` to Phase 2.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use quiche::{ConnectionId, RecvInfo};
use ring::rand::{SecureRandom, SystemRandom};

use crate::MAX_DATAGRAM_SIZE;

/// Serialized NewSessionTicket + transport parameters as produced by
/// `quiche::Connection::session()`. Suitable input for Phase 2's
/// `set_session()` on a fresh `Config`.
pub type SessionTicketBlob = Vec<u8>;

/// Wall-clock deadline for Phase 1 (handshake + ticket capture).
///
/// Local-loopback navette typically issues a NewSessionTicket within a
/// few RTTs of `is_established()`. 2_000 ms matches
/// `HANDSHAKE_DEADLINE_MS` in `lib.rs` and is well above the observed
/// per-host noise floor.
const PHASE1_DEADLINE_MS: u64 = 2_000;

/// Drive a fresh QUIC + HTTP/3 connection to navette and return the
/// issued NewSessionTicket blob.
///
/// Steps, in order:
///
/// 1. Build a quiche client `Config` with `enable_early_data()` so the
///    server's `NewSessionTicket` carries the `max_early_data_size`
///    extension that Phase 2 needs.
/// 2. Bind an ephemeral UDP socket on loopback.
/// 3. Generate a random 16-byte source CID.
/// 4. `quiche::connect(Some("localhost"), ...)` — matches the SNI used
///    by every other scenario in this crate.
/// 5. Drive the standard recv/send/timeout loop until
///    `is_established()`.
/// 6. Wire `quiche::h3::Connection` on top and `send_request` a `GET /`
///    so the server commits to issuing a ticket.
/// 7. Continue pumping the connection until `conn.session()` returns
///    `Some(_)` or `PHASE1_DEADLINE_MS` elapses.
/// 8. Clone the blob, close cleanly, return.
///
/// # Errors
///
/// Returns `io::ErrorKind::TimedOut` if the deadline elapses before a
/// ticket is captured, and `io::ErrorKind::Other` for any quiche /
/// socket error along the way.
pub fn drive_to_session_ticket(server_addr: SocketAddr) -> io::Result<SessionTicketBlob> {
    // === 1. Config. ===
    //
    // Mirrors `build_client_config` in `lib.rs` but with early-data
    // enabled — Phase 1 needs the server to issue a ticket that
    // advertises `max_early_data_size`, otherwise Phase 2's `set_session`
    // + 0-RTT keys never materialise.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| io::Error::other(format!("Config::new: {e:?}")))?;
    config.verify_peer(false);
    config
        .set_application_protos(&[b"h3"])
        .map_err(|e| io::Error::other(format!("set_application_protos: {e:?}")))?;
    config.enable_early_data();
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

    // === 2. Socket. ===
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(25)))?;
    let local = socket.local_addr()?;

    // === 3. Source CID. ===
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new()
        .fill(&mut scid_bytes[..])
        .map_err(|_| io::Error::other("random scid"))?;
    let scid = ConnectionId::from_ref(&scid_bytes);

    // === 4. Connect. ===
    let mut conn = quiche::connect(Some("localhost"), &scid, local, server_addr, &mut config)
        .map_err(|e| io::Error::other(format!("quiche::connect: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_millis(PHASE1_DEADLINE_MS);
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut buf = [0u8; 65_535];

    // Flush any pending Initial packets before entering the recv loop.
    flush(&mut conn, &socket, &mut out)?;

    // === 5. Drive handshake to is_established(). ===
    while !conn.is_established() && Instant::now() < deadline {
        pump_once(&mut conn, &socket, local, &mut buf, &mut out)?;
    }
    if !conn.is_established() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("handshake not established within {PHASE1_DEADLINE_MS} ms"),
        ));
    }

    // === 6. GET / over HTTP/3 — prompts the server to issue a ticket. ===
    //
    // Some TLS stacks defer NewSessionTicket until the first application
    // record exchange; sending a real H3 request guarantees navette has
    // taken the post-handshake server path.
    let h3_config = quiche::h3::Config::new()
        .map_err(|e| io::Error::other(format!("h3::Config::new: {e:?}")))?;
    let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
        .map_err(|e| io::Error::other(format!("h3::with_transport: {e:?}")))?;

    let req = [
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"user-agent", b"navette-resumption-phase1"),
    ];
    h3_conn
        .send_request(&mut conn, &req, true)
        .map_err(|e| io::Error::other(format!("h3::send_request: {e:?}")))?;
    flush(&mut conn, &socket, &mut out)?;

    // === 7. Pump until session() is populated or deadline. ===
    let mut blob: Option<SessionTicketBlob> = None;
    while Instant::now() < deadline {
        if let Some(bytes) = conn.session() {
            blob = Some(bytes.to_vec());
            break;
        }
        pump_once(&mut conn, &socket, local, &mut buf, &mut out)?;
        // Drain any H3 events so quiche keeps making forward progress.
        loop {
            match h3_conn.poll(&mut conn) {
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(_) => break,
            }
        }
    }

    let blob = blob.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no session ticket within {PHASE1_DEADLINE_MS} ms"),
        )
    })?;

    // === 8. Close cleanly. Errors here are non-fatal — we already have
    // the blob; navette will time the connection out on its own if the
    // close datagram is lost.
    let _ = conn.close(false, 0, b"phase 1 done");
    let _ = flush(&mut conn, &socket, &mut out);

    Ok(blob)
}

/// Run one iteration of the recv -> on_timeout -> flush pump.
///
/// Mirrors the body of `navette_connect`'s drive loop in `lib.rs`. Kept
/// private so Phase 2 can build a different state machine on top of the
/// same primitives without coupling to this helper.
fn pump_once(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    local: SocketAddr,
    buf: &mut [u8],
    out: &mut [u8],
) -> io::Result<()> {
    match socket.recv_from(buf) {
        Ok((len, from)) => {
            let recv_info = RecvInfo { to: local, from };
            conn.recv(&mut buf[..len], recv_info)
                .map_err(|e| io::Error::other(format!("conn.recv: {e:?}")))?;
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            conn.on_timeout();
        }
        Err(e) => return Err(e),
    }
    flush(conn, socket, out)
}

/// Drain quiche's outgoing packet queue. Stops on `Done` or `WouldBlock`.
fn flush(conn: &mut quiche::Connection, socket: &UdpSocket, out: &mut [u8]) -> io::Result<()> {
    loop {
        match conn.send(out) {
            Ok((written, send_info)) => {
                match socket.send_to(&out[..written], send_info.to) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(io::Error::other(format!("conn.send: {e:?}"))),
        }
    }
}
