//! Resumption fixture for scenarios that need a 0-RTT-capable connection.
//!
//! Phase 1 (`drive_to_session_ticket`): connect to a navette server,
//! complete a handshake, capture the issued NewSessionTicket.
//!
//! Phase 2 (`drive_to_zero_rtt_seal`) reconnects with the cached blob,
//! drives until quiche's `crypto_seal[Application]` is populated, and
//! returns the connection in a state where
//! `encode_pkt(Type::ZeroRTT, ...)` is valid.
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

/// Wall-clock deadline for Phase 2 (resumed-handshake drive until the
/// Application `crypto_seal` is populated).
///
/// Same budget as Phase 1; aborting after 2 s catches the case where the
/// server rejected the ticket (handshake degrades to a full 1-RTT
/// handshake and the early-data keys never install).
const PHASE2_DEADLINE_MS: u64 = 2_000;

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

/// A resumed quiche client connection driven up to the point where 0-RTT
/// packets can be encoded against it.
///
/// `conn` holds the live `quiche::Connection`; `socket` is the bound UDP
/// socket peer-connected to `server_addr` for ongoing send/recv. Callers
/// own the lifetimes of all three fields; nothing inside attempts a
/// close on drop.
pub struct ResumedConn {
    /// The resumed quiche client connection. `has_application_crypto_seal()`
    /// returns true when this struct is returned from
    /// `drive_to_zero_rtt_seal`.
    pub conn: quiche::Connection,
    /// UDP socket bound to a loopback ephemeral port. Read-timeout is
    /// preserved from the helper's drive loop; callers may reset it.
    pub socket: UdpSocket,
    /// Server address the connection targets. Re-exposed so the caller
    /// can build follow-up `RecvInfo` and `send_to` calls without
    /// re-resolving.
    pub server_addr: SocketAddr,
}

/// Reconnect with a cached NewSessionTicket blob and drive the resumed
/// handshake until quiche's Application `crypto_seal` is populated.
///
/// Returned in this state, the connection accepts
/// `quiche::test_utils::encode_pkt(quiche::packet::Type::ZeroRTT, ...)`
/// — the precondition the F30 scenario binary needs to inject a 0-RTT
/// CRYPTO frame at the navette server.
///
/// Steps, in order:
///
/// 1. Build a quiche client `Config` with `enable_early_data()` and the
///    same transport parameters as Phase 1.
/// 2. Bind an ephemeral UDP socket on loopback.
/// 3. Generate a fresh random 16-byte source CID.
/// 4. `quiche::connect(Some("localhost"), ...)`.
/// 5. `conn.set_session(session_blob)` — primes the resumed handshake.
/// 6. Flush any pending Initial packets, then loop the standard
///    recv/on_timeout/flush pump while
///    `!conn.has_application_crypto_seal()` and
///    `Instant::now() < deadline`.
/// 7. Return `ResumedConn { conn, socket, server_addr }` once the seal
///    is installed; surface `io::ErrorKind::TimedOut` on deadline.
///
/// # Errors
///
/// * `io::ErrorKind::TimedOut` — the deadline elapsed before the
///   Application `crypto_seal` was installed. Usually means navette
///   rejected the resumption ticket and the connection degraded to a
///   full 1-RTT handshake.
/// * `io::ErrorKind::Other` — wraps any quiche or socket error
///   encountered on the way (config build, `set_session`, recv/send).
pub fn drive_to_zero_rtt_seal(
    server_addr: SocketAddr,
    session_blob: &[u8],
) -> io::Result<ResumedConn> {
    // === 1. Config — same shape as Phase 1. ===
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

    // === 5. Prime the resumed handshake with the cached ticket. ===
    //
    // After this call, the next outgoing Initial flight carries the
    // pre_shared_key extension; if navette accepts, the Application
    // (1-RTT) keys derive directly from the early-data secret without
    // waiting for the server Finished message.
    conn.set_session(session_blob)
        .map_err(|e| io::Error::other(format!("conn.set_session: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_millis(PHASE2_DEADLINE_MS);
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut buf = [0u8; 65_535];

    // === 6. Flush the resumed Initial flight, then pump. ===
    flush(&mut conn, &socket, &mut out)?;

    while !conn.has_application_crypto_seal() && Instant::now() < deadline {
        pump_once(&mut conn, &socket, local, &mut buf, &mut out)?;
    }

    if !conn.has_application_crypto_seal() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "Application crypto_seal not installed within {PHASE2_DEADLINE_MS} ms \
                 (resumption likely rejected by server)"
            ),
        ));
    }

    // === 7. Hand the connection back to the caller. ===
    Ok(ResumedConn {
        conn,
        socket,
        server_addr,
    })
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

/// Variant of `drive_to_zero_rtt_seal` that drives a resumed handshake
/// with 0-RTT-bearing application data, capturing every UDP datagram
/// the client sends to the server into a `Vec<Vec<u8>>` (one inner vec
/// per datagram).
///
/// Used by `s_zero_rtt_replay`'s Phase 2 to capture the wire bytes that
/// Phase 3 will replay verbatim against a fresh socket.
///
/// Steps, in order:
///   1. Build a quiche client Config identical to `build_client_config`
///      in this module (early-data enabled, h3 ALPN, disable migration).
///   2. Bind a fresh ephemeral UDP socket and connect logically to
///      `server_addr` via `quiche::connect`.
///   3. `conn.set_session(session_blob)` to prime the resumption.
///   4. Wire `quiche::h3::Connection::with_transport` and queue a GET /
///      so the server commits to processing 0-RTT-borne application data
///      once the Application crypto_seal is installed.
///   5. Run a drive loop:
///        a. `conn.send(...)` to get the next outgoing datagram.
///        b. Push the datagram bytes into `captured`.
///        c. `socket.send_to(...)` the bytes to the server.
///        d. `socket.recv_from(...)` to ingest any server reply.
///        e. Loop until either `conn.has_application_crypto_seal()`
///           returned true earlier AND we've sent at least one
///           1-RTT-or-later datagram carrying the 0-RTT stream open,
///           OR `deadline` elapses.
///   6. Return `(ResumedConn, captured)`.
///
/// # Errors
///
/// `io::ErrorKind::TimedOut` if the deadline elapses before any
/// datagram is captured.
pub fn drive_to_zero_rtt_with_datagram_capture(
    server_addr: SocketAddr,
    session_blob: &[u8],
) -> io::Result<(ResumedConn, Vec<Vec<u8>>)> {
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

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(25)))?;
    let local = socket.local_addr()?;

    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new()
        .fill(&mut scid_bytes[..])
        .map_err(|_| io::Error::other("random scid"))?;
    let scid = ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some("localhost"), &scid, local, server_addr, &mut config)
        .map_err(|e| io::Error::other(format!("quiche::connect: {e:?}")))?;

    conn.set_session(session_blob)
        .map_err(|e| io::Error::other(format!("conn.set_session: {e:?}")))?;

    let deadline = Instant::now() + Duration::from_millis(2_000);
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    let mut buf = [0u8; 65_535];
    let mut captured: Vec<Vec<u8>> = Vec::new();

    // Pre-flush + capture: the resumed Initial flight needs to leave
    // the client before we issue the H3 request.
    loop {
        match conn.send(&mut out) {
            Ok((written, send_info)) => {
                captured.push(out[..written].to_vec());
                socket.send_to(&out[..written], send_info.to)?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(io::Error::other(format!("conn.send: {e:?}"))),
        }
    }

    // Wire H3 + queue a request once 0-RTT seal is available. Some
    // builds queue the H3 stream open into the very next 0-RTT
    // datagram; others defer until after one round trip. The drive
    // loop below handles both.
    let h3_config = quiche::h3::Config::new()
        .map_err(|e| io::Error::other(format!("h3::Config::new: {e:?}")))?;

    let mut h3_state: Option<quiche::h3::Connection> = None;
    let mut request_sent = false;

    while Instant::now() < deadline {
        // Lazy H3 wiring + request — only fire once the resumed
        // Application crypto_seal is installed so the H3 stream
        // open rides 0-RTT.
        if !request_sent && conn.has_application_crypto_seal() {
            let mut h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .map_err(|e| io::Error::other(format!("h3::with_transport: {e:?}")))?;
            let req = [
                quiche::h3::Header::new(b":method", b"GET"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/"),
                quiche::h3::Header::new(b"user-agent", b"navette-replay-capture"),
            ];
            h3.send_request(&mut conn, &req, true)
                .map_err(|e| io::Error::other(format!("h3::send_request: {e:?}")))?;
            h3_state = Some(h3);
            request_sent = true;
        }

        // Capture outgoing datagrams.
        loop {
            match conn.send(&mut out) {
                Ok((written, send_info)) => {
                    captured.push(out[..written].to_vec());
                    socket.send_to(&out[..written], send_info.to)?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => return Err(io::Error::other(format!("conn.send: {e:?}"))),
            }
        }

        // Pump incoming.
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let recv_info = RecvInfo { to: local, from };
                conn.recv(&mut buf[..len], recv_info)
                    .map_err(|e| io::Error::other(format!("conn.recv: {e:?}")))?;
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                conn.on_timeout();
            }
            Err(e) => return Err(e),
        }

        // Drain H3 events (best-effort; we don't need the response body).
        if let Some(ref mut h3) = h3_state {
            loop {
                match h3.poll(&mut conn) {
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(_) => break,
                }
            }
        }

        // Termination: after the request has been sent AND we've
        // captured at least one datagram, give the server ~100 ms to
        // process and bump its counter. Pinning to wall-clock instead
        // of a packet count avoids racy "send one more, hope it lands"
        // logic.
        if request_sent && !captured.is_empty() {
            // Give the server a tail interval to commit the accept.
            std::thread::sleep(Duration::from_millis(100));
            break;
        }
    }

    if captured.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "drive_to_zero_rtt_with_datagram_capture: no datagrams captured",
        ));
    }

    let resumed = ResumedConn {
        conn,
        socket,
        server_addr,
    };
    Ok((resumed, captured))
}

/// Replay every captured client→server datagram verbatim against the
/// same server, from a FRESH UDP socket and FRESH source CID. The
/// captured bytes carry their original DCID, which lets navette route
/// the packets to the original-issuance state machine path — Path A
/// short-circuits subsequent 0-RTT packets per the anti-replay design,
/// but the FIRST 0-RTT packet's authenticator MUST collide with the
/// store entry left by Phase 2 and the store MUST return
/// `duplicate`.
///
/// Reads up to `expected_responses_us` ms after each send to drain any
/// server reply (we discard the body; we only need the server to RUN
/// its replay check). Returns `Ok(())` once every captured datagram is
/// sent; surfaces socket errors immediately.
pub fn replay_datagrams_verbatim(
    server_addr: SocketAddr,
    datagrams: &[Vec<u8>],
    settle_ms: u64,
) -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(25)))?;
    let mut buf = [0u8; 65_535];

    for d in datagrams {
        socket.send_to(d, server_addr)?;
        // Best-effort drain. The server's CONNECTION_CLOSE (if any) or
        // application reply (if accept) lands here; we don't care which.
        match socket.recv_from(&mut buf) {
            Ok(_) | Err(_) => {}
        }
    }

    // Tail wait so the server's AcceptProfile commits the counter.
    std::thread::sleep(Duration::from_millis(settle_ms));
    Ok(())
}
