//! sanity_get — Phase α always-on probe.
//!
//! Completes a QUIC + HTTP/3 handshake against navette's `hello_h3_server`
//! and issues a single `GET /` request. Exits 0 if the server returns a
//! `:status` HEADERS frame (any 2xx/3xx code accepted — the test is for
//! the round-trip, not the response code). Exits 1 on any handshake or
//! H3-poll failure.
//!
//! This scenario carries no GUARD-TAG / CONNECTION_CLOSE assertion — it
//! is the cycle's "the server is alive" smoke check.

use std::env;
use std::io;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use quiche::h3::NameValue;
use quiche::RecvInfo;
use quiche_raw_frame_scenarios::{
    navette_connect, server_addr_with_port, MAX_DATAGRAM_SIZE,
};

const SANITY_TAG: &str = "sanity_get";
const SANITY_DEADLINE_MS: u64 = 2_000;

fn main() -> ExitCode {
    let port: u16 = env::var("QRF_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    // Handshake. `navette_connect` panics on hard failure (UDP bind error,
    // handshake timeout); catch the panic with the standard runtime so the
    // gate sees exit code 1 rather than a process abort.
    let panic_result = std::panic::catch_unwind(|| navette_connect(port));
    let (mut conn, socket, _server) = match panic_result {
        Ok(triple) => triple,
        Err(_) => {
            eprintln!("FAIL {SANITY_TAG}: handshake did not establish (see panic above)");
            return ExitCode::from(1);
        }
    };
    let _ = server_addr_with_port(port); // smoke-check helper reachability.

    // Wire HTTP/3 atop the established QUIC connection.
    let h3_config = match quiche::h3::Config::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAIL {SANITY_TAG}: h3::Config::new failed: {e:?}");
            return ExitCode::from(1);
        }
    };
    let mut h3_conn = match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAIL {SANITY_TAG}: h3 with_transport failed: {e:?}");
            return ExitCode::from(1);
        }
    };

    // Submit GET /.
    let req = [
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/"),
        quiche::h3::Header::new(b"user-agent", b"quiche-raw-frame-sanity"),
    ];
    if let Err(e) = h3_conn.send_request(&mut conn, &req, true) {
        eprintln!("FAIL {SANITY_TAG}: send_request failed: {e:?}");
        return ExitCode::from(1);
    }

    // Drain quiche send-queue post-request.
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
    if !flush_send(&mut conn, &socket, &mut out) {
        eprintln!("FAIL {SANITY_TAG}: send loop hard error after request");
        return ExitCode::from(1);
    }

    // Poll H3 events until we observe `:status` or the deadline.
    let deadline = Instant::now() + Duration::from_millis(SANITY_DEADLINE_MS);
    let local = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("FAIL {SANITY_TAG}: local_addr failed: {e}");
            return ExitCode::from(1);
        }
    };

    let mut buf = [0u8; 65_535];
    let mut saw_status = false;

    while Instant::now() < deadline && !saw_status {
        // Receive any pending datagrams.
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let info = RecvInfo { to: local, from };
                if let Err(e) = conn.recv(&mut buf[..len], info) {
                    eprintln!("FAIL {SANITY_TAG}: conn.recv: {e:?}");
                    return ExitCode::from(1);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut => {
                conn.on_timeout();
            }
            Err(e) => {
                eprintln!("FAIL {SANITY_TAG}: recv_from: {e}");
                return ExitCode::from(1);
            }
        }

        // Poll the H3 layer.
        loop {
            match h3_conn.poll(&mut conn) {
                Ok((_stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    for hdr in &list {
                        if hdr.name() == b":status" {
                            saw_status = true;
                            break;
                        }
                    }
                }
                Ok((_, quiche::h3::Event::Data)) |
                Ok((_, quiche::h3::Event::Finished)) |
                Ok((_, quiche::h3::Event::Reset(_))) |
                Ok((_, quiche::h3::Event::GoAway)) |
                Ok((_, quiche::h3::Event::PriorityUpdate)) => {
                    // Non-status events are fine; keep polling.
                }
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    eprintln!("FAIL {SANITY_TAG}: h3 poll: {e:?}");
                    return ExitCode::from(1);
                }
            }
        }

        if !flush_send(&mut conn, &socket, &mut out) {
            eprintln!("FAIL {SANITY_TAG}: send loop hard error");
            return ExitCode::from(1);
        }
    }

    if saw_status {
        println!("PASS {SANITY_TAG}");
        ExitCode::from(0)
    } else {
        eprintln!("FAIL {SANITY_TAG}: no :status received within {SANITY_DEADLINE_MS} ms");
        ExitCode::from(1)
    }
}

/// Drain quiche's outgoing send-queue. Returns false on hard I/O error.
fn flush_send(
    conn: &mut quiche::Connection,
    socket: &std::net::UdpSocket,
    out: &mut [u8],
) -> bool {
    loop {
        match conn.send(out) {
            Ok((written, send_info)) => {
                match socket.send_to(&out[..written], send_info.to) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                    Err(_) => return false,
                }
            }
            Err(quiche::Error::Done) => return true,
            Err(_) => return false,
        }
    }
}
