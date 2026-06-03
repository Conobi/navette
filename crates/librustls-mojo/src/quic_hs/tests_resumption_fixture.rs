//! Forced-resumption fixture for server-side 0-RTT decrypt key tests.
//!
//! Drives a real rustls handshake → ticket issuance → resumed handshake
//! sequence so that `ServerConnection::zero_rtt_keys()` returns `Some(_)`
//! at the moment the fixture returns control to the test.
//!
//! Test-only (`#[cfg(test)]`); never compiled into production.

use std::sync::Arc;

use rustls::client::{ClientConfig, ClientSessionStore, Resumption};
use rustls::pki_types::ServerName;
use rustls::quic::{ClientConnection, ServerConnection, Version as QuicVersion};
use rustls::server::ServerConfig;
use rustls::RootCertStore;

use super::tests::gen_test_cert;
use super::{quic_conn_table, QuicConn, QuicConnEntry};

/// Empty transport-parameters bytes, matching the test scaffolding's
/// default in `make_conn_pair`. rustls accepts empty TPs in test setups.
const TP_BYTES: &[u8] = &[];

/// Bounded extra round-trip count after `is_handshaking() == false` to
/// flush the post-handshake `NewSessionTicket` from server to client.
/// rustls 0.23 typically emits the ticket within 1-2 round-trips; this
/// is conservative.
const TICKET_FLUSH_EXTRA_ROUNDS: usize = 8;

/// Build a real (cert, key, root-DER) triple via rcgen.
fn build_certs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    gen_test_cert()
}

/// Build a `ServerConfig` with TLS 1.3, h3 ALPN, default
/// `session_storage`, and 0-RTT enabled (`max_early_data_size = u32::MAX`).
fn build_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Arc<ServerConfig> {
    use std::io::BufReader;

    let certs: Vec<_> = {
        let mut r = BufReader::new(cert_pem);
        rustls_pemfile::certs(&mut r)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse cert pem")
    };

    let key = {
        let mut r = BufReader::new(key_pem);
        rustls_pemfile::private_key(&mut r)
            .expect("parse key pem")
            .expect("at least one private key")
    };

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config build");

    config.alpn_protocols = vec![b"h3".to_vec()];
    config.max_early_data_size = u32::MAX;
    // 0-RTT requires stateful resumption in rustls 0.23: `decide_if_early_data_allowed`
    // (server/tls13.rs L632) gates on `!config.ticketer.enabled()`, so we leave the
    // default `NeverProducesTickets` in place and rely on `session_storage`
    // (default `ServerSessionMemoryCache`, 256 entries) for ticket persistence.

    Arc::new(config)
}

/// Build a `ClientConfig` that trusts the given self-signed root, with
/// h3 ALPN, 0-RTT enabled, and a shared session store for resumption.
fn build_client_config(
    root_cert_der: &[u8],
    session_store: Arc<dyn ClientSessionStore>,
) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(root_cert_der.to_vec()))
        .expect("add root cert");

    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;
    config.resumption = Resumption::store(session_store);

    Arc::new(config)
}

/// Drive a single ping-pong of CRYPTO data between two `rustls::quic`
/// connections. Returns `true` if either side produced any bytes
/// (forward progress).
fn pump_once(client: &mut ClientConnection, server: &mut ServerConnection) -> bool {
    let mut progress = false;
    let mut buf: Vec<u8> = Vec::new();

    // Client → Server. We ignore returned `KeyChange` events: the rustls
    // state machine continues to advance internally regardless of whether
    // the caller consumes the key material. This fixture only cares about
    // `zero_rtt_keys()` returning `Some(_)` on the resumed conn.
    let _kc = client.write_hs(&mut buf);
    if !buf.is_empty() {
        progress = true;
        server.read_hs(&buf).expect("server read_hs");
    }
    buf.clear();

    // Server → Client.
    let _kc = server.write_hs(&mut buf);
    if !buf.is_empty() {
        progress = true;
        client.read_hs(&buf).expect("client read_hs");
    }

    progress
}

/// Drive a full handshake plus a tail of extra round-trips to flush the
/// post-handshake `NewSessionTicket` from server to client.
///
/// rustls 0.23 emits the `NewSessionTicket` after `is_handshaking() == false`
/// on both sides. The `ClientSessionStore::take_tls13_ticket` API is
/// consuming (no non-destructive peek), so we cannot terminate Phase B
/// early without invalidating the ticket the resumed handshake needs.
/// Instead we drive a fixed conservative tail count.
fn drive_first_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    // Phase A: drive until both sides finish the cryptographic handshake.
    for _ in 0..32 {
        let progress = pump_once(client, server);
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        assert!(progress, "first handshake stalled with no progress");
    }
    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "first handshake did not converge in 32 rounds",
    );

    // Phase B: pump extra round-trips so the post-handshake NewSessionTicket
    // reaches the client and is stored in the shared session cache. We
    // cannot probe the store non-destructively, so use a fixed conservative
    // count; rustls typically flushes within 1-2 round-trips.
    for _ in 0..TICKET_FLUSH_EXTRA_ROUNDS {
        let _ = pump_once(client, server);
    }
}

/// Public(crate) entry point. Returns `(server_h, client_h)` for a RESUMED
/// QUIC connection where `ServerConnection::zero_rtt_keys()` is `Some(_)`
/// at return time.
///
/// The fixture:
///   1. Builds a self-signed cert + matching ServerConfig with 0-RTT enabled.
///   2. Builds a ClientConfig sharing a `ClientSessionMemoryCache`.
///   3. Drives a first handshake to completion, then extra round-trips to
///      flush the NewSessionTicket to the client cache.
///   4. Drops the first conn pair (the ticket lives in the shared store).
///   5. Builds a SECOND ClientConnection against the SAME shared store and
///      a fresh ServerConnection from the SAME ServerConfig Arc (preserving
///      the in-memory `session_storage` so the resumed ClientHello PSK
///      identity is recognised).
///   6. Pumps the resumption flight until `server.zero_rtt_keys()` is
///      `Some(_)`, then STOPS — driving past `KeyChange::OneRtt` would make
///      rustls discard the early-data secret (RFC 9001 §4.1.3-style).
///   7. Inserts both conns into `QUIC_CONN_TABLE` and returns the handles.
pub(super) fn drive_full_handshake_with_resumption() -> (i32, i32) {
    let (cert_pem, key_pem, cert_der) = build_certs();
    let server_config = build_server_config(&cert_pem, &key_pem);

    let session_store: Arc<dyn ClientSessionStore> =
        Arc::new(rustls::client::ClientSessionMemoryCache::new(32));
    let client_config = build_client_config(&cert_der, session_store.clone());

    let server_name: ServerName<'static> = ServerName::try_from("localhost".to_owned())
        .expect("ServerName::try_from localhost");

    // ---- Handshake 1: issue a session ticket. ----
    {
        let mut client_1 = ClientConnection::new(
            client_config.clone(),
            QuicVersion::V1,
            server_name.clone(),
            TP_BYTES.to_vec(),
        )
        .expect("client conn 1");
        let mut server_1 = ServerConnection::new(
            server_config.clone(),
            QuicVersion::V1,
            TP_BYTES.to_vec(),
        )
        .expect("server conn 1");

        drive_first_handshake(&mut client_1, &mut server_1);
    }

    // ---- Handshake 2: resumption with 0-RTT. ----
    let mut client_2 = ClientConnection::new(
        client_config.clone(),
        QuicVersion::V1,
        server_name.clone(),
        TP_BYTES.to_vec(),
    )
    .expect("client conn 2");
    let mut server_2 = ServerConnection::new(
        server_config.clone(),
        QuicVersion::V1,
        TP_BYTES.to_vec(),
    )
    .expect("server conn 2");

    // Drive the resumed handshake just far enough for the server to derive
    // the early-data secret. Break the loop the moment `zero_rtt_keys()`
    // returns `Some(_)` — driving past `KeyChange::OneRtt` would discard
    // the early-data secret on the server side.
    //
    // The fixture also tracks the first ClientHello prefix as the client
    // produces it, mirroring what the production ingress hook on
    // `rlsm_quic_conn_read_hs` would do if the resumed handshake had been
    // driven through the FFI. Bytes 6..38 of that prefix are the
    // ClientHello.random per RFC 8446 §4.1.2 and form the replay
    // authenticator the dedup store consumes.
    let mut first_ch_prefix = [0u8; 38];
    let mut first_ch_prefix_len: u8 = 0;
    let mut client_random_captured = false;
    let mut client_random = [0u8; 32];

    let mut got_zero_rtt = false;
    for _ in 0..16 {
        let mut buf: Vec<u8> = Vec::new();
        let _ = client_2.write_hs(&mut buf);
        if !buf.is_empty() {
            // Accumulate the leading 38 bytes from the client→server flight
            // into a sticky buffer. Mirrors the production ingress hook
            // exactly, including tolerance of CRYPTO fragmentation.
            if !client_random_captured {
                let cur = first_ch_prefix_len as usize;
                if cur < 38 {
                    let want = 38 - cur;
                    let take = std::cmp::min(want, buf.len());
                    first_ch_prefix[cur..cur + take].copy_from_slice(&buf[..take]);
                    first_ch_prefix_len = (cur + take) as u8;
                    if first_ch_prefix_len == 38 && first_ch_prefix[0] == 0x01 {
                        client_random.copy_from_slice(&first_ch_prefix[6..38]);
                        client_random_captured = true;
                    }
                }
            }
            server_2.read_hs(&buf).expect("server_2 read_hs");
        }
        if server_2.zero_rtt_keys().is_some() {
            got_zero_rtt = true;
            break;
        }
        // Pump server→client so rustls can drive the state machine, but
        // STOP before client.read_hs would advance past OneRtt installation
        // on the server. We let the server emit; we let the client read.
        // If the server is already past OneRtt-emit it has discarded the
        // early secret — which is exactly what we must prevent.
        let mut buf2: Vec<u8> = Vec::new();
        let _ = server_2.write_hs(&mut buf2);
        if server_2.zero_rtt_keys().is_some() {
            got_zero_rtt = true;
            break;
        }
        if !buf2.is_empty() {
            client_2.read_hs(&buf2).expect("client_2 read_hs");
        }
    }
    assert!(
        got_zero_rtt,
        "resumed server never produced zero_rtt_keys = Some(_); \
         verify enable_early_data + max_early_data_size + ticket cache wiring",
    );
    assert!(
        client_random_captured,
        "resumed handshake completed without observing a 38-byte ClientHello \
         prefix; the fixture cannot pre-populate the authenticator",
    );

    // ---- Insert into Wave 1's QUIC_CONN_TABLE. ----
    let server_entry = QuicConnEntry {
        conn: QuicConn::Server(server_2),
        pending: None,
        next_secrets: None,
        alert_cache: None,
        first_ch_prefix,
        first_ch_prefix_len,
        client_random_captured,
        client_random,
    };
    let client_entry = QuicConnEntry {
        conn: QuicConn::Client(client_2),
        pending: None,
        next_secrets: None,
        alert_cache: None,
        first_ch_prefix: [0u8; 38],
        first_ch_prefix_len: 0,
        client_random_captured: false,
        client_random: [0u8; 32],
    };

    let server_h = quic_conn_table()
        .insert(server_entry)
        .expect("QUIC_CONN_TABLE handle counter exhausted (server)");
    let client_h = quic_conn_table()
        .insert(client_entry)
        .expect("QUIC_CONN_TABLE handle counter exhausted (client)");

    (server_h, client_h)
}
