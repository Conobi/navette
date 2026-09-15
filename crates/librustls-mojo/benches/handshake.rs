//! Server-side CPU cost of one TLS 1.3 handshake, as navette's HTTP/3 server
//! performs it through `rlsm_quic_server_config_new` (0-RTT disabled).
//!
//! The handshake is driven entirely in memory: a rustls QUIC client and
//! server exchange plaintext CRYPTO bytes through a `Vec<u8>`. Only the
//! server-side calls (`ServerConnection::new`, `read_hs`, `write_hs`) are
//! timed; client work is excluded. Scenarios:
//!
//! * `full`          — fresh client each time, server sends 2 tickets (prod).
//! * `full-tickets0` — same, `send_tls13_tickets = 0` (isolates ticket cost).
//! * `resumed`       — client reuses the previous ticket (PSK + DHE).
//! * `primitives`    — raw aws-lc-rs X25519 / ECDSA-P256 sign / RNG fill.
//!
//! Run: `cargo bench --bench handshake --features skip-locks [-- N]`
//! (N = measured handshakes per scenario, default 3000). Pin to one core
//! with `taskset -c <cpu>` for stable numbers.

use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::{agreement, rand, signature};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs as provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::quic::{ClientConnection, ServerConnection, Version};
use rustls::{ClientConfig, DigitallySignedStruct, HandshakeKind, ServerConfig, SignatureScheme};

const WARMUP: usize = 200;
const DEFAULT_ITERS: usize = 3000;
const ALPN: &[u8] = b"h3";
/// Opaque bytes standing in for encoded QUIC transport parameters; rustls
/// forwards them without parsing.
const TRANSPORT_PARAMS: &[u8] = &[0x01, 0x04, 0x80, 0x00, 0xea, 0x60];

/// Accepts any server certificate; verification cost is client-side and
/// out of scope here.
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &provider::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Cert chain + PKCS#8 key from `certs/server.{crt,key}` at the repo root.
fn load_cert_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/");
    let cert_pem = std::fs::read(format!("{dir}server.crt")).expect("read certs/server.crt");
    let key_pem = std::fs::read(format!("{dir}server.key")).expect("read certs/server.key");
    let certs = rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse cert PEM");
    let key = rustls_pemfile::private_key(&mut BufReader::new(&key_pem[..]))
        .expect("parse key PEM")
        .expect("no private key in certs/server.key");
    (certs, key)
}

/// Mirrors `rlsm_quic_server_config_new` with `max_early_data == 0`, minus
/// the `KeyLogFile` (which is a no-op unless `SSLKEYLOGFILE` is set).
fn server_config(send_tls13_tickets: usize) -> Arc<ServerConfig> {
    let (certs, key) = load_cert_key();
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.ticketer = provider::Ticketer::new().expect("ticketer");
    config.send_tls13_tickets = send_tls13_tickets;
    Arc::new(config)
}

/// TLS 1.3-only client with the default in-memory resumption store, so a
/// reused `Arc<ClientConfig>` offers the PSK from the previous ticket.
fn client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

/// Per-handshake server-side measurements.
struct HandshakeSample {
    server_time: Duration,
    /// Bytes the server emitted after the client's Finished (NewSessionTicket).
    post_hs_bytes: usize,
    kind: Option<HandshakeKind>,
}

/// Flush one encryption level of pending handshake bytes into `buf`.
///
/// Returns false once nothing is pending and no key change occurred.
/// rustls requires bytes from different encryption levels to be fed to
/// `read_hs` in separate calls, so the caller feeds `buf` between calls.
fn pull_level<C>(conn: &mut C, buf: &mut Vec<u8>, write: impl Fn(&mut C, &mut Vec<u8>) -> bool) -> bool {
    buf.clear();
    let key_change = write(conn, buf);
    key_change || !buf.is_empty()
}

/// One complete handshake plus post-handshake ticket delivery.
fn run_handshake(server_cfg: &Arc<ServerConfig>, client_cfg: &Arc<ClientConfig>) -> HandshakeSample {
    let name = ServerName::try_from("localhost").expect("server name");
    let mut client =
        ClientConnection::new(client_cfg.clone(), Version::V1, name, TRANSPORT_PARAMS.to_vec())
            .expect("client connection");

    let mut server_time = Duration::ZERO;
    let t = Instant::now();
    let mut server = ServerConnection::new(server_cfg.clone(), Version::V1, TRANSPORT_PARAMS.to_vec())
        .expect("server connection");
    server_time += t.elapsed();

    let mut buf = Vec::with_capacity(4096);
    let mut post_hs_bytes = 0usize;

    for _round in 0..8 {
        // Client -> server, one encryption level per read_hs call.
        while pull_level(&mut client, &mut buf, |c, b| c.write_hs(b).is_some()) {
            if !buf.is_empty() {
                let t = Instant::now();
                server.read_hs(&buf).expect("server read_hs");
                server_time += t.elapsed();
            }
        }

        // Server -> client. Anything emitted once the server has finished
        // handshaking is post-handshake data (NewSessionTicket).
        let server_done = !server.is_handshaking();
        let mut server_emitted = 0usize;
        loop {
            let t = Instant::now();
            let more = pull_level(&mut server, &mut buf, |s, b| s.write_hs(b).is_some());
            server_time += t.elapsed();
            if !more {
                break;
            }
            if !buf.is_empty() {
                server_emitted += buf.len();
                client.read_hs(&buf).expect("client read_hs");
            }
        }
        if server_done {
            post_hs_bytes += server_emitted;
        }

        if !client.is_handshaking() && !server.is_handshaking() && server_emitted == 0 {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking(), "handshake did not complete");
    assert_eq!(server.alpn_protocol(), Some(ALPN), "ALPN not negotiated");

    HandshakeSample { server_time, post_hs_bytes, kind: server.handshake_kind() }
}

/// min / p50 / p90 / mean over sorted nanosecond samples.
struct Stats {
    min: f64,
    p50: f64,
    p90: f64,
    mean: f64,
}

fn stats(samples: &mut [u64]) -> Stats {
    samples.sort_unstable();
    let n = samples.len();
    let pct = |p: f64| samples[((n as f64 * p) as usize).min(n - 1)] as f64 / 1000.0;
    Stats {
        min: samples[0] as f64 / 1000.0,
        p50: pct(0.50),
        p90: pct(0.90),
        mean: samples.iter().sum::<u64>() as f64 / n as f64 / 1000.0,
    }
}

fn print_row(name: &str, s: &Stats, note: &str) {
    println!("{name:<24} {:>9.1} {:>9.1} {:>9.1} {:>9.1}   {note}", s.min, s.p50, s.p90, s.mean);
}

/// Warm up, then collect `iters` timed server-side handshakes.
fn bench_handshakes(
    name: &str,
    iters: usize,
    server_cfg: &Arc<ServerConfig>,
    client_cfg: impl Fn() -> Arc<ClientConfig>,
    expect_kind: HandshakeKind,
    expect_post_hs: bool,
) {
    let check = |s: &HandshakeSample| {
        assert_eq!(s.kind, Some(expect_kind), "{name}: unexpected handshake kind");
        assert_eq!(s.post_hs_bytes > 0, expect_post_hs, "{name}: post-handshake bytes = {}", s.post_hs_bytes);
    };
    for _ in 0..WARMUP {
        check(&run_handshake(server_cfg, &client_cfg()));
    }
    let mut samples = Vec::with_capacity(iters);
    let mut post_hs = 0usize;
    for _ in 0..iters {
        let s = run_handshake(server_cfg, &client_cfg());
        check(&s);
        post_hs = s.post_hs_bytes;
        samples.push(s.server_time.as_nanos() as u64);
    }
    print_row(name, &stats(&mut samples), &format!("{expect_kind:?}, {post_hs} post-hs bytes"));
}

/// Time `f` over `iters` calls after a warm-up.
fn bench_primitive(name: &str, iters: usize, mut f: impl FnMut()) {
    for _ in 0..WARMUP {
        f();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    print_row(name, &stats(&mut samples), "");
}

fn bench_primitives(iters: usize) {
    let rng = rand::SystemRandom::new();

    let peer = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).expect("peer key");
    let peer_pub = peer.compute_public_key().expect("peer pub");
    let peer_pub = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub.as_ref().to_vec());
    bench_primitive("x25519 keygen+agree", iters, || {
        let mine = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).expect("keygen");
        let _ = agreement::agree_ephemeral(mine, &peer_pub, aws_lc_rs::error::Unspecified, |secret| {
            Ok::<_, aws_lc_rs::error::Unspecified>(secret[0])
        })
        .expect("agree");
    });

    let (_, key) = load_cert_key();
    let PrivateKeyDer::Pkcs8(pkcs8) = key else {
        panic!("certs/server.key is not PKCS#8; adjust EcdsaKeyPair loading");
    };
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
    )
    .expect("ecdsa key pair");
    let msg = [0x5au8; 32];
    bench_primitive("ecdsa p256 sign", iters, || {
        let _ = key_pair.sign(&rng, &msg).expect("sign");
    });

    let mut out = [0u8; 32];
    bench_primitive("rng fill 32B", iters, || {
        rand::SecureRandom::fill(&rng, &mut out).expect("fill");
    });
}

fn main() {
    // Cargo appends `--bench` to the argv of harness-less benches; take the
    // first integer argument and ignore any flags.
    let iters = std::env::args()
        .skip(1)
        .find_map(|a| a.parse::<usize>().ok())
        .unwrap_or(DEFAULT_ITERS);

    println!("rustls TLS 1.3 QUIC server-side handshake cost, {iters} iters (+{WARMUP} warm-up), µs");
    println!("{:<24} {:>9} {:>9} {:>9} {:>9}", "scenario", "min", "p50", "p90", "mean");

    let prod = server_config(2);
    bench_handshakes("full", iters, &prod, client_config, HandshakeKind::Full, true);

    let no_tickets = server_config(0);
    bench_handshakes("full-tickets0", iters, &no_tickets, client_config, HandshakeKind::Full, false);

    let shared_client = client_config();
    let priming = run_handshake(&prod, &shared_client);
    assert_eq!(priming.kind, Some(HandshakeKind::Full));
    bench_handshakes("resumed", iters, &prod, || shared_client.clone(), HandshakeKind::Resumed, true);

    bench_primitives(iters);
}
