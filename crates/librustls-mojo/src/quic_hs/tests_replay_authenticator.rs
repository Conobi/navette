//! FFI replay-authenticator unit tests.
//!
//! Covers the simplified `ffi-*` acceptance criteria: ClientHello.random
//! capture once + HRR-only-first, stable across verbatim replay, changes
//! on fresh client random, unavailable before any ClientHello prefix has
//! been captured, and output-shape (32 bytes, not all-zero, stable
//! across multiple read-only invocations).

use rustls::quic::{ServerConnection, Version as QuicVersion};
use std::sync::Arc;

use super::tests::gen_test_cert;
use super::tests_resumption_fixture::drive_full_handshake_with_resumption;
use super::{
    quic_conn_table, quic_server_cfg_table,
    rlsm_quic_server_conn_replay_authenticator,
    rlsm_quic_server_config_new, rlsm_quic_conn_free,
    QuicConn, QuicConnEntry,
};

fn build_server_config_via_ffi() -> Arc<rustls::server::ServerConfig> {
    let (cert_pem, key_pem, _cert_der) = gen_test_cert();
    let alpn = b"h3";
    let mut out_handle: i32 = -1;
    let rc = rlsm_quic_server_config_new(
        cert_pem.as_ptr(), cert_pem.len() as i32,
        key_pem.as_ptr(), key_pem.len() as i32,
        alpn.as_ptr(), alpn.len() as i32,
        u32::MAX,
        &mut out_handle,
    );
    assert_eq!(rc, 0, "rlsm_quic_server_config_new must succeed");
    assert!(out_handle > 0);
    quic_server_cfg_table()
        .with(out_handle, |cfg: &Arc<rustls::server::ServerConfig>| cfg.clone())
        .expect("config handle must exist")
}

#[test]
fn test_ffi_replay_authenticator_unavailable_before_client_hello() {
    // No read_hs ever called → client_random_captured = false → rc=1.
    let cfg = build_server_config_via_ffi();
    let server = ServerConnection::new(cfg, QuicVersion::V1, Vec::new())
        .expect("ServerConnection::new");
    let entry = QuicConnEntry {
        conn: QuicConn::Server(server),
        pending: None,
        next_secrets: None,
        alert_cache: None,
        first_ch_prefix: [0u8; 38],
        first_ch_prefix_len: 0,
        client_random_captured: false,
        client_random: [0u8; 32],
    };
    let h = quic_conn_table().insert(entry).expect("insert");

    let mut buf = [0u8; 32];
    let mut out_len: usize = 999;
    let rc = rlsm_quic_server_conn_replay_authenticator(
        h, buf.as_mut_ptr(), &mut out_len,
    );
    assert_eq!(rc, 1, "no client_random captured yet -> rc=1");
    assert_eq!(out_len, 0, "out_len must be 0 on rc != 0");

    let _ = rlsm_quic_conn_free(h);
}

#[test]
fn test_ffi_replay_authenticator_stable_across_verbatim_replay() {
    // Drive the resumption fixture once; probe the authenticator twice
    // on the same connection. Bytes MUST be identical.
    let (server_h, client_h) = drive_full_handshake_with_resumption();

    let mut buf1 = [0u8; 32];
    let mut len1: usize = 0;
    let rc1 = rlsm_quic_server_conn_replay_authenticator(
        server_h, buf1.as_mut_ptr(), &mut len1,
    );
    assert_eq!(rc1, 0, "first read must succeed on captured-random conn");
    assert_eq!(len1, 32);

    let mut buf2 = [0u8; 32];
    let mut len2: usize = 0;
    let rc2 = rlsm_quic_server_conn_replay_authenticator(
        server_h, buf2.as_mut_ptr(), &mut len2,
    );
    assert_eq!(rc2, 0, "second read must also succeed");
    assert_eq!(len2, 32);
    assert_eq!(buf1, buf2, "two reads of the same conn yield identical bytes");

    let _ = rlsm_quic_conn_free(server_h);
    let _ = rlsm_quic_conn_free(client_h);
}

#[test]
fn test_ffi_replay_authenticator_output_shape() {
    let (server_h, client_h) = drive_full_handshake_with_resumption();

    let mut buf = [0u8; 32];
    let mut len: usize = 0;
    let rc = rlsm_quic_server_conn_replay_authenticator(
        server_h, buf.as_mut_ptr(), &mut len,
    );
    assert_eq!(rc, 0);
    assert_eq!(len, 32);
    let all_zero = buf.iter().all(|b| *b == 0);
    assert!(!all_zero, "client_random must not be all-zero");

    let _ = rlsm_quic_conn_free(server_h);
    let _ = rlsm_quic_conn_free(client_h);
}

#[test]
fn test_ffi_replay_authenticator_changes_on_fresh_client_random() {
    // Two independent fixture drives produce DIFFERENT ClientHello.randoms
    // (rustls generates a fresh one per ClientConnection::new). Authenticators
    // MUST differ.
    let (s1, c1) = drive_full_handshake_with_resumption();
    let (s2, c2) = drive_full_handshake_with_resumption();
    let mut b1 = [0u8; 32];
    let mut b2 = [0u8; 32];
    let mut l1: usize = 0;
    let mut l2: usize = 0;
    assert_eq!(
        rlsm_quic_server_conn_replay_authenticator(s1, b1.as_mut_ptr(), &mut l1),
        0
    );
    assert_eq!(
        rlsm_quic_server_conn_replay_authenticator(s2, b2.as_mut_ptr(), &mut l2),
        0
    );
    assert_ne!(b1, b2, "independent resumptions produce distinct authenticators");
    let _ = rlsm_quic_conn_free(s1); let _ = rlsm_quic_conn_free(c1);
    let _ = rlsm_quic_conn_free(s2); let _ = rlsm_quic_conn_free(c2);
}

#[test]
fn test_ffi_client_random_captured_on_first_read_hs() {
    // After drive_full_handshake_with_resumption, the server connection
    // has client_random_captured = true and a non-zero 32-byte client_random.
    let (server_h, client_h) = drive_full_handshake_with_resumption();

    let probe = quic_conn_table()
        .with(server_h, |entry: &QuicConnEntry| {
            (entry.client_random_captured, entry.client_random)
        })
        .expect("server handle must exist");
    assert!(probe.0, "client_random_captured must be true after read_hs");
    assert!(probe.1.iter().any(|b| *b != 0), "client_random must not be all-zero");

    let _ = rlsm_quic_conn_free(server_h);
    let _ = rlsm_quic_conn_free(client_h);
}

#[test]
fn test_ffi_client_random_captured_on_first_clienthello_only() {
    // After the random is captured, feeding another 38-byte buffer starting
    // with 0x01 (a synthetic HRR-second-CH) MUST NOT overwrite the captured
    // client_random.
    let (server_h, client_h) = drive_full_handshake_with_resumption();

    let original = quic_conn_table()
        .with(server_h, |entry: &QuicConnEntry| entry.client_random)
        .expect("server handle must exist");

    // Synthetic second CH: handshake_type=0x01, length=34, legacy_version=0x0303, random=32 0xAB bytes.
    let mut synthetic = vec![0u8; 38];
    synthetic[0] = 0x01;
    synthetic[1] = 0x00; synthetic[2] = 0x00; synthetic[3] = 0x22;
    synthetic[4] = 0x03; synthetic[5] = 0x03;
    for i in 0..32 {
        synthetic[6 + i] = 0xAB;
    }

    let mut sm_us: u64 = 0;
    let mut lk_us: u64 = 0;
    let _rc = super::rlsm_quic_conn_read_hs(
        server_h,
        synthetic.as_ptr(),
        synthetic.len() as i32,
        &mut sm_us,
        &mut lk_us,
    );
    // _rc may be -1 (rustls protocol error); irrelevant. The invariant is
    // on the captured field state.

    let after = quic_conn_table()
        .with(server_h, |entry: &QuicConnEntry| entry.client_random)
        .expect("server handle must exist");
    assert_eq!(
        after, original,
        "HRR-scenario synthetic CH must NOT overwrite the first-captured random"
    );

    let _ = rlsm_quic_conn_free(server_h);
    let _ = rlsm_quic_conn_free(client_h);
}

#[test]
fn test_ffi_client_random_captured_handles_fragmented_first_read_hs() {
    // Feed a server connection two partial CRYPTO chunks (5 bytes + 33 bytes)
    // simulating RFC 9000 §7.5 fragmentation. After the second read_hs, the
    // sticky accumulator has 38 bytes and client_random_captured = true.
    let cfg = build_server_config_via_ffi();
    let server = ServerConnection::new(cfg, QuicVersion::V1, Vec::new())
        .expect("ServerConnection::new");
    let entry = QuicConnEntry {
        conn: QuicConn::Server(server),
        pending: None,
        next_secrets: None,
        alert_cache: None,
        first_ch_prefix: [0u8; 38],
        first_ch_prefix_len: 0,
        client_random_captured: false,
        client_random: [0u8; 32],
    };
    let h = quic_conn_table().insert(entry).expect("insert");

    // Build a valid 38-byte ClientHello prefix:
    //   [0x01, 0x00, 0x00, 0x22, 0x03, 0x03, <32 fresh bytes>]
    let mut full = vec![0u8; 38];
    full[0] = 0x01;
    full[1] = 0x00; full[2] = 0x00; full[3] = 0x22;
    full[4] = 0x03; full[5] = 0x03;
    for i in 0..32 {
        full[6 + i] = (i as u8).wrapping_add(0x40);
    }

    // First read_hs: bytes 0..5 (5 bytes).
    let mut sm_us: u64 = 0;
    let mut lk_us: u64 = 0;
    let _rc1 = super::rlsm_quic_conn_read_hs(
        h, full[0..5].as_ptr(), 5, &mut sm_us, &mut lk_us,
    );

    // After first read_hs: accumulator has 5 bytes, not yet captured.
    let probe1 = quic_conn_table()
        .with(h, |e: &QuicConnEntry| (e.first_ch_prefix_len, e.client_random_captured))
        .expect("handle exists");
    assert_eq!(probe1.0, 5);
    assert!(!probe1.1, "5 bytes is below the 38-byte threshold");

    // Second read_hs: bytes 5..38 (33 bytes).
    let _rc2 = super::rlsm_quic_conn_read_hs(
        h, full[5..38].as_ptr(), 33, &mut sm_us, &mut lk_us,
    );

    // After second read_hs: accumulator has 38 bytes, capture fired.
    let probe2 = quic_conn_table()
        .with(h, |e: &QuicConnEntry| (e.first_ch_prefix_len, e.client_random_captured, e.client_random))
        .expect("handle exists");
    assert_eq!(probe2.0, 38);
    assert!(probe2.1, "38 bytes accumulated -> capture must fire");
    let expected: Vec<u8> = (0..32u8).map(|i| i.wrapping_add(0x40)).collect();
    assert_eq!(&probe2.2[..], &expected[..], "captured random must equal bytes 6..38 of the assembled CH");

    let _ = rlsm_quic_conn_free(h);
}
