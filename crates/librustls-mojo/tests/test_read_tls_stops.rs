//! read_tls stop reasons, entry check, close_notify placement and read_eof,
//! with a native rustls server as the peer of the FFI client.
//! cargo test --features insecure --test test_read_tls_stops -- --test-threads=1

#[cfg(feature = "insecure")]
mod stops {
    use librustls_mojo::*;
    use std::io::Write as _;
    use std::sync::Arc;

    const COMPLETE: i32 = 0;
    const NEEDS_DRAIN: i32 = 1;
    const PEER_CLOSED: i32 = 3;
    /// Failing shape-(a) record LAYOUT printed by probe_plaintext_full.rs
    /// (the total alone does not fail on main; this layout does).
    const PINNED_LAYOUT_A: [usize; 5] = [16384, 512, 512, 512, 512];

    extern "C" {
        fn rlsm_tls_client_new(config_handle: i32, sn_ptr: *const u8, sn_len: i32) -> i32;
        fn rlsm_tls_conn_read_tls(handle: i32, ct_ptr: *const u8, ct_len: i32, stop_out: *mut i32) -> i32;
        fn rlsm_tls_conn_write_tls(handle: i32, out_buf: *mut u8, buf_len: i32) -> i32;
        fn rlsm_tls_conn_read_plaintext(handle: i32, out_buf: *mut u8, buf_len: i32) -> i32;
        fn rlsm_tls_conn_read_eof(handle: i32, stop_out: *mut i32) -> i32;
        fn rlsm_client_config_new_insecure() -> i32;
    }

    fn last_error_str() -> String {
        let mut buf = vec![0u8; 512];
        let n = rlsm_last_error(buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 { return String::from("<no error>"); }
        String::from_utf8_lossy(&buf[..(n as usize) - 1]).into_owned()
    }

    fn feed(client: i32, ct: &[u8]) -> (i32, i32) {
        let mut stop = -1i32;
        let rc = unsafe { rlsm_tls_conn_read_tls(client, ct.as_ptr(), ct.len() as i32, &mut stop) };
        (rc, stop)
    }

    fn drain(client: i32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 16384];
        loop {
            let n = unsafe { rlsm_tls_conn_read_plaintext(client, buf.as_mut_ptr(), buf.len() as i32) };
            assert!(n >= 0, "read_plaintext failed: {}", last_error_str());
            if n == 0 { return out; }
            out.extend_from_slice(&buf[..n as usize]);
        }
    }

    fn pair() -> (i32, rustls::ServerConnection) {
        let certs = rustls_pemfile::certs(&mut &include_bytes!("../testdata/server.crt")[..])
            .collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pemfile::private_key(&mut &include_bytes!("../testdata/server.key")[..])
            .unwrap().unwrap();
        let cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
        let ccfg = unsafe { rlsm_client_config_new_insecure() };
        let sn = b"localhost";
        let client = unsafe { rlsm_tls_client_new(ccfg, sn.as_ptr(), sn.len() as i32) };
        assert!(client > 0, "client: {}", last_error_str());
        for _ in 0..20 {
            let mut buf = vec![0u8; 65536];
            let n = unsafe { rlsm_tls_conn_write_tls(client, buf.as_mut_ptr(), buf.len() as i32) };
            if n > 0 { server.read_tls(&mut &buf[..n as usize]).unwrap(); server.process_new_packets().unwrap(); }
            let mut out = Vec::new();
            server.write_tls(&mut out).unwrap();
            if !out.is_empty() { let (rc, _) = feed(client, &out); assert!(rc >= 0, "{}", last_error_str()); }
            if !server.is_handshaking() && n == 0 && out.is_empty() { break; }
        }
        assert!(!server.is_handshaking(), "handshake did not finish");
        (client, server)
    }

    fn records(server: &mut rustls::ServerConnection, sizes: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for &n in sizes {
            server.writer().write_all(&vec![0x62u8; n]).unwrap();
            server.write_tls(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn close_notify_as_last_record_reports_peer_closed() {
        let (client, mut server) = pair();
        let mut ct = records(&mut server, &[100]);
        server.send_close_notify();
        server.write_tls(&mut ct).unwrap();
        let (rc, stop) = feed(client, &ct);
        assert_eq!(rc as usize, ct.len());
        assert_eq!(stop, PEER_CLOSED);
        assert_eq!(drain(client).len(), 100);
    }

    #[test]
    fn close_notify_mid_chunk_ignores_bytes_after() {
        let (client, mut server) = pair();
        let mut ct = records(&mut server, &[100]);
        server.send_close_notify();
        server.write_tls(&mut ct).unwrap();
        let close_end = ct.len();
        ct.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
        let (rc, stop) = feed(client, &ct);
        assert_eq!(stop, PEER_CLOSED);
        assert!(rc as usize <= ct.len() && rc as usize >= close_end - 5);
        assert_eq!(drain(client).len(), 100);
    }

    #[test]
    fn close_notify_beats_needs_drain() {
        let (client, mut server) = pair();
        let mut ct = records(&mut server, &[16384, 16384]);
        server.send_close_notify();
        server.write_tls(&mut ct).unwrap();
        let mut off = 0usize;
        let mut got = 0usize;
        let mut last = COMPLETE;
        for _ in 0..100 {
            let (rc, stop) = feed(client, &ct[off..]);
            assert!(rc >= 0, "{}", last_error_str());
            off += rc as usize;
            last = stop;
            if stop == PEER_CLOSED { break; }
            if stop == NEEDS_DRAIN { got += drain(client).len(); }
            if off == ct.len() && stop == COMPLETE { break; }
        }
        assert_eq!(last, PEER_CLOSED);
        got += drain(client).len();
        assert_eq!(got, 32768, "plaintext before close_notify is kept");
    }

    #[test]
    fn pinned_shape_a_size_succeeds_with_drain_stop() {
        let (client, mut server) = pair();
        let ct = records(&mut server, &PINNED_LAYOUT_A);
        let mut off = 0usize;
        let mut got = 0usize;
        let mut saw_drain = false;
        for _ in 0..100 {
            let (rc, stop) = feed(client, &ct[off..]);
            assert!(rc >= 0, "pinned size must not error: {}", last_error_str());
            off += rc as usize;
            saw_drain |= stop == NEEDS_DRAIN;
            got += drain(client).len();
            if off == ct.len() && stop != NEEDS_DRAIN { break; }
        }
        got += drain(client).len();
        assert!(saw_drain, "pinned layout must hit the drain stop");
        assert_eq!(got, PINNED_LAYOUT_A.iter().sum::<usize>());
    }

    #[test]
    fn entry_check_stops_before_reading() {
        let (client, mut server) = pair();
        let first = records(&mut server, &[16384, 200]);
        let second = records(&mut server, &[10]);
        let (rc1, stop1) = feed(client, &first);
        assert_eq!(rc1 as usize, first.len());
        assert_eq!(stop1, NEEDS_DRAIN);
        let (rc2, stop2) = feed(client, &second);
        assert_eq!(rc2, 0);
        assert_eq!(stop2, NEEDS_DRAIN);
    }

    #[test]
    fn read_eof_after_drain_reports_unclean() {
        let (client, mut server) = pair();
        let ct = records(&mut server, &[50]);
        let _ = feed(client, &ct);
        assert_eq!(drain(client).len(), 50);
        let mut stop = -1;
        assert_eq!(unsafe { rlsm_tls_conn_read_eof(client, &mut stop) }, 0);
        assert_eq!(stop, COMPLETE, "bare EOF is not a clean close");
        assert_eq!(drain(client).len(), 0, "UnexpectedEof drains as 0, not an error");
    }

    #[test]
    fn read_eof_after_close_notify_reports_peer_closed() {
        let (client, mut server) = pair();
        let mut ct = records(&mut server, &[50]);
        server.send_close_notify();
        server.write_tls(&mut ct).unwrap();
        let _ = feed(client, &ct);
        assert_eq!(drain(client).len(), 50);
        let mut stop = -1;
        assert_eq!(unsafe { rlsm_tls_conn_read_eof(client, &mut stop) }, 0);
        assert_eq!(stop, PEER_CLOSED);
    }
}
