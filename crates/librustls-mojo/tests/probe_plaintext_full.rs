//! Probe: smallest server→client transcript that the FFI `read_tls`
//! rejects with "received plaintext buffer full" when fed in one call.
//!
//! Run: cargo test --features insecure --test probe_plaintext_full -- --nocapture --test-threads=1
//! Prints `PIN min_shape_a_plaintext=<N> layout=[..]`; the layout (not the
//! total) is what tests/_split_harness.mojo pins.

#[cfg(feature = "insecure")]
mod probe {
    use librustls_mojo::*;
    use std::io::Write as _;
    use std::sync::Arc;

    extern "C" {
        fn rlsm_tls_client_new(config_handle: i32, sn_ptr: *const u8, sn_len: i32) -> i32;
        fn rlsm_tls_conn_free(handle: i32) -> i32;
        fn rlsm_tls_conn_read_tls(handle: i32, ct_ptr: *const u8, ct_len: i32, stop_out: *mut i32) -> i32;
        fn rlsm_tls_conn_write_tls(handle: i32, out_buf: *mut u8, buf_len: i32) -> i32;
        fn rlsm_client_config_new_insecure() -> i32;
        fn rlsm_config_free(handle: i32) -> i32;
    }

    fn last_error_str() -> String {
        let mut buf = vec![0u8; 512];
        let n = rlsm_last_error(buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 { return String::from("<no error>"); }
        String::from_utf8_lossy(&buf[..(n as usize) - 1]).into_owned()
    }

    /// Feed `ct` to the FFI client in one call; Err carries the shim's message.
    pub fn feed(client: i32, ct: &[u8]) -> Result<i32, String> {
        let mut stop = 0i32;
        let rc = unsafe { rlsm_tls_conn_read_tls(client, ct.as_ptr(), ct.len() as i32, &mut stop) };
        if rc < 0 { Err(last_error_str()) } else { Ok(rc) }
    }

    pub fn native_server() -> rustls::ServerConnection {
        let certs = rustls_pemfile::certs(&mut &include_bytes!("../testdata/server.crt")[..])
            .collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pemfile::private_key(&mut &include_bytes!("../testdata/server.key")[..])
            .unwrap().unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth().with_single_cert(certs, key).unwrap();
        rustls::ServerConnection::new(Arc::new(cfg)).unwrap()
    }

    /// FFI client handshaked against a native server.
    pub fn pair() -> (i32, rustls::ServerConnection) {
        let cfg = unsafe { rlsm_client_config_new_insecure() };
        let sn = b"localhost";
        let client = unsafe { rlsm_tls_client_new(cfg, sn.as_ptr(), sn.len() as i32) };
        assert!(client > 0, "client: {}", last_error_str());
        // The connection keeps its own reference to the config.
        assert_eq!(unsafe { rlsm_config_free(cfg) }, 0, "config free: {}", last_error_str());
        let mut server = native_server();
        for _ in 0..20 {
            let mut buf = vec![0u8; 65536];
            let n = unsafe { rlsm_tls_conn_write_tls(client, buf.as_mut_ptr(), buf.len() as i32) };
            if n > 0 {
                server.read_tls(&mut &buf[..n as usize]).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut out = Vec::new();
            server.write_tls(&mut out).unwrap();
            if !out.is_empty() { feed(client, &out).unwrap(); }
            if !server.is_handshaking() && n == 0 && out.is_empty() { break; }
        }
        assert!(!server.is_handshaking(), "handshake did not finish");
        (client, server)
    }

    /// Ciphertext of one record per entry of `records` (plaintext sizes).
    pub fn transcript(server: &mut rustls::ServerConnection, records: &[usize]) -> Vec<u8> {
        let mut out = Vec::new();
        for &n in records {
            server.writer().write_all(&vec![0x61u8; n]).unwrap();
            server.write_tls(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn probe_smallest_failing_transcript() {
        let mut min_fail: Option<(usize, Vec<usize>)> = None;
        for tail in [1usize, 64, 512, 1024, 2048, 4096, 4097, 8192, 16384] {
            for n_small in 1..=8usize {
                let mut records = vec![16384usize];
                records.extend(std::iter::repeat(tail).take(n_small));
                let total: usize = records.iter().sum();
                let (client, mut server) = pair();
                let ct = transcript(&mut server, &records);
                let res = feed(client, &ct);
                unsafe { rlsm_tls_conn_free(client); }
                if let Err(msg) = res {
                    println!("FAIL total={total} records={records:?} err={msg}");
                    if min_fail.as_ref().map_or(true, |(m, _)| total < *m) {
                        min_fail = Some((total, records.clone()));
                    }
                }
            }
        }
        match min_fail {
            Some((n, layout)) => println!("PIN min_shape_a_plaintext={n} layout={layout:?}"),
            None => println!("PIN none: no layout failed (shape (a) not reproduced)"),
        }
    }
}
