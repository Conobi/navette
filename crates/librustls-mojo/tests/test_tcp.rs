//! Integration test for Task 6: TCP-TLS connection lifecycle.
//!
//! Performs an in-process client↔server TLS handshake and a data round-trip
//! using the BYO-transport (slice-based) API.
//!
//! Build and run with:
//!   cargo test --features insecure --test test_tcp

#[cfg(feature = "insecure")]
mod tcp_tests {
    use librustls_mojo::*;

    extern "C" {
        fn rlsm_tls_client_new(config_handle: i32, sn_ptr: *const u8, sn_len: i32) -> i32;
        fn rlsm_tls_server_new(config_handle: i32) -> i32;
        fn rlsm_tls_conn_free(handle: i32) -> i32;
        fn rlsm_tls_conn_read_tls(handle: i32, ct_ptr: *const u8, ct_len: i32) -> i32;
        fn rlsm_tls_conn_write_tls(handle: i32, out_buf: *mut u8, buf_len: i32) -> i32;
        fn rlsm_tls_conn_read_plaintext(handle: i32, out_buf: *mut u8, buf_len: i32) -> i32;
        fn rlsm_tls_conn_write_plaintext(handle: i32, data_ptr: *const u8, data_len: i32) -> i32;
        fn rlsm_tls_conn_is_handshaking(handle: i32) -> i32;
        fn rlsm_server_config_new(
            cert_pem: *const u8,
            cert_len: i32,
            key_pem: *const u8,
            key_len: i32,
        ) -> i32;
        fn rlsm_client_config_new_insecure() -> i32;
        fn rlsm_config_free(handle: i32) -> i32;
    }

    fn last_error_str() -> String {
        let mut buf = vec![0u8; 512];
        let n = rlsm_last_error(buf.as_mut_ptr(), buf.len() as i32);
        if n <= 0 {
            return String::from("<no error>");
        }
        let s = &buf[..(n as usize) - 1]; // strip NUL
        String::from_utf8_lossy(s).into_owned()
    }

    /// Shuttle ciphertext from `src` to `dst` through an intermediate buffer.
    /// Returns the number of bytes transferred.
    fn shuttle(src: i32, dst: i32) -> usize {
        let mut buf = vec![0u8; 65536];
        let written = unsafe {
            rlsm_tls_conn_write_tls(src, buf.as_mut_ptr(), buf.len() as i32)
        };
        assert!(written >= 0, "write_tls failed: {}", last_error_str());
        if written == 0 {
            return 0;
        }
        let consumed = unsafe {
            rlsm_tls_conn_read_tls(dst, buf.as_ptr(), written)
        };
        assert!(consumed >= 0, "read_tls failed: {}", last_error_str());
        written as usize
    }

    #[test]
    fn handshake_and_data_transfer() {
        // ---- load test certificates ----
        let cert_pem = include_bytes!("../testdata/server.crt");
        let key_pem = include_bytes!("../testdata/server.key");

        // ---- create configs ----
        let srv_cfg = unsafe {
            rlsm_server_config_new(
                cert_pem.as_ptr(),
                cert_pem.len() as i32,
                key_pem.as_ptr(),
                key_pem.len() as i32,
            )
        };
        assert!(srv_cfg > 0, "server config: {}", last_error_str());

        let cli_cfg = unsafe { rlsm_client_config_new_insecure() };
        assert!(cli_cfg > 0, "client config: {}", last_error_str());

        // ---- create connections ----
        let server_name = b"localhost";
        let cli = unsafe {
            rlsm_tls_client_new(cli_cfg, server_name.as_ptr(), server_name.len() as i32)
        };
        assert!(cli > 0, "client conn: {}", last_error_str());

        let srv = unsafe { rlsm_tls_server_new(srv_cfg) };
        assert!(srv > 0, "server conn: {}", last_error_str());

        // ---- run the handshake ----
        // Client sends ClientHello; keep shuttling until both sides are done.
        let mut iterations = 0usize;
        loop {
            let cli_hs = unsafe { rlsm_tls_conn_is_handshaking(cli) };
            let srv_hs = unsafe { rlsm_tls_conn_is_handshaking(srv) };
            assert!(cli_hs >= 0, "is_handshaking (cli): {}", last_error_str());
            assert!(srv_hs >= 0, "is_handshaking (srv): {}", last_error_str());

            if cli_hs == 0 && srv_hs == 0 {
                break;
            }

            // client → server
            let c2s = shuttle(cli, srv);
            // server → client
            let s2c = shuttle(srv, cli);

            if c2s == 0 && s2c == 0 {
                // Nothing moved but handshake is not done — something is wrong.
                panic!(
                    "handshake stalled after {} iterations (cli_hs={cli_hs}, srv_hs={srv_hs})",
                    iterations
                );
            }

            iterations += 1;
            assert!(iterations < 100, "handshake did not complete in 100 iterations");
        }

        // ---- client writes plaintext ----
        let msg = b"Hello from Mojo!";
        let written = unsafe {
            rlsm_tls_conn_write_plaintext(cli, msg.as_ptr(), msg.len() as i32)
        };
        assert_eq!(written, msg.len() as i32, "write_plaintext: {}", last_error_str());

        // Shuttle encrypted data from client to server
        shuttle(cli, srv);

        // ---- server reads plaintext ----
        let mut rx_buf = vec![0u8; 256];
        let read = unsafe {
            rlsm_tls_conn_read_plaintext(srv, rx_buf.as_mut_ptr(), rx_buf.len() as i32)
        };
        assert!(read > 0, "read_plaintext returned {read}: {}", last_error_str());
        assert_eq!(&rx_buf[..read as usize], msg);

        // ---- cleanup ----
        assert_eq!(unsafe { rlsm_tls_conn_free(cli) }, 0);
        assert_eq!(unsafe { rlsm_tls_conn_free(srv) }, 0);
        assert_eq!(unsafe { rlsm_config_free(cli_cfg) }, 0);
        assert_eq!(unsafe { rlsm_config_free(srv_cfg) }, 0);
    }

    #[test]
    fn free_invalid_handle_returns_minus_one() {
        let ret = unsafe { rlsm_tls_conn_free(99999) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn client_new_invalid_config_returns_minus_one() {
        let name = b"localhost";
        let ret = unsafe {
            rlsm_tls_client_new(99999, name.as_ptr(), name.len() as i32)
        };
        assert_eq!(ret, -1);
    }

    #[test]
    fn server_new_invalid_config_returns_minus_one() {
        let ret = unsafe { rlsm_tls_server_new(99999) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn read_tls_null_pointer_returns_minus_one() {
        let ret = unsafe { rlsm_tls_conn_read_tls(1, std::ptr::null(), 10) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn write_tls_null_pointer_returns_minus_one() {
        let ret = unsafe { rlsm_tls_conn_write_tls(1, std::ptr::null_mut(), 10) };
        assert_eq!(ret, -1);
    }

    #[test]
    fn is_handshaking_invalid_handle_returns_minus_one() {
        let ret = unsafe { rlsm_tls_conn_is_handshaking(99999) };
        assert_eq!(ret, -1);
    }
}
