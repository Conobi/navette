#[no_mangle] pub extern "C" fn rlsm_tls_client_new(_ch: i32, _sn: *const u8, _snl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_server_new(_ch: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_free(_h: i32) -> i32 { 0 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_read_tls(_h: i32, _ct: *const u8, _cl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_write_tls(_h: i32, _ob: *mut u8, _bl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_read_plaintext(_h: i32, _ob: *mut u8, _bl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_write_plaintext(_h: i32, _d: *const u8, _dl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_is_handshaking(_h: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_tls_conn_alpn(_h: i32, _ob: *mut u8, _bl: i32) -> i32 { -1 }
