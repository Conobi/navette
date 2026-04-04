#[no_mangle] pub extern "C" fn rlsm_client_config_new() -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_server_config_new(_cp: *const u8, _cl: i32, _kp: *const u8, _kl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_config_free(_h: i32) -> i32 { 0 }
