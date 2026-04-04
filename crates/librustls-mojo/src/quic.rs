#[no_mangle] pub extern "C" fn rlsm_initial_keys(_v: i32, _d: *const u8, _dl: i32, _c: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_initial_keys_raw(_v: i32, _d: *const u8, _dl: i32, _c: i32, _ok: *mut u8, _okl: *mut i32, _oi: *mut u8, _oil: *mut i32, _oh: *mut u8, _ohl: *mut i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_local_encrypt(_h: i32, _pn: u64, _hdr: *const u8, _hl: i32, _p: *mut u8, _pl: i32, _bc: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_remote_decrypt(_h: i32, _pn: u64, _hdr: *const u8, _hl: i32, _p: *mut u8, _pl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_local_header_protect(_h: i32, _s: *const u8, _sl: i32, _f: *mut u8, _pn: *mut u8, _pnl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_remote_header_unprotect(_h: i32, _s: *const u8, _sl: i32, _f: *mut u8, _pn: *mut u8, _pnl: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_tag_len(_h: i32) -> i32 { -1 }
#[no_mangle] pub extern "C" fn rlsm_keys_free(_h: i32) -> i32 { 0 }
