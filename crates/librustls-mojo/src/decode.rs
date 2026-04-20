// Stateful streaming decoders for Content-Encoding (gzip, brotli).
// API: init -> feed (accumulate + decompress) -> finish (final decompress) -> free

use flate2::read::GzDecoder;
use std::io::Read;

struct GzipState {
    buf: Vec<u8>,
}

struct BrotliState {
    buf: Vec<u8>,
}

// --- Gzip ---

#[no_mangle]
pub extern "C" fn rlsm_gzip_init() -> *mut GzipState {
    Box::into_raw(Box::new(GzipState { buf: Vec::new() }))
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_gzip_feed(
    state: *mut GzipState,
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i64 {
    if state.is_null() || in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let state = unsafe { &mut *state };
    let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    state.buf.extend_from_slice(input);
    // Attempt to decompress from accumulated buffer
    let mut decoder = GzDecoder::new(state.buf.as_slice());
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };
    let mut total = 0usize;
    loop {
        match decoder.read(&mut out_slice[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                if total > 0 { break; }
                return 0; // not enough data yet, not an error
            }
        }
    }
    // Clear consumed data so finish() does not re-decompress
    if total > 0 {
        state.buf.clear();
    }
    total as i64
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_gzip_finish(
    state: *mut GzipState,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i64 {
    if state.is_null() || out_ptr.is_null() {
        return -1;
    }
    let state = unsafe { &*state };
    if state.buf.is_empty() {
        return 0;
    }
    let mut decoder = GzDecoder::new(state.buf.as_slice());
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };
    let mut total = 0usize;
    loop {
        match decoder.read(&mut out_slice[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                if total > 0 { break; }
                return -1;
            }
        }
    }
    total as i64
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_gzip_free(state: *mut GzipState) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state)); }
    }
}

// --- Brotli ---

#[no_mangle]
pub extern "C" fn rlsm_br_init() -> *mut BrotliState {
    Box::into_raw(Box::new(BrotliState { buf: Vec::new() }))
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_br_feed(
    state: *mut BrotliState,
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i64 {
    if state.is_null() || in_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let state = unsafe { &mut *state };
    let input = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    state.buf.extend_from_slice(input);
    let mut decoder = brotli::Decompressor::new(state.buf.as_slice(), 4096);
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };
    let mut total = 0usize;
    loop {
        match decoder.read(&mut out_slice[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                if total > 0 { break; }
                return 0;
            }
        }
    }
    // Clear consumed data so finish() does not re-decompress
    if total > 0 {
        state.buf.clear();
    }
    total as i64
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_br_finish(
    state: *mut BrotliState,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i64 {
    if state.is_null() || out_ptr.is_null() {
        return -1;
    }
    let state = unsafe { &*state };
    if state.buf.is_empty() {
        return 0;
    }
    let mut decoder = brotli::Decompressor::new(state.buf.as_slice(), 4096);
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out_ptr, out_cap) };
    let mut total = 0usize;
    loop {
        match decoder.read(&mut out_slice[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => {
                if total > 0 { break; }
                return -1;
            }
        }
    }
    total as i64
}

#[no_mangle]
pub unsafe extern "C" fn rlsm_br_free(state: *mut BrotliState) {
    if !state.is_null() {
        unsafe { drop(Box::from_raw(state)); }
    }
}
