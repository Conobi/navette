//! libcompress-mojo: thin C shim over system zlib + libbrotlidec.
//!
//! All FFI logic lives in the C sources compiled by build.rs (see
//! specs/2026-05-17-compress-shim-split.md). The Rust side is just
//! the link glue:
//!   - build.rs emits `cargo:rustc-link-lib=static:+whole-archive=
//!     compress_wrappers` so the .o files are linked unconditionally,
//!   - build.rs layers `--version-script=lcm_export.ver` over rustc's
//!     default cdylib version script so the lcm_* symbols land in
//!     .dynsym (rustc's script otherwise hides every C symbol).
//!
//! Unit tests below exercise the wrappers via raw FFI; they live in
//! lib.rs (not tests/) because the static archive's symbols don't
//! propagate cleanly to integration-test binaries.

#[cfg(test)]
mod tests {
    use core::ffi::{c_int, c_void};

    // gzip.compress(b"hello world") with mtime=0 — same fixture as
    // tests/test_decode.mojo:_make_gzip_hello_world.
    const GZIP_HELLO: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 203, 72, 205, 201, 201, 87,
        40, 207, 47, 202, 73, 1, 0, 133, 17, 74, 13, 11, 0, 0, 0,
    ];

    // brotli.compress(b"hello world") — same fixture as
    // tests/test_decode.mojo:_make_brotli_hello_world.
    const BROTLI_HELLO: &[u8] = &[
        11, 5, 128, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 3,
    ];

    extern "C" {
        fn lcm_gzip_init(input_cap: u64, output_cap: u64, ratio_x100: u32) -> *mut c_void;
        fn lcm_gzip_feed(s: *mut c_void, in_ptr: *const u8, in_len: usize,
                         out_ptr: *mut u8, out_cap: usize) -> i64;
        fn lcm_gzip_finish(s: *mut c_void, out_ptr: *mut u8, out_cap: usize) -> i64;
        fn lcm_gzip_free(s: *mut c_void);

        fn lcm_br_init(input_cap: u64, output_cap: u64, ratio_x100: u32) -> *mut c_void;
        fn lcm_br_feed(s: *mut c_void, in_ptr: *const u8, in_len: usize,
                       out_ptr: *mut u8, out_cap: usize) -> i64;
        fn lcm_br_finish(s: *mut c_void, out_ptr: *mut u8, out_cap: usize) -> i64;
        fn lcm_br_free(s: *mut c_void);

        fn lcm_last_error(out_buf: *mut u8, buf_len: c_int) -> c_int;
    }

    fn last_error_string() -> String {
        let mut buf = [0u8; 512];
        unsafe {
            let n = lcm_last_error(buf.as_mut_ptr(), buf.len() as c_int);
            if n <= 0 { return String::new(); }
            String::from_utf8_lossy(&buf[..(n as usize - 1)]).into_owned()
        }
    }

    #[test]
    fn gzip_round_trip_hello_world() {
        unsafe {
            let s = lcm_gzip_init(1 << 20, 1 << 20, 0);
            assert!(!s.is_null());
            let mut out = [0u8; 64];
            let n = lcm_gzip_feed(s, GZIP_HELLO.as_ptr(), GZIP_HELLO.len(),
                                  out.as_mut_ptr(), out.len());
            assert!(n >= 0, "feed: {} ({:?})", n, last_error_string());
            let tail = lcm_gzip_finish(s, out.as_mut_ptr().add(n as usize),
                                       out.len() - n as usize);
            assert!(tail >= 0, "finish: {} ({:?})", tail, last_error_string());
            assert_eq!(&out[..(n + tail) as usize], b"hello world");
            lcm_gzip_free(s);
        }
    }

    #[test]
    fn brotli_round_trip_hello_world() {
        unsafe {
            let s = lcm_br_init(1 << 20, 1 << 20, 0);
            assert!(!s.is_null());
            let mut out = [0u8; 64];
            let n = lcm_br_feed(s, BROTLI_HELLO.as_ptr(), BROTLI_HELLO.len(),
                                out.as_mut_ptr(), out.len());
            assert!(n >= 0, "feed: {} ({:?})", n, last_error_string());
            let tail = lcm_br_finish(s, out.as_mut_ptr().add(n as usize),
                                     out.len() - n as usize);
            assert!(tail >= 0, "finish: {} ({:?})", tail, last_error_string());
            assert_eq!(&out[..(n + tail) as usize], b"hello world");
            lcm_br_free(s);
        }
    }

    #[test]
    fn gzip_input_cap_rejects_oversized_feed() {
        unsafe {
            let s = lcm_gzip_init(8, 1 << 20, 0);
            assert!(!s.is_null());
            let mut out = [0u8; 64];
            let n = lcm_gzip_feed(s, GZIP_HELLO.as_ptr(), GZIP_HELLO.len(),
                                  out.as_mut_ptr(), out.len());
            assert_eq!(n, -2, "expected -2 (input cap), got {}", n);
            assert!(last_error_string().contains("input cap"));
            lcm_gzip_free(s);
        }
    }

    #[test]
    fn brotli_input_cap_rejects_oversized_feed() {
        unsafe {
            let s = lcm_br_init(4, 1 << 20, 0);
            assert!(!s.is_null());
            let mut out = [0u8; 64];
            let n = lcm_br_feed(s, BROTLI_HELLO.as_ptr(), BROTLI_HELLO.len(),
                                out.as_mut_ptr(), out.len());
            assert_eq!(n, -2, "expected -2 (input cap), got {}", n);
            lcm_br_free(s);
        }
    }
}

