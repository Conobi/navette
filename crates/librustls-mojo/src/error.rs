//! Thread-local last-error storage.
//!
//! C callers retrieve the last error message via `rlsm_last_error`.
//! Rust internals set / clear it through `set_last_error` / `clear_last_error`
//! and the `rlsm_err!` convenience macro.

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Store `msg` as the thread-local last error.
pub fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(msg.into()));
}

/// Clear the thread-local last error.
pub fn clear_last_error() {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = None);
}

/// Copy the last error message into `out_buf` (NUL-terminated).
///
/// Returns the number of bytes written (including the NUL terminator) on
/// success, `0` when there is no error, or `-1` if the buffer is too small.
#[no_mangle]
pub extern "C" fn rlsm_last_error(out_buf: *mut u8, buf_len: i32) -> i32 {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_deref() {
            None => 0,
            Some(msg) => {
                // We need space for the message plus a NUL terminator.
                let needed = msg.len() + 1;
                if buf_len < 0 || (buf_len as usize) < needed {
                    return -1;
                }
                if out_buf.is_null() {
                    return -1;
                }
                // SAFETY: caller guarantees the buffer is valid for `buf_len` bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        msg.as_ptr(),
                        out_buf,
                        msg.len(),
                    );
                    out_buf.add(msg.len()).write(0u8); // NUL terminator
                }
                needed as i32
            }
        }
    })
}

/// Set the thread-local error to `$msg` and immediately return `$ret`
/// from the enclosing function.
///
/// Usage:
/// ```ignore
/// rlsm_err!("something went wrong"; return -1);
/// ```
#[macro_export]
macro_rules! rlsm_err {
    ($msg:expr; return $ret:expr) => {{
        $crate::error::set_last_error($msg);
        return $ret;
    }};
}
