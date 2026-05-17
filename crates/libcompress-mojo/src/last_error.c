// Thread-local last-error buffer for libcompress-mojo.
//
// Mirrors the pattern in crates/librustls-mojo/src/error.rs: a per-thread
// 512-byte buffer that callers populate via lcm_set_last_error() and read
// via lcm_last_error(). The Mojo side calls only lcm_last_error.

// strnlen is POSIX, not c11. cc::Build defaults to -std=c11 without
// _POSIX_C_SOURCE, so the declaration is hidden by glibc's feature tests.
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <string.h>

#define LCM_ERR_BUF 512

static _Thread_local char g_err[LCM_ERR_BUF];
static _Thread_local int32_t g_err_len;  // bytes including NUL, or 0 if no error

void lcm_set_last_error(const char *msg) {
    if (!msg) {
        g_err_len = 0;
        g_err[0] = '\0';
        return;
    }
    int32_t n = (int32_t)strnlen(msg, LCM_ERR_BUF - 1);
    memcpy(g_err, msg, (size_t)n);
    g_err[n] = '\0';
    g_err_len = n + 1;
}

// Copy the last error message into out_buf (NUL-terminated).
// Returns bytes written including the NUL, or 0 if there is no error
// or out_buf is too small / NULL.
int32_t lcm_last_error(uint8_t *out_buf, int32_t buf_len) {
    if (!out_buf || buf_len <= 0 || g_err_len <= 0) return 0;
    if (g_err_len > buf_len) return 0;
    memcpy(out_buf, g_err, (size_t)g_err_len);
    return g_err_len;
}
