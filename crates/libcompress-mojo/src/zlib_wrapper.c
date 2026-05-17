// lcm_gzip_* — streaming gzip decoder backed by system zlib.
//
// API shape mirrors the rlsm_gzip_* it replaces: init / feed / finish / free.
// Adds decompression-bomb caps (input_cap, output_cap, ratio_x100) configured
// per-state at init() time, enforced inside feed/finish.
//
// Limits are *runtime* parameters, not #define constants — the Mojo side
// (navette/compress/lib.mojo DecoderLimits) owns the defaults.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

extern void lcm_set_last_error(const char *msg);

typedef struct GzipState {
    z_stream zs;
    int      inited;        // 1 once inflateInit2 succeeded
    int      finished;      // 1 once inflate() returned Z_STREAM_END
    uint64_t in_total;      // cumulative compressed bytes fed
    uint64_t out_total;     // cumulative decompressed bytes emitted
    uint64_t input_cap;     // 0 disables
    uint64_t output_cap;    // 0 disables
    uint32_t ratio_x100;    // 0 disables; check kicks in once in_total >= 1024
} GzipState;

// Allocate a GzipState with explicit decompression caps. Returns NULL on
// allocation/init failure. Caps of 0 disable the corresponding check.
GzipState *lcm_gzip_init(uint64_t input_cap, uint64_t output_cap, uint32_t ratio_x100) {
    GzipState *s = (GzipState *)calloc(1, sizeof(*s));
    if (!s) {
        lcm_set_last_error("lcm_gzip_init: out of memory");
        return NULL;
    }
    s->input_cap  = input_cap;
    s->output_cap = output_cap;
    s->ratio_x100 = ratio_x100;
    // windowBits = 15 + 32 → "accept gzip header" (auto-detect zlib or gzip).
    // We document this as gzip-only at the binding layer; zlib accepts both,
    // which is more lenient than the previous flate2 behaviour but never less.
    int rc = inflateInit2(&s->zs, 15 + 32);
    if (rc != Z_OK) {
        lcm_set_last_error("lcm_gzip_init: inflateInit2 failed");
        free(s);
        return NULL;
    }
    s->inited = 1;
    return s;
}

// Internal: enforce caps after a feed/finish iteration. Returns 0 if ok,
// negative error code otherwise (matches public ABI).
static int64_t check_caps(GzipState *s) {
    if (s->input_cap && s->in_total > s->input_cap) {
        lcm_set_last_error("lcm_gzip: input cap exceeded");
        return -2;
    }
    if (s->output_cap && s->out_total > s->output_cap) {
        lcm_set_last_error("lcm_gzip: output cap exceeded");
        return -3;
    }
    if (s->ratio_x100 && s->in_total >= 1024) {
        // out * 100 > ratio * in  →  ratio_x100 exceeded
        // Use 128-bit-safe form: out / in compared to ratio/100; multiplying
        // out*100 stays in uint64 for any out < 2^57 (~144 PB), which we
        // bound separately via output_cap.
        if (s->out_total > (s->in_total * (uint64_t)s->ratio_x100) / 100ULL) {
            lcm_set_last_error("lcm_gzip: ratio cap exceeded");
            return -4;
        }
    }
    return 0;
}

// Feed compressed bytes; write up to out_cap decompressed bytes to out_ptr.
// Returns bytes written (>= 0), or:
//   -1 on argument / inflate error
//   -2 input cap exceeded
//   -3 output cap exceeded
//   -4 ratio cap exceeded
int64_t lcm_gzip_feed(GzipState *s, const uint8_t *in_ptr, size_t in_len,
                      uint8_t *out_ptr, size_t out_cap) {
    if (!s || !s->inited || !out_ptr) {
        lcm_set_last_error("lcm_gzip_feed: bad args");
        return -1;
    }
    if (in_len > 0 && !in_ptr) {
        lcm_set_last_error("lcm_gzip_feed: in_ptr NULL with in_len > 0");
        return -1;
    }
    if (s->finished) return 0;  // nothing more will come out

    s->in_total += (uint64_t)in_len;
    if (s->input_cap && s->in_total > s->input_cap) {
        lcm_set_last_error("lcm_gzip: input cap exceeded");
        return -2;
    }

    s->zs.next_in   = (Bytef *)in_ptr;
    s->zs.avail_in  = (uInt)in_len;
    s->zs.next_out  = (Bytef *)out_ptr;
    s->zs.avail_out = (uInt)out_cap;

    int rc = inflate(&s->zs, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        lcm_set_last_error("lcm_gzip_feed: inflate error");
        return -1;
    }
    if (rc == Z_STREAM_END) s->finished = 1;

    size_t written = out_cap - s->zs.avail_out;
    s->out_total += (uint64_t)written;

    int64_t cap_err = check_caps(s);
    if (cap_err) return cap_err;
    return (int64_t)written;
}

// Drain any remaining decompressed bytes. Repeatable until it returns 0.
int64_t lcm_gzip_finish(GzipState *s, uint8_t *out_ptr, size_t out_cap) {
    if (!s || !s->inited || !out_ptr) {
        lcm_set_last_error("lcm_gzip_finish: bad args");
        return -1;
    }
    if (s->finished && s->zs.avail_in == 0) return 0;

    s->zs.next_out  = (Bytef *)out_ptr;
    s->zs.avail_out = (uInt)out_cap;
    // No more input — just drain whatever zlib has buffered.
    s->zs.next_in  = NULL;
    s->zs.avail_in = 0;

    int rc = inflate(&s->zs, Z_FINISH);
    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        lcm_set_last_error("lcm_gzip_finish: inflate error");
        return -1;
    }
    if (rc == Z_STREAM_END) s->finished = 1;

    size_t written = out_cap - s->zs.avail_out;
    s->out_total += (uint64_t)written;

    int64_t cap_err = check_caps(s);
    if (cap_err) return cap_err;
    return (int64_t)written;
}

void lcm_gzip_free(GzipState *s) {
    if (!s) return;
    if (s->inited) inflateEnd(&s->zs);
    free(s);
}
