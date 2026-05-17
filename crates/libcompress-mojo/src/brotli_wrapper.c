// lcm_br_* — streaming brotli decoder backed by system libbrotlidec.
//
// Same shape and cap semantics as lcm_gzip_* in zlib_wrapper.c — see that
// file for the contract docs. Differences are confined to the underlying
// library's stream object and decompress call.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/decode.h>

extern void lcm_set_last_error(const char *msg);

typedef struct BrotliState {
    BrotliDecoderState *bs;
    int      finished;
    uint64_t in_total;
    uint64_t out_total;
    uint64_t input_cap;
    uint64_t output_cap;
    uint32_t ratio_x100;
} BrotliState;

BrotliState *lcm_br_init(uint64_t input_cap, uint64_t output_cap, uint32_t ratio_x100) {
    BrotliState *s = (BrotliState *)calloc(1, sizeof(*s));
    if (!s) {
        lcm_set_last_error("lcm_br_init: out of memory");
        return NULL;
    }
    s->bs = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!s->bs) {
        lcm_set_last_error("lcm_br_init: BrotliDecoderCreateInstance failed");
        free(s);
        return NULL;
    }
    s->input_cap  = input_cap;
    s->output_cap = output_cap;
    s->ratio_x100 = ratio_x100;
    return s;
}

static int64_t check_caps_br(BrotliState *s) {
    if (s->input_cap && s->in_total > s->input_cap) {
        lcm_set_last_error("lcm_br: input cap exceeded");
        return -2;
    }
    if (s->output_cap && s->out_total > s->output_cap) {
        lcm_set_last_error("lcm_br: output cap exceeded");
        return -3;
    }
    if (s->ratio_x100 && s->in_total >= 1024) {
        if (s->out_total > (s->in_total * (uint64_t)s->ratio_x100) / 100ULL) {
            lcm_set_last_error("lcm_br: ratio cap exceeded");
            return -4;
        }
    }
    return 0;
}

int64_t lcm_br_feed(BrotliState *s, const uint8_t *in_ptr, size_t in_len,
                    uint8_t *out_ptr, size_t out_cap) {
    if (!s || !s->bs || !out_ptr) {
        lcm_set_last_error("lcm_br_feed: bad args");
        return -1;
    }
    if (in_len > 0 && !in_ptr) {
        lcm_set_last_error("lcm_br_feed: in_ptr NULL with in_len > 0");
        return -1;
    }
    if (s->finished) return 0;

    s->in_total += (uint64_t)in_len;
    if (s->input_cap && s->in_total > s->input_cap) {
        lcm_set_last_error("lcm_br: input cap exceeded");
        return -2;
    }

    size_t       avail_in  = in_len;
    const uint8_t *next_in = in_ptr;
    size_t       avail_out = out_cap;
    uint8_t      *next_out = out_ptr;

    BrotliDecoderResult rc = BrotliDecoderDecompressStream(
        s->bs, &avail_in, &next_in, &avail_out, &next_out, NULL);

    if (rc == BROTLI_DECODER_RESULT_ERROR) {
        lcm_set_last_error("lcm_br_feed: BrotliDecoderDecompressStream error");
        return -1;
    }
    if (rc == BROTLI_DECODER_RESULT_SUCCESS) s->finished = 1;

    size_t written = out_cap - avail_out;
    s->out_total += (uint64_t)written;

    int64_t cap_err = check_caps_br(s);
    if (cap_err) return cap_err;
    return (int64_t)written;
}

int64_t lcm_br_finish(BrotliState *s, uint8_t *out_ptr, size_t out_cap) {
    if (!s || !s->bs || !out_ptr) {
        lcm_set_last_error("lcm_br_finish: bad args");
        return -1;
    }
    if (s->finished) return 0;

    // Drain with empty input. If the decoder still needs more bytes,
    // BrotliDecoderDecompressStream returns NEEDS_MORE_INPUT — we treat
    // that as "no more output coming" (return 0) since the caller has
    // signalled end-of-stream by switching from feed() to finish().
    size_t       avail_in  = 0;
    const uint8_t *next_in = NULL;
    size_t       avail_out = out_cap;
    uint8_t      *next_out = out_ptr;

    BrotliDecoderResult rc = BrotliDecoderDecompressStream(
        s->bs, &avail_in, &next_in, &avail_out, &next_out, NULL);

    if (rc == BROTLI_DECODER_RESULT_ERROR) {
        lcm_set_last_error("lcm_br_finish: BrotliDecoderDecompressStream error");
        return -1;
    }
    if (rc == BROTLI_DECODER_RESULT_SUCCESS) s->finished = 1;

    size_t written = out_cap - avail_out;
    s->out_total += (uint64_t)written;

    int64_t cap_err = check_caps_br(s);
    if (cap_err) return cap_err;
    return (int64_t)written;
}

void lcm_br_free(BrotliState *s) {
    if (!s) return;
    if (s->bs) BrotliDecoderDestroyInstance(s->bs);
    free(s);
}
