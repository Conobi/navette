// lcm_br_* — streaming brotli decoder backed by system libbrotlidec.
//
// Same shape and cap semantics as lcm_gzip_* in zlib_wrapper.c — see that
// file for the contract docs. Differences are confined to the underlying
// library's stream object and decompress call.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <brotli/decode.h>

#include "caps.h"

typedef struct BrotliState {
    BrotliDecoderState *bs;
    int      stream_done;   // BROTLI_DECODER_RESULT_SUCCESS seen
    LcmCaps  caps;
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
    s->caps.input_cap  = input_cap;
    s->caps.output_cap = output_cap;
    s->caps.ratio_x100 = ratio_x100;
    return s;
}

// Same contract as lcm_gzip_step; bytes after a complete stream are
// trailing data (consumed, counted, dropped).
int32_t lcm_br_step(BrotliState *s, const uint8_t *in, size_t in_len, size_t *in_consumed,
                    uint8_t *out, size_t out_cap, size_t *out_written) {
    if (!s || !s->bs || !out || !in_consumed || !out_written || (in_len && !in)) {
        lcm_set_last_error("lcm_br_step: bad args");
        return LCM_ERR_DECODE;
    }
    *in_consumed = 0;
    *out_written = 0;
    int32_t status = caps_step_gate(&s->caps, in_len, out_cap);
    if (status) return status;

    size_t used = in_len, made = 0, trailing = in_len;
    status = LCM_DONE;
    if (!s->stream_done) {
        size_t room = caps_room(&s->caps, out_cap);
        size_t avail_in = in_len, avail_out = room;
        const uint8_t *next_in = in;
        uint8_t *next_out = out;
        BrotliDecoderResult rc = BrotliDecoderDecompressStream(
            s->bs, &avail_in, &next_in, &avail_out, &next_out, NULL);
        if (rc == BROTLI_DECODER_RESULT_ERROR)
            return caps_fail(&s->caps, LCM_ERR_DECODE, "lcm_br_step: decode error");
        made = room - avail_out;
        if (rc == BROTLI_DECODER_RESULT_SUCCESS) {
            s->stream_done = 1;
            trailing = avail_in;
        } else {
            used = in_len - avail_in;
            trailing = 0;
            status = rc == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT ? LCM_NEED_OUTPUT : LCM_NEED_INPUT;
        }
    }
    if (trailing) s->caps.trailing_seen = 1;
    int32_t err = caps_account(&s->caps, used, made);
    if (err) return err;
    *in_consumed = used;
    *out_written = made;
    return status;
}

// Same contract as lcm_gzip_finish_step.
int32_t lcm_br_finish_step(BrotliState *s, uint8_t *out, size_t out_cap, size_t *out_written) {
    if (!s || !s->bs || !out || !out_written) {
        lcm_set_last_error("lcm_br_finish_step: bad args");
        return LCM_ERR_DECODE;
    }
    *out_written = 0;
    int32_t gate;
    if (caps_finish_gate(&s->caps, out_cap, &gate)) return gate;
    if (s->caps.in_total == 0 || s->stream_done) {
        s->caps.finished = CAPS_FINISHED;
        return LCM_DONE;
    }
    size_t room = caps_room(&s->caps, out_cap);
    size_t avail_in = 0, avail_out = room;
    const uint8_t *next_in = NULL;
    uint8_t *next_out = out;
    BrotliDecoderResult rc = BrotliDecoderDecompressStream(
        s->bs, &avail_in, &next_in, &avail_out, &next_out, NULL);
    if (rc == BROTLI_DECODER_RESULT_ERROR) {
        s->caps.finished = CAPS_FINISHED;
        return caps_fail(&s->caps, LCM_ERR_DECODE, "lcm_br_finish_step: decode error");
    }
    if (rc == BROTLI_DECODER_RESULT_SUCCESS) s->stream_done = 1;
    return caps_finish_result(&s->caps, room - avail_out, s->stream_done,
                              rc == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT,
                              "truncated brotli stream", out_written);
}

int32_t lcm_br_trailing_seen(const BrotliState *s) {
    return s && s->caps.trailing_seen;
}

void lcm_br_free(BrotliState *s) {
    if (!s) return;
    if (s->bs) BrotliDecoderDestroyInstance(s->bs);
    free(s);
}
