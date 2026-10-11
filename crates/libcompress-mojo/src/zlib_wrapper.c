// lcm_gzip_* — streaming gzip decoder backed by system zlib.
//
// init / step / finish_step / trailing_seen / free. Decompression-bomb caps
// (input_cap, output_cap, ratio_x100) are configured per state at init()
// and enforced on every step by caps.h.
//
// Limits are *runtime* parameters, not #define constants — the Mojo side
// (navette/compress/lib.mojo DecoderLimits) owns the defaults.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <zlib.h>

#include "caps.h"

typedef struct GzipState {
    z_stream zs;
    int      inited;        // 1 once inflateInit2 succeeded
    int      member_done;   // inflate reached Z_STREAM_END for the current member
    int      held_1f;       // one 0x1f byte consumed, decided on the next call
    LcmCaps  caps;
} GzipState;

// Allocate a GzipState with explicit decompression caps. Returns NULL on
// allocation/init failure. Caps of 0 disable the corresponding check.
GzipState *lcm_gzip_init(uint64_t input_cap, uint64_t output_cap, uint32_t ratio_x100) {
    GzipState *s = (GzipState *)calloc(1, sizeof(*s));
    if (!s) {
        lcm_set_last_error("lcm_gzip_init: out of memory");
        return NULL;
    }
    s->caps.input_cap  = input_cap;
    s->caps.output_cap = output_cap;
    s->caps.ratio_x100 = ratio_x100;
    // windowBits = 15 + 32 → "accept gzip header" (auto-detect zlib or gzip).
    // We document this as gzip-only at the binding layer; zlib accepts both,
    // which is more lenient than the previous flate2 behaviour but never less.
    if (inflateInit2(&s->zs, 15 + 32) != Z_OK) {
        lcm_set_last_error("lcm_gzip_init: inflateInit2 failed");
        free(s);
        return NULL;
    }
    s->inited = 1;
    return s;
}

// Start the next member after Z_STREAM_END; re-feeds a held 0x1f. inflate
// rejects a NULL next_out even with avail_out == 0, hence the dummy byte.
static int gzip_next_member(GzipState *s) {
    if (inflateReset(&s->zs) != Z_OK) return 0;
    s->member_done = 0;
    if (s->held_1f) {
        Bytef b = 0x1f, sink;
        s->zs.next_in = &b; s->zs.avail_in = 1;
        s->zs.next_out = &sink; s->zs.avail_out = 0;
        int rc = inflate(&s->zs, Z_NO_FLUSH);
        s->held_1f = 0;
        if (rc != Z_OK || s->zs.avail_in) return 0;
    }
    return 1;
}

// After a member ended at in[used]: 1 if a new member starts there, 0 for
// trailing data, -1 when a lone 0x1f must wait for the next call.
static int gzip_member_starts(const GzipState *s, const uint8_t *in, size_t in_len, size_t used) {
    if (s->held_1f) return in[used] == 0x8b;
    if (in[used] != 0x1f) return 0;
    if (used + 1 == in_len) return -1;
    return in[used + 1] == 0x8b;
}

// Decode from `in` into `out` (at most out_cap bytes). Writes bytes
// consumed / produced; returns LCM_NEED_INPUT / NEED_OUTPUT / DONE or an
// LCM_ERR_*. After a member ends, a following gzip member continues in the
// same call; anything else is trailing data: consumed, counted, dropped.
int32_t lcm_gzip_step(GzipState *s, const uint8_t *in, size_t in_len, size_t *in_consumed,
                      uint8_t *out, size_t out_cap, size_t *out_written) {
    if (!s || !s->inited || !out || !in_consumed || !out_written || (in_len && !in)) {
        lcm_set_last_error("lcm_gzip_step: bad args");
        return LCM_ERR_DECODE;
    }
    *in_consumed = 0;
    *out_written = 0;
    int32_t gate = caps_step_gate(&s->caps, in_len, out_cap);
    if (gate) return gate;

    size_t room = caps_room(&s->caps, out_cap);
    size_t used = 0, made = 0;
    int32_t status = LCM_NEED_INPUT;
    int rc = Z_OK;
    for (;;) {
        if (s->member_done) {
            int starts = used == in_len || s->caps.trailing_seen
                ? 0 : gzip_member_starts(s, in, in_len, used);
            if (starts <= 0) {
                if (starts == -1) s->held_1f = 1;
                else if (used < in_len) { s->held_1f = 0; s->caps.trailing_seen = 1; }
                used = in_len;
                status = LCM_DONE;
                break;
            }
            if (!gzip_next_member(s)) { rc = Z_DATA_ERROR; break; }
        }
        size_t in_left = in_len - used;
        uInt avail_in = in_left < (size_t)UINT_MAX ? (uInt)in_left : UINT_MAX;
        s->zs.next_in   = in ? (Bytef *)(in + used) : Z_NULL;
        s->zs.avail_in  = avail_in;
        s->zs.next_out  = (Bytef *)(out + made);
        s->zs.avail_out = (uInt)(room - made);
        rc = inflate(&s->zs, Z_NO_FLUSH);
        used += avail_in - s->zs.avail_in;
        made += (room - made) - s->zs.avail_out;
        if (rc == Z_STREAM_END) { s->member_done = 1; continue; }
        if (rc != Z_OK && rc != Z_BUF_ERROR) break;
        if (made == room) { status = LCM_NEED_OUTPUT; break; }
        if (used == in_len || rc == Z_BUF_ERROR) { status = LCM_NEED_INPUT; break; }
    }
    s->zs.next_in = NULL; s->zs.avail_in = 0; s->zs.next_out = NULL; s->zs.avail_out = 0;
    if (rc != Z_OK && rc != Z_BUF_ERROR && rc != Z_STREAM_END)
        return caps_fail(&s->caps, LCM_ERR_DECODE, "lcm_gzip_step: inflate error");
    int32_t err = caps_account(&s->caps, used, made);
    if (err) return err;
    *in_consumed = used;
    *out_written = made;
    return status;
}

// Drain pending output with no more input. DONE closes the decoder;
// NEED_OUTPUT means call again; a stream that never ended is truncated.
// Uses Z_NO_FLUSH: Z_FINISH reports a full output buffer and missing input
// with the same Z_BUF_ERROR.
int32_t lcm_gzip_finish_step(GzipState *s, uint8_t *out, size_t out_cap, size_t *out_written) {
    if (!s || !s->inited || !out || !out_written) {
        lcm_set_last_error("lcm_gzip_finish_step: bad args");
        return LCM_ERR_DECODE;
    }
    *out_written = 0;
    int32_t rc;
    if (caps_finish_gate(&s->caps, out_cap, &rc)) return rc;
    if (s->caps.in_total == 0 || s->member_done) {
        if (s->held_1f) { s->caps.trailing_seen = 1; s->held_1f = 0; }
        s->caps.finished = CAPS_FINISHED;
        return LCM_DONE;
    }
    size_t room = caps_room(&s->caps, out_cap);
    s->zs.next_in = NULL; s->zs.avail_in = 0;
    s->zs.next_out = (Bytef *)out; s->zs.avail_out = (uInt)room;
    int zrc = inflate(&s->zs, Z_NO_FLUSH);
    size_t made = room - s->zs.avail_out;
    s->zs.next_out = NULL; s->zs.avail_out = 0;
    if (zrc != Z_OK && zrc != Z_BUF_ERROR && zrc != Z_STREAM_END) {
        s->caps.finished = CAPS_FINISHED;
        return caps_fail(&s->caps, LCM_ERR_DECODE, "lcm_gzip_finish_step: inflate error");
    }
    if (zrc == Z_STREAM_END) s->member_done = 1;
    return caps_finish_result(&s->caps, made, zrc == Z_STREAM_END, made == room,
                              "truncated gzip stream", out_written);
}

int32_t lcm_gzip_trailing_seen(const GzipState *s) {
    return s && s->caps.trailing_seen;
}

void lcm_gzip_free(GzipState *s) {
    if (!s) return;
    if (s->inited) inflateEnd(&s->zs);
    free(s);
}
