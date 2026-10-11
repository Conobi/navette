/* caps.h: decompression accounting and caps shared by the gzip and brotli
 * wrappers. Counters move by bytes actually consumed / produced, after each
 * call, and are cumulative across gzip members. Any error poisons the
 * decoder: later steps return LCM_ERR_FAILED. */
#ifndef LCM_CAPS_H
#define LCM_CAPS_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

extern void lcm_set_last_error(const char *msg);

enum {
    LCM_NEED_INPUT = 0, LCM_NEED_OUTPUT = 1, LCM_DONE = 2,
    LCM_ERR_DECODE = -1, LCM_ERR_INPUT_CAP = -2, LCM_ERR_OUTPUT_CAP = -3,
    LCM_ERR_RATIO = -4, LCM_ERR_TRUNCATED = -5, LCM_ERR_AFTER_FINISH = -6,
    LCM_ERR_FAILED = -7,
};

/* `finished` values: a closed decoder answers later steps with "feed after
 * finish", unless it was already poisoned when finish ran. */
enum { CAPS_OPEN = 0, CAPS_FINISHED = 1, CAPS_CLOSED_POISONED = 2 };

typedef struct LcmCaps {
    uint64_t in_total;
    uint64_t out_total;
    uint64_t input_cap;   /* 0 disables */
    uint64_t output_cap;  /* 0 disables */
    uint32_t ratio_x100;  /* 0 disables */
    int finished;
    int failed;
    int trailing_seen;
} LcmCaps;

/* Record an error, poison the decoder, return `code`. */
static inline int32_t caps_fail(LcmCaps *c, int32_t code, const char *msg) {
    c->failed = 1;
    lcm_set_last_error(msg);
    return code;
}

/* LCM_ERR_AFTER_FINISH / LCM_ERR_FAILED for a closed or poisoned decoder,
 * else 0. */
static inline int32_t caps_gate(const LcmCaps *c) {
    if (c->finished == CAPS_FINISHED) {
        lcm_set_last_error("feed after finish");
        return LCM_ERR_AFTER_FINISH;
    }
    if (c->failed) {
        lcm_set_last_error("decoder failed");
        return LCM_ERR_FAILED;
    }
    return 0;
}

/* Shared finish prologue: 1 with *rc set when finish must return now
 * (already closed: DONE; poisoned: closes it and fails), else 0. */
static inline int caps_finish_gate(LcmCaps *c, size_t out_cap, int32_t *rc) {
    if (c->finished) { *rc = LCM_DONE; return 1; }
    if (c->failed) {
        c->finished = CAPS_CLOSED_POISONED;
        lcm_set_last_error("decoder failed");
        *rc = LCM_ERR_FAILED;
        return 1;
    }
    if (out_cap < 1) {
        c->finished = CAPS_FINISHED;
        *rc = caps_fail(c, LCM_ERR_DECODE, "max_out < 1");
        return 1;
    }
    return 0;
}

/* Output room for one call: at most max_out, the zlib uInt range, and one
 * byte past output_cap (producing that byte is the cap error). */
static inline size_t caps_room(const LcmCaps *c, size_t max_out) {
    size_t room = max_out < (size_t)UINT_MAX ? max_out : (size_t)UINT_MAX;
    if (c->output_cap) {
        uint64_t left = c->out_total < c->output_cap ? c->output_cap - c->out_total + 1 : 1;
        if ((uint64_t)room > left) room = (size_t)left;
    }
    return room;
}

/* Count one call's progress and check every cap. Ratio is armed from the
 * first byte with a 1 KiB floor on the input side; the limit saturates
 * instead of wrapping for huge inputs. */
static inline int32_t caps_account(LcmCaps *c, size_t consumed, size_t produced) {
    c->in_total += consumed;
    c->out_total += produced;
    if (c->input_cap && c->in_total > c->input_cap)
        return caps_fail(c, LCM_ERR_INPUT_CAP, "input cap exceeded");
    if (c->output_cap && c->out_total > c->output_cap)
        return caps_fail(c, LCM_ERR_OUTPUT_CAP, "output cap exceeded");
    if (c->ratio_x100) {
        uint64_t base = c->in_total > 1024 ? c->in_total : 1024;
        uint64_t lim = base > UINT64_MAX / c->ratio_x100 ? UINT64_MAX : base * c->ratio_x100 / 100ULL;
        if (c->out_total > lim)
            return caps_fail(c, LCM_ERR_RATIO, "ratio cap exceeded");
    }
    return 0;
}

/* Shared step prologue: gate, max_out check and input-cap precheck (which
 * may only reject early; counting happens in caps_account). */
static inline int32_t caps_step_gate(LcmCaps *c, size_t in_len, size_t out_cap) {
    int32_t gate = caps_gate(c);
    if (gate) return gate;
    if (out_cap < 1) return caps_fail(c, LCM_ERR_DECODE, "max_out < 1");
    if (c->input_cap && c->in_total + in_len > c->input_cap)
        return caps_fail(c, LCM_ERR_INPUT_CAP, "input cap exceeded");
    return 0;
}

/* Shared finish epilogue: account `made`, then DONE at stream end (closes),
 * NEED_OUTPUT when output is still pending, else truncated. Any error
 * closes the decoder. */
static inline int32_t caps_finish_result(LcmCaps *c, size_t made, int at_end, int more_out,
                                         const char *trunc_msg, size_t *out_written) {
    int32_t err = caps_account(c, 0, made);
    if (!err && (at_end || more_out)) {
        *out_written = made;
        if (at_end) c->finished = CAPS_FINISHED;
        return at_end ? LCM_DONE : LCM_NEED_OUTPUT;
    }
    if (!err) err = caps_fail(c, LCM_ERR_TRUNCATED, trunc_msg);
    c->finished = CAPS_FINISHED;
    return err;
}

#endif
