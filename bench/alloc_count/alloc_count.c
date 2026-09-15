/* LD_PRELOAD shim that counts malloc/free/calloc/realloc calls.
   On SIGUSR1: print counts to stderr and reset.
   On process exit: print final counts. */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static atomic_uint_least64_t g_malloc_count  = 0;
static atomic_uint_least64_t g_free_count    = 0;
static atomic_uint_least64_t g_calloc_count  = 0;
static atomic_uint_least64_t g_realloc_count = 0;

static void (*real_free)(void *) = NULL;
static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;

/* Bootstrap buffer for calloc calls during dlsym resolution. */
static char bootstrap_buf[65536];
static size_t bootstrap_used = 0;
static volatile int hooks_ready = 0;

static void dump_and_reset(int sig) {
    (void)sig;
    uint64_t m = atomic_exchange(&g_malloc_count, 0);
    uint64_t f = atomic_exchange(&g_free_count, 0);
    uint64_t c = atomic_exchange(&g_calloc_count, 0);
    uint64_t r = atomic_exchange(&g_realloc_count, 0);
    dprintf(STDERR_FILENO,
            "[alloc_count] malloc=%lu free=%lu calloc=%lu realloc=%lu total_alloc=%lu\n",
            m, f, c, r, m + c + r);
}

static void dump_final(void) {
    dump_and_reset(0);
}

static void init_hooks(void) __attribute__((constructor));
static void init_hooks(void) {
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    hooks_ready = 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = dump_and_reset;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    atexit(dump_final);
}

void *malloc(size_t size) {
    if (!hooks_ready) {
        /* Before dlsym resolves, hand out from the bootstrap buffer. */
        void *p = bootstrap_buf + bootstrap_used;
        bootstrap_used += (size + 15) & ~(size_t)15;
        return p;
    }
    atomic_fetch_add_explicit(&g_malloc_count, 1, memory_order_relaxed);
    return real_malloc(size);
}

void free(void *ptr) {
    if (!ptr) return;
    /* Ignore frees into the bootstrap buffer. */
    if ((char *)ptr >= bootstrap_buf &&
        (char *)ptr < bootstrap_buf + sizeof(bootstrap_buf))
        return;
    if (!hooks_ready) return;
    atomic_fetch_add_explicit(&g_free_count, 1, memory_order_relaxed);
    real_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
    if (!hooks_ready) {
        size_t total = nmemb * size;
        void *p = bootstrap_buf + bootstrap_used;
        bootstrap_used += (total + 15) & ~(size_t)15;
        memset(p, 0, total);
        return p;
    }
    atomic_fetch_add_explicit(&g_calloc_count, 1, memory_order_relaxed);
    return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size) {
    if (!hooks_ready) {
        void *p = malloc(size);
        if (ptr) memcpy(p, ptr, size);
        return p;
    }
    atomic_fetch_add_explicit(&g_realloc_count, 1, memory_order_relaxed);
    return real_realloc(ptr, size);
}
