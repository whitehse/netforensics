/**
 * @file host_alloc.c
 * @brief Process malloc gate for CPE agent buffers (P2.3).
 */

#include "cpe_host_alloc.h"

#include <stdlib.h>
#include <string.h>

static uint64_t g_allocs;
static uint64_t g_reallocs;
static uint64_t g_frees;
static uint64_t g_bytes;

void cpe_host_alloc_reset_stats(void)
{
    g_allocs = 0;
    g_reallocs = 0;
    g_frees = 0;
    g_bytes = 0;
}

uint64_t cpe_host_alloc_count(void)
{
    return g_allocs;
}

uint64_t cpe_host_realloc_count(void)
{
    return g_reallocs;
}

uint64_t cpe_host_free_count(void)
{
    return g_frees;
}

uint64_t cpe_host_bytes_outstanding(void)
{
    return g_bytes;
}

void *cpe_host_alloc(size_t n)
{
    void *p;

    if (n == 0) {
        return NULL;
    }
    p = calloc(1, n);
    if (!p) {
        return NULL;
    }
    g_allocs++;
    g_bytes += (uint64_t)n;
    return p;
}

void *cpe_host_realloc(void *p, size_t n)
{
    void *q;

    if (n == 0) {
        cpe_host_free(p);
        return NULL;
    }
    if (!p) {
        return cpe_host_alloc(n);
    }
    q = realloc(p, n);
    if (!q) {
        return NULL;
    }
    g_reallocs++;
    return q;
}

void cpe_host_free(void *p)
{
    if (!p) {
        return;
    }
    free(p);
    g_frees++;
}
