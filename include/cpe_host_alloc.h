/**
 * @file cpe_host_alloc.h
 * @brief Sole process malloc gate for CPE agent-owned buffers (P2.3).
 *
 * Agent core requests memory via events; host fulfills with these helpers.
 * libnetdiag / libyaml keep their own create-time alloc policies.
 */
#ifndef CPE_HOST_ALLOC_H
#define CPE_HOST_ALLOC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *cpe_host_alloc(size_t n);
void *cpe_host_realloc(void *p, size_t n);
void  cpe_host_free(void *p);

void     cpe_host_alloc_reset_stats(void);
uint64_t cpe_host_alloc_count(void);
uint64_t cpe_host_realloc_count(void);
uint64_t cpe_host_free_count(void);
uint64_t cpe_host_bytes_outstanding(void);

#ifdef __cplusplus
}
#endif

#endif /* CPE_HOST_ALLOC_H */
