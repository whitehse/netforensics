/**
 * @file cpe_agent_fuzz.h
 * @brief Local fuzz stubs for config + NDJSON (P2.7a; no libsim required).
 */
#ifndef CPE_AGENT_FUZZ_H
#define CPE_AGENT_FUZZ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Feed arbitrary bytes as YAML config load + apply (rejects OK).
 * Also formats a cpe_perf line from truncated fields in the buffer.
 * Always returns 0.
 */
int cpe_agent_fuzz_config_and_ndjson(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* CPE_AGENT_FUZZ_H */
