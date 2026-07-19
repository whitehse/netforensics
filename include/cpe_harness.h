/**
 * @file cpe_harness.h
 * @brief libharness local tools for CPE agent (P2.6).
 *
 * Registers get_local_latency against a harness_ctx; host invokes via
 * cpe_harness_invoke_local (no network). Soft dependency — only built when
 * libharness is available.
 */
#ifndef CPE_HARNESS_H
#define CPE_HARNESS_H

#include "cpe_agent.h"

#include "harness.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** OpenAI-style tool name. */
#define CPE_TOOL_GET_LOCAL_LATENCY "get_local_latency"

/**
 * Register CPE local tools on @p h (get_local_latency).
 * Does not store agent pointer in harness (host keeps both).
 * @return 0 ok, -1 on error.
 */
int cpe_harness_register_tools(harness_ctx_t *h);

/**
 * Invoke a local CPE tool by name against agent state.
 * Known: get_local_latency (args ignored / may be "{}").
 * @return 0 ok (result in @p out), -1 unknown tool or format error.
 */
int cpe_harness_invoke_local(const cpe_agent_t *agent, const char *name,
                             const char *arguments_json, char *out,
                             size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* CPE_HARNESS_H */
