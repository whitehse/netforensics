/**
 * @file harness_driver.c
 * @brief Register + invoke get_local_latency via libharness (P2.6).
 */

#include "cpe_harness.h"

#include <stdio.h>
#include <string.h>

int cpe_harness_register_tools(harness_ctx_t *h)
{
    harness_tool_def_t def;

    if (!h) {
        return -1;
    }
    memset(&def, 0, sizeof(def));
    def.name = CPE_TOOL_GET_LOCAL_LATENCY;
    def.description =
        "Return the last CPE performance sample (rtt_ms, loss, probe, target). "
        "Local only; no network.";
    def.parameters_json = "{\"type\":\"object\",\"properties\":{}}";
    def.type = HARNESS_TOOL_FUNCTION;
    if (harness_tool_register(h, &def) != 0) {
        return -1;
    }
    return 0;
}

int cpe_harness_invoke_local(const cpe_agent_t *agent, const char *name,
                             const char *arguments_json, char *out,
                             size_t out_cap)
{
    (void)arguments_json;
    if (!agent || !name || !out || out_cap < 8) {
        return -1;
    }
    if (strcmp(name, CPE_TOOL_GET_LOCAL_LATENCY) != 0) {
        return -1;
    }
    if (cpe_agent_get_local_latency_json(agent, out, out_cap) < 0) {
        return -1;
    }
    return 0;
}
