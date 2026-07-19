/**
 * @file agent_fuzz.c
 * @brief Local fuzz stubs: config YAML + NDJSON formatter (P2.7a).
 */

#include "cpe_agent_fuzz.h"
#include "cpe_agent.h"

#include <stdio.h>
#include <string.h>

int cpe_agent_fuzz_config_and_ndjson(const uint8_t *data, size_t size)
{
    cpe_agent_config_t cfg;
    cpe_agent_t *a;
    cpe_agent_event_t ev;
    cpe_perf_sample_t s;
    char line[CPE_NDJSON_LINE_MAX];
    char err[64];
    size_t n;

    /* 1) Treat buffer as YAML (may fail; that is fine). */
    (void)cpe_agent_config_load_yaml_buf(
        data && size ? (const char *)data : "", size, &cfg, err, sizeof(err));
    (void)cpe_agent_config_validate(&cfg, err, sizeof(err));

    a = cpe_agent_create();
    if (!a) {
        return 0;
    }
    (void)cpe_agent_apply_config(a, &cfg);
    while (cpe_agent_next_event(a, &ev) == 1) {
    }

    /* 2) Build a sample from leading bytes (deterministic). */
    memset(&s, 0, sizeof(s));
    snprintf(s.probe, sizeof(s.probe), "ping");
    if (size > 0) {
        snprintf(s.target, sizeof(s.target), "%u.%u.%u.%u",
                 (unsigned)(data[0] % 223) + 1, (unsigned)(size > 1 ? data[1] : 0),
                 (unsigned)(size > 2 ? data[2] : 0),
                 (unsigned)(size > 3 ? data[3] : 1));
        s.rtt_ms = (double)(data[0]);
        s.loss = (size > 1) ? (data[1] / 255.0f) : 0.0f;
    } else {
        snprintf(s.target, sizeof(s.target), "0.0.0.0");
    }
    snprintf(s.ts_iso, sizeof(s.ts_iso), "1970-01-01T00:00:00.000Z");
    snprintf(s.meta, sizeof(s.meta), "{}");
    (void)cpe_perf_format_ndjson(cfg.router_id[0] ? cfg.router_id : "fuzz", &s,
                                 line, sizeof(line));
    (void)cpe_agent_spool_push_line(a, line);

    /* 3) Optional demo tick if enough bytes look like a flag. */
    if (size > 4 && (data[4] & 1u)) {
        (void)cpe_agent_demo_ping_tick(a);
        n = cpe_agent_spool_depth(a);
        (void)n;
    }

    (void)cpe_agent_get_local_latency_json(a, line, sizeof(line));
    cpe_agent_destroy(a);
    return 0;
}
