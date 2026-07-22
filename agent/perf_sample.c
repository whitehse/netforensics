/**
 * @file perf_sample.c
 * @brief cpe_perf NDJSON formatter (N-A05 / P2.5).
 */

#include "cpe_agent.h"

#include <stdio.h>
#include <string.h>

int cpe_perf_format_ndjson(const char *router_id, const cpe_perf_sample_t *s,
                           char *buf, size_t buflen)
{
    int n;
    const char *rid = router_id && router_id[0] ? router_id : "unknown";
    const char *probe;
    const char *target;
    const char *ts;
    const char *meta;

    if (!s || !buf || buflen < 32) {
        return -1;
    }
    probe = s->probe[0] ? s->probe : "ping";
    target = s->target[0] ? s->target : "";
    ts = s->ts_iso[0] ? s->ts_iso : "1970-01-01T00:00:00.000Z";
    meta = s->meta[0] ? s->meta : "{}";

    /* Keep meta as embedded JSON object (already validated small). */
    /* %.3f → millisecond field with microsecond resolution (e.g. 14.567). */
    n = snprintf(buf, buflen,
                 "{\"type\":\"cpe_perf\",\"ts\":\"%s\",\"router_id\":\"%s\","
                 "\"probe\":\"%s\",\"target\":\"%s\",\"rtt_ms\":%.3f,"
                 "\"loss\":%.4f,\"meta\":%s}",
                 ts, rid, probe, target, s->rtt_ms, (double)s->loss, meta);
    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }
    return n;
}
