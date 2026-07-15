#include "netforensics.h"

#include <string.h>

int nf_ipfix_collect_flows(ipfix_ctx_t *ctx, const uint8_t *msg, size_t len,
                           const char *router_id, nf_flow_obs_t *out, size_t max_out)
{
    ipfix_event_t ev;
    size_t n = 0;
    if (!ctx || !msg || !out || max_out == 0) {
        return -1;
    }
    if (ipfix_feed_message(ctx, msg, len) != 0) {
        return -1;
    }
    while (ipfix_next_event(ctx, &ev) == 1) {
        if (ev.type != IPFIX_EVENT_DATA_RECORD) {
            continue;
        }
        if (n >= max_out) {
            break;
        }
        if (nf_obs_from_ipfix(&ev.data.record, router_id,
                              (uint64_t)ev.message.export_time * 1000ull,
                              &out[n]) == 0) {
            n++;
        }
    }
    return (int)n;
}
