#include "netforensics.h"

#include <string.h>
#include <stdio.h>

int nf_obs_from_ipfix(const ipfix_data_record_t *rec, const char *router_id,
                      uint64_t fallback_ts_ms, nf_flow_obs_t *out)
{
    ipfix_flow_key_t key;
    if (!rec || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (ipfix_record_flow_key(rec, &key) < 0) {
        return -1;
    }
    out->src_ip = key.src_ipv4;
    out->dst_ip = key.dst_ipv4;
    out->src_port = key.src_port;
    out->dst_port = key.dst_port;
    out->protocol = key.protocol;
    out->ts_ms = key.has_start_ms ? key.flow_start_ms : fallback_ts_ms;
    out->from_cpe = 0;
    if (router_id) {
        strncpy(out->router_id, router_id, sizeof(out->router_id) - 1);
    }
    return key.has_5tuple ? 0 : -1;
}

int nf_obs_from_nfct(const nfct_event_t *ev, const char *router_id,
                     uint64_t ts_ms, nf_flow_obs_t *out)
{
    uint32_t lan_ip = 0, wan_ip = 0;
    uint16_t lan_port = 0, wan_port = 0;
    uint8_t proto = 0;
    if (!ev || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (nfct_event_forensics_tuple(ev, &lan_ip, &lan_port, &wan_ip, &wan_port, &proto) != 1) {
        return -1;
    }
    out->ts_ms = ts_ms;
    out->src_ip = lan_ip;
    out->src_port = lan_port;
    out->dst_ip = ev->lan_dst_ip;
    out->dst_port = ev->lan_dst_port;
    out->wan_src_ip = wan_ip;
    out->wan_src_port = wan_port;
    out->protocol = proto;
    out->from_cpe = 1;
    if (router_id) {
        strncpy(out->router_id, router_id, sizeof(out->router_id) - 1);
    }
    return 0;
}

int nf_flows_correlate(const nf_flow_obs_t *cpe, const nf_flow_obs_t *core,
                       uint64_t max_skew_ms)
{
    uint64_t dt;
    if (!cpe || !core || !cpe->from_cpe || core->from_cpe) {
        return -1;
    }
    /* Match post-NAT WAN source to core source (outbound). */
    if (cpe->wan_src_ip != core->src_ip || cpe->wan_src_port != core->src_port) {
        return 0;
    }
    if (cpe->protocol != core->protocol) {
        return 0;
    }
    if (cpe->dst_ip != 0 && core->dst_ip != 0 && cpe->dst_ip != core->dst_ip) {
        return 0;
    }
    dt = (cpe->ts_ms > core->ts_ms) ? (cpe->ts_ms - core->ts_ms)
                                    : (core->ts_ms - cpe->ts_ms);
    if (dt > max_skew_ms) {
        return 0;
    }
    return 1;
}

int nf_obs_format(const nf_flow_obs_t *obs, char *buf, size_t buflen)
{
    if (!obs || !buf || buflen < 32) {
        return -1;
    }
    if (obs->from_cpe) {
        snprintf(buf, buflen,
                 "{\"type\":\"cpe_nat\",\"router\":\"%s\",\"ts\":%llu,"
                 "\"lan\":\"%u.%u.%u.%u:%u\",\"wan\":\"%u.%u.%u.%u:%u\",\"proto\":%u}",
                 obs->router_id,
                 (unsigned long long)obs->ts_ms,
                 (obs->src_ip >> 24) & 0xFF, (obs->src_ip >> 16) & 0xFF,
                 (obs->src_ip >> 8) & 0xFF, obs->src_ip & 0xFF, obs->src_port,
                 (obs->wan_src_ip >> 24) & 0xFF, (obs->wan_src_ip >> 16) & 0xFF,
                 (obs->wan_src_ip >> 8) & 0xFF, obs->wan_src_ip & 0xFF, obs->wan_src_port,
                 obs->protocol);
    } else {
        snprintf(buf, buflen,
                 "{\"type\":\"ipfix\",\"router\":\"%s\",\"ts\":%llu,"
                 "\"flow\":\"%u.%u.%u.%u:%u>%u.%u.%u.%u:%u\",\"proto\":%u}",
                 obs->router_id,
                 (unsigned long long)obs->ts_ms,
                 (obs->src_ip >> 24) & 0xFF, (obs->src_ip >> 16) & 0xFF,
                 (obs->src_ip >> 8) & 0xFF, obs->src_ip & 0xFF, obs->src_port,
                 (obs->dst_ip >> 24) & 0xFF, (obs->dst_ip >> 16) & 0xFF,
                 (obs->dst_ip >> 8) & 0xFF, obs->dst_ip & 0xFF, obs->dst_port,
                 obs->protocol);
    }
    return 0;
}
