#include "netforensics.h"

#include <string.h>
#include <stdio.h>

static void ipv6_hex(const uint8_t a[16], char *out, size_t out_len)
{
    /* Compact 8 hextets without compression (stable for logs). */
    snprintf(out, out_len,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
             a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
}

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
    if (!ev || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->ts_ms = ts_ms;
    out->from_cpe = 1;
    out->is_destroy = ev->is_destroy || (ev->type == NFCT_EVENT_DESTROY);
    out->has_ct_id = ev->has_id;
    out->ct_id = ev->id;
    switch (ev->type) {
    case NFCT_EVENT_NEW: strcpy(out->event, "NEW"); break;
    case NFCT_EVENT_UPDATE: strcpy(out->event, "UPDATE"); break;
    case NFCT_EVENT_DESTROY: strcpy(out->event, "DESTROY"); break;
    default: strcpy(out->event, "PARTIAL"); break;
    }
    if (router_id) {
        strncpy(out->router_id, router_id, sizeof(out->router_id) - 1);
    }

    /* DESTROY may only carry id — still a valid observation for ingest */
    if (out->is_destroy && !ev->has_lan && !ev->has_wan && ev->has_id) {
        out->protocol = 0;
        return 0;
    }

    if (ev->is_ipv6) {
        uint8_t lan[16], wan[16];
        uint16_t lp = 0, wp = 0;
        uint8_t proto = 0;
        if (nfct_event_forensics_tuple_v6(ev, lan, &lp, wan, &wp, &proto) != 1) {
            return -1;
        }
        out->is_ipv6 = 1;
        memcpy(out->src_ip6, lan, 16);
        memcpy(out->wan_src_ip6, wan, 16);
        memcpy(out->dst_ip6, ev->lan_dst_ip6, 16);
        memcpy(out->wan_dst_ip6, ev->wan_dst_ip6, 16);
        out->src_port = lp;
        out->wan_src_port = wp;
        out->dst_port = ev->lan_dst_port;
        out->protocol = proto;
        return 0;
    }

    {
        uint32_t lan_ip = 0, wan_ip = 0;
        uint16_t lan_port = 0, wan_port = 0;
        uint8_t proto = 0;
        if (nfct_event_forensics_tuple(ev, &lan_ip, &lan_port, &wan_ip, &wan_port,
                                       &proto) != 1) {
            return -1;
        }
        out->src_ip = lan_ip;
        out->src_port = lan_port;
        out->dst_ip = ev->lan_dst_ip;
        out->dst_port = ev->lan_dst_port;
        out->wan_src_ip = wan_ip;
        out->wan_src_port = wan_port;
        out->protocol = proto;
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
    if (cpe->is_ipv6 || core->is_ipv6) {
        return 0; /* IPv4 path only for now */
    }
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
        if (obs->is_destroy && !obs->src_port && !obs->wan_src_port && obs->has_ct_id) {
            snprintf(buf, buflen,
                     "{\"type\":\"cpe_nat\",\"event\":\"DESTROY\",\"router\":\"%s\","
                     "\"ts\":%llu,\"ct_id\":%u}",
                     obs->router_id, (unsigned long long)obs->ts_ms,
                     (unsigned)obs->ct_id);
            return 0;
        }
        if (obs->is_ipv6) {
            char lan[48], wan[48];
            ipv6_hex(obs->src_ip6, lan, sizeof(lan));
            ipv6_hex(obs->wan_src_ip6, wan, sizeof(wan));
            if (obs->has_ct_id) {
                snprintf(buf, buflen,
                         "{\"type\":\"cpe_nat\",\"event\":\"%s\",\"router\":\"%s\","
                         "\"ts\":%llu,\"ip_version\":6,"
                         "\"lan\":\"[%s]:%u\",\"wan\":\"[%s]:%u\",\"proto\":%u,"
                         "\"ct_id\":%u}",
                         obs->event[0] ? obs->event : "NEW",
                         obs->router_id,
                         (unsigned long long)obs->ts_ms,
                         lan, (unsigned)obs->src_port,
                         wan, (unsigned)obs->wan_src_port,
                         (unsigned)obs->protocol, (unsigned)obs->ct_id);
            } else {
                snprintf(buf, buflen,
                         "{\"type\":\"cpe_nat\",\"event\":\"%s\",\"router\":\"%s\","
                         "\"ts\":%llu,\"ip_version\":6,"
                         "\"lan\":\"[%s]:%u\",\"wan\":\"[%s]:%u\",\"proto\":%u}",
                         obs->event[0] ? obs->event : "NEW",
                         obs->router_id,
                         (unsigned long long)obs->ts_ms,
                         lan, (unsigned)obs->src_port,
                         wan, (unsigned)obs->wan_src_port,
                         (unsigned)obs->protocol);
            }
            return 0;
        }
        if (obs->has_ct_id) {
            snprintf(buf, buflen,
                     "{\"type\":\"cpe_nat\",\"event\":\"%s\",\"router\":\"%s\","
                     "\"ts\":%llu,\"ip_version\":4,"
                     "\"lan\":\"%u.%u.%u.%u:%u\",\"wan\":\"%u.%u.%u.%u:%u\","
                     "\"proto\":%u,\"ct_id\":%u}",
                     obs->event[0] ? obs->event : "NEW",
                     obs->router_id,
                     (unsigned long long)obs->ts_ms,
                     (obs->src_ip >> 24) & 0xFF, (obs->src_ip >> 16) & 0xFF,
                     (obs->src_ip >> 8) & 0xFF, obs->src_ip & 0xFF, obs->src_port,
                     (obs->wan_src_ip >> 24) & 0xFF, (obs->wan_src_ip >> 16) & 0xFF,
                     (obs->wan_src_ip >> 8) & 0xFF, obs->wan_src_ip & 0xFF,
                     obs->wan_src_port, obs->protocol, (unsigned)obs->ct_id);
        } else {
            snprintf(buf, buflen,
                     "{\"type\":\"cpe_nat\",\"event\":\"%s\",\"router\":\"%s\","
                     "\"ts\":%llu,\"ip_version\":4,"
                     "\"lan\":\"%u.%u.%u.%u:%u\",\"wan\":\"%u.%u.%u.%u:%u\","
                     "\"proto\":%u}",
                     obs->event[0] ? obs->event : "NEW",
                     obs->router_id,
                     (unsigned long long)obs->ts_ms,
                     (obs->src_ip >> 24) & 0xFF, (obs->src_ip >> 16) & 0xFF,
                     (obs->src_ip >> 8) & 0xFF, obs->src_ip & 0xFF, obs->src_port,
                     (obs->wan_src_ip >> 24) & 0xFF, (obs->wan_src_ip >> 16) & 0xFF,
                     (obs->wan_src_ip >> 8) & 0xFF, obs->wan_src_ip & 0xFF,
                     obs->wan_src_port, obs->protocol);
        }
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
