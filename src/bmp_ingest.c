/**
 * @file bmp_ingest.c
 * @brief App-side glue: libbmp events → forensics observations / NDJSON.
 *
 * libbmp owns parsing (no I/O). This module owns policy: router_id labeling,
 * formatting for Vector/ClickHouse, and observation shaping.
 */

#include "bmp_ingest.h"

#include <stdio.h>
#include <string.h>

static void format_peer_addr(const bmp_peer_header_t *ph, char *out, size_t out_len)
{
    if (!ph || !out || out_len == 0) {
        return;
    }
    if (ph->is_ipv6) {
        snprintf(out, out_len,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ph->peer_address[0], ph->peer_address[1],
                 ph->peer_address[2], ph->peer_address[3],
                 ph->peer_address[4], ph->peer_address[5],
                 ph->peer_address[6], ph->peer_address[7],
                 ph->peer_address[8], ph->peer_address[9],
                 ph->peer_address[10], ph->peer_address[11],
                 ph->peer_address[12], ph->peer_address[13],
                 ph->peer_address[14], ph->peer_address[15]);
    } else {
        /* IPv4 in last 4 bytes (RFC 7854) */
        snprintf(out, out_len, "%u.%u.%u.%u",
                 ph->peer_address[12], ph->peer_address[13],
                 ph->peer_address[14], ph->peer_address[15]);
    }
}

int nf_obs_from_bmp(const bmp_event_t *ev, const char *router_id, nf_bmp_obs_t *out)
{
    if (!ev || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (router_id) {
        strncpy(out->router_id, router_id, sizeof(out->router_id) - 1);
    }

    switch (ev->type) {
    case BMP_EVENT_INITIATION:
        strcpy(out->event, "initiation");
        break;
    case BMP_EVENT_TERMINATION:
        strcpy(out->event, "termination");
        break;
    case BMP_EVENT_PEER_UP:
        strcpy(out->event, "peer_up");
        out->has_peer = 1;
        break;
    case BMP_EVENT_PEER_DOWN:
        strcpy(out->event, "peer_down");
        out->has_peer = 1;
        break;
    case BMP_EVENT_ROUTE_MONITORING:
        strcpy(out->event, "route");
        out->has_peer = 1;
        break;
    case BMP_EVENT_STATISTICS:
        strcpy(out->event, "stats");
        out->has_peer = 1;
        break;
    case BMP_EVENT_QUEUE_OVERFLOW:
        strcpy(out->event, "queue_overflow");
        break;
    case BMP_EVENT_ERROR:
        strcpy(out->event, "error");
        break;
    default:
        return -1;
    }

    if (out->has_peer) {
        out->peer_as = ev->peer.peer_as;
        out->peer_bgp_id = ev->peer.peer_bgp_id;
        out->peer_is_ipv6 = ev->peer.is_ipv6;
        memcpy(out->peer_addr, ev->peer.peer_address, 16);
        out->ts_ms = (uint64_t)ev->peer.timestamp_sec * 1000ull +
                     (uint64_t)ev->peer.timestamp_usec / 1000ull;
        format_peer_addr(&ev->peer, out->peer_addr_str, sizeof(out->peer_addr_str));
    }

    out->payload_len = ev->payload_len;
    out->payload_truncated = ev->payload_truncated;
    return 0;
}

int nf_bmp_obs_format(const nf_bmp_obs_t *obs, char *buf, size_t buflen)
{
    if (!obs || !buf || buflen < 32) {
        return -1;
    }
    if (obs->has_peer) {
        snprintf(buf, buflen,
                 "{\"type\":\"bmp\",\"router\":\"%s\",\"event\":\"%s\","
                 "\"ts\":%llu,\"peer_as\":%u,\"peer_bgp_id\":\"%u.%u.%u.%u\","
                 "\"peer_addr\":\"%s\",\"payload_len\":%zu%s}",
                 obs->router_id, obs->event,
                 (unsigned long long)obs->ts_ms,
                 (unsigned)obs->peer_as,
                 (obs->peer_bgp_id >> 24) & 0xFF,
                 (obs->peer_bgp_id >> 16) & 0xFF,
                 (obs->peer_bgp_id >> 8) & 0xFF,
                 obs->peer_bgp_id & 0xFF,
                 obs->peer_addr_str[0] ? obs->peer_addr_str : "",
                 obs->payload_len,
                 obs->payload_truncated ? ",\"payload_truncated\":true" : "");
    } else {
        snprintf(buf, buflen,
                 "{\"type\":\"bmp\",\"router\":\"%s\",\"event\":\"%s\","
                 "\"payload_len\":%zu%s}",
                 obs->router_id, obs->event, obs->payload_len,
                 obs->payload_truncated ? ",\"payload_truncated\":true" : "");
    }
    return 0;
}

static int drain_obs(bmp_ctx_t *ctx, const char *router_id,
                     nf_bmp_obs_t *out, size_t max_out, size_t *n_out)
{
    bmp_event_t ev;
    size_t n = *n_out;
    while (n < max_out && bmp_next_event(ctx, &ev) == 1) {
        if (nf_obs_from_bmp(&ev, router_id, &out[n]) == 0) {
            n++;
        }
    }
    *n_out = n;
    return 0;
}

int nf_bmp_collect(bmp_ctx_t *ctx, const uint8_t *msg, size_t len,
                   const char *router_id, nf_bmp_obs_t *out, size_t max_out)
{
    size_t n = 0;
    if (!ctx || !msg || !out || max_out == 0) {
        return -1;
    }
    if (bmp_feed_message(ctx, msg, len) != 0) {
        /* Still drain any ERROR events */
    }
    (void)drain_obs(ctx, router_id, out, max_out, &n);
    return (int)n;
}

int nf_bmp_collect_stream(bmp_ctx_t *ctx, const uint8_t *data, size_t len,
                          const char *router_id, nf_bmp_obs_t *out, size_t max_out)
{
    size_t n = 0;
    if (!ctx || !data || !out || max_out == 0) {
        return -1;
    }
    (void)bmp_feed_input(ctx, data, len);
    (void)drain_obs(ctx, router_id, out, max_out, &n);
    return (int)n;
}
