/**
 * @file tcp_stats.c
 * @brief NFLOG TCP control-plane aggregation + NDJSON emit for cpe_agent.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"
#include "cpe_tcp_stats.h"
#include "nflog_netlink.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Accessors implemented in agent_core.c */
cpe_tcp_state_t *cpe_agent_tcp_state(cpe_agent_t *a);
const cpe_tcp_state_t *cpe_agent_tcp_state_const(const cpe_agent_t *a);
int cpe_agent_tcp_state_ensure(cpe_agent_t *a);

void cpe_tcp_state_init(cpe_tcp_state_t *st)
{
    if (!st) {
        return;
    }
    memset(st, 0, sizeof(*st));
    st->fd = -1;
    st->group = NFLOG_GROUP_DEFAULT;
    st->copy_range = NFLOG_COPY_RANGE_DEFAULT;
    st->prefix_len = 24;
    st->emit_interval_ms = 10000;
    st->emit_top_n = 20;
    st->snap.nflog_group = NFLOG_GROUP_DEFAULT;
    st->snap.prefix_len = 24;
}

float cpe_tcp_loss_hint(uint32_t syn, uint32_t fin, uint32_t rst,
                        uint32_t syn_retrans)
{
    double control = (double)syn + (double)fin + (double)rst;
    double bad;
    float h;

    if (control < 1.0) {
        return 0.0f;
    }
    bad = (double)rst + 0.5 * (double)syn_retrans;
    h = (float)(bad / control);
    if (h < 0.0f) {
        return 0.0f;
    }
    if (h > 1.0f) {
        return 1.0f;
    }
    return h;
}

static int is_private_v4(uint32_t be_addr)
{
    uint32_t a = ntohl(be_addr);
    /* 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 */
    if ((a & 0xff000000u) == 0x0a000000u) {
        return 1;
    }
    if ((a & 0xfff00000u) == 0xac100000u) {
        return 1;
    }
    if ((a & 0xffff0000u) == 0xc0a80000u) {
        return 1;
    }
    if ((a & 0xff000000u) == 0x7f000000u) {
        return 1;
    }
    if ((a & 0xffff0000u) == 0xa9fe0000u) {
        return 1;
    }
    return 0;
}

int cpe_tcp_parse_ip_packet(const uint8_t *pkt, size_t len,
                            cpe_tcp_packet_t *out)
{
    uint8_t ver;
    size_t ip_hdr_len;
    size_t off;
    const uint8_t *th;

    if (!pkt || !out || len < 20) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    ver = (uint8_t)(pkt[0] >> 4);

    if (ver == 4) {
        const struct iphdr *ip = (const struct iphdr *)pkt;
        if (ip->ihl < 5 || len < (size_t)ip->ihl * 4) {
            return -1;
        }
        if (ip->protocol != IPPROTO_TCP) {
            return -1;
        }
        ip_hdr_len = (size_t)ip->ihl * 4;
        if (len < ip_hdr_len + 14) {
            return -1;
        }
        th = pkt + ip_hdr_len;
        if (!inet_ntop(AF_INET, &ip->saddr, out->src_ip, sizeof(out->src_ip))) {
            return -1;
        }
        if (!inet_ntop(AF_INET, &ip->daddr, out->dst_ip, sizeof(out->dst_ip))) {
            return -1;
        }
        out->ip_len = ntohs(ip->tot_len);
        if (out->ip_len == 0) {
            out->ip_len = (uint16_t)len;
        }
        out->is_ipv6 = 0;
        out->src_port = (uint16_t)((th[0] << 8) | th[1]);
        out->dst_port = (uint16_t)((th[2] << 8) | th[3]);
        out->seq = ((uint32_t)th[4] << 24) | ((uint32_t)th[5] << 16) |
                   ((uint32_t)th[6] << 8) | (uint32_t)th[7];
        out->flags = th[13]; /* portable TCP flags byte */
        return 0;
    }

    if (ver == 6) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)pkt;
        uint8_t nx;
        if (len < sizeof(struct ip6_hdr) + 14) {
            return -1;
        }
        nx = ip6->ip6_nxt;
        off = sizeof(struct ip6_hdr);
        while (nx != IPPROTO_TCP && off + 8 <= len) {
            if (nx == IPPROTO_HOPOPTS || nx == IPPROTO_ROUTING ||
                nx == IPPROTO_DSTOPTS) {
                uint8_t ext_len = pkt[off + 1];
                nx = pkt[off];
                off += (size_t)(ext_len + 1) * 8;
            } else if (nx == IPPROTO_FRAGMENT) {
                nx = pkt[off];
                off += 8;
            } else {
                break;
            }
        }
        if (nx != IPPROTO_TCP || off + 14 > len) {
            return -1;
        }
        th = pkt + off;
        if (!inet_ntop(AF_INET6, &ip6->ip6_src, out->src_ip,
                       sizeof(out->src_ip))) {
            return -1;
        }
        if (!inet_ntop(AF_INET6, &ip6->ip6_dst, out->dst_ip,
                       sizeof(out->dst_ip))) {
            return -1;
        }
        out->ip_len = (uint16_t)(ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr));
        out->is_ipv6 = 1;
        out->src_port = (uint16_t)((th[0] << 8) | th[1]);
        out->dst_port = (uint16_t)((th[2] << 8) | th[3]);
        out->seq = ((uint32_t)th[4] << 24) | ((uint32_t)th[5] << 16) |
                   ((uint32_t)th[6] << 8) | (uint32_t)th[7];
        out->flags = th[13];
        return 0;
    }

    return -1;
}

int cpe_tcp_format_ndjson(const char *router_id, const char *scope,
                          const cpe_tcp_snapshot_t *snap,
                          const cpe_tcp_remote_t *remote,
                          const cpe_tcp_prefix_t *prefix, char *buf,
                          size_t buflen)
{
    const char *rid = router_id && router_id[0] ? router_id : "unknown";
    const char *sc = scope && scope[0] ? scope : "summary";
    const char *ts;
    int n;

    if (!snap || !buf || buflen < 64) {
        return -1;
    }
    ts = snap->ts_iso[0] ? snap->ts_iso : "1970-01-01T00:00:00.000Z";

    if (strcmp(sc, "remote") == 0 && remote) {
        float loss = cpe_tcp_loss_hint(remote->syn_count, remote->fin_count,
                                       remote->rst_count, remote->syn_retrans);
        n = snprintf(
            buf, buflen,
            "{\"type\":\"cpe_tcp\",\"ts\":\"%s\",\"router_id\":\"%s\","
            "\"scope\":\"remote\",\"remote_ip\":\"%s\",\"local_ip\":\"%s\","
            "\"remote_port\":%u,\"local_port\":%u,"
            "\"syn\":%u,\"fin\":%u,\"rst\":%u,\"syn_retrans\":%u,"
            "\"pkts\":%u,\"bytes\":%llu,\"loss_hint\":%.4f,"
            "\"nflog_group\":%u}",
            ts, rid, remote->remote_ip, remote->local_ip,
            (unsigned)remote->remote_port, (unsigned)remote->local_port,
            (unsigned)remote->syn_count, (unsigned)remote->fin_count,
            (unsigned)remote->rst_count, (unsigned)remote->syn_retrans,
            (unsigned)remote->pkt_count,
            (unsigned long long)remote->bytes_est, (double)loss,
            (unsigned)snap->nflog_group);
    } else if (strcmp(sc, "prefix") == 0 && prefix) {
        float loss = cpe_tcp_loss_hint(prefix->syn_count, prefix->fin_count,
                                       prefix->rst_count, prefix->syn_retrans);
        n = snprintf(
            buf, buflen,
            "{\"type\":\"cpe_tcp\",\"ts\":\"%s\",\"router_id\":\"%s\","
            "\"scope\":\"prefix\",\"prefix\":\"%s\","
            "\"syn\":%u,\"fin\":%u,\"rst\":%u,\"syn_retrans\":%u,"
            "\"pkts\":%u,\"bytes\":%llu,\"remotes\":%u,\"loss_hint\":%.4f,"
            "\"nflog_group\":%u}",
            ts, rid, prefix->prefix, (unsigned)prefix->syn_count,
            (unsigned)prefix->fin_count, (unsigned)prefix->rst_count,
            (unsigned)prefix->syn_retrans, (unsigned)prefix->pkt_count,
            (unsigned long long)prefix->bytes_est,
            (unsigned)prefix->remote_count, (double)loss,
            (unsigned)snap->nflog_group);
    } else {
        float loss = cpe_tcp_loss_hint(snap->syn_total, snap->fin_total,
                                       snap->rst_total, snap->syn_retrans_total);
        n = snprintf(
            buf, buflen,
            "{\"type\":\"cpe_tcp\",\"ts\":\"%s\",\"router_id\":\"%s\","
            "\"scope\":\"summary\",\"syn\":%u,\"fin\":%u,\"rst\":%u,"
            "\"syn_retrans\":%u,\"pkts\":%u,\"bytes\":%llu,"
            "\"remotes\":%u,\"prefixes\":%u,\"loss_hint\":%.4f,"
            "\"prefix_len\":%u,\"nflog_group\":%u,"
            "\"pkts_parsed\":%llu,\"pkts_non_tcp\":%llu,"
            "\"pkts_parse_fail\":%llu}",
            ts, rid, (unsigned)snap->syn_total, (unsigned)snap->fin_total,
            (unsigned)snap->rst_total, (unsigned)snap->syn_retrans_total,
            (unsigned)snap->pkt_total, (unsigned long long)snap->bytes_total,
            (unsigned)snap->remote_count, (unsigned)snap->prefix_count,
            (double)loss, (unsigned)snap->prefix_len,
            (unsigned)snap->nflog_group,
            (unsigned long long)snap->pkts_parsed,
            (unsigned long long)snap->pkts_non_tcp,
            (unsigned long long)snap->pkts_parse_fail);
    }
    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }
    return n;
}

static void iso_now(char *out, size_t n)
{
    struct timespec ts;
    struct tm tm;
    time_t sec;
    int ms;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    sec = ts.tv_sec;
    ms = (int)(ts.tv_nsec / 1000000L);
    if (ms < 0) {
        ms = 0;
    } else if (ms > 999) {
        ms = 999;
    }
    if (!gmtime_r(&sec, &tm)) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    /* Fixed 24-char ISO-8601 + NUL; clamp fields so -Wformat-truncation is quiet. */
    {
        int y = tm.tm_year + 1900;
        int mo = tm.tm_mon + 1;
        int d = tm.tm_mday;
        int h = tm.tm_hour;
        int mi = tm.tm_min;
        int s = tm.tm_sec;
        if (y < 0) {
            y = 0;
        } else if (y > 9999) {
            y = 9999;
        }
        if (mo < 1) {
            mo = 1;
        } else if (mo > 12) {
            mo = 12;
        }
        if (d < 1) {
            d = 1;
        } else if (d > 31) {
            d = 31;
        }
        if (h < 0) {
            h = 0;
        } else if (h > 23) {
            h = 23;
        }
        if (mi < 0) {
            mi = 0;
        } else if (mi > 59) {
            mi = 59;
        }
        if (s < 0) {
            s = 0;
        } else if (s > 60) {
            s = 60;
        }
        snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, mo, d, h, mi,
                 s, ms);
    }
}

static uint64_t mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint32_t ip4_parse(const char *s)
{
    struct in_addr a;
    if (!s || inet_pton(AF_INET, s, &a) != 1) {
        return 0;
    }
    return a.s_addr; /* network order */
}

static void prefix_from_ip4(uint32_t be_addr, uint8_t plen, char *out,
                            size_t out_sz)
{
    uint32_t host = ntohl(be_addr);
    uint32_t mask;
    uint32_t net;
    struct in_addr a;

    if (plen == 0 || plen > 32) {
        plen = 24;
    }
    if (plen == 32) {
        mask = 0xffffffffu;
    } else {
        mask = 0xffffffffu << (32 - plen);
    }
    net = host & mask;
    a.s_addr = htonl(net);
    inet_ntop(AF_INET, &a, out, (socklen_t)out_sz);
    {
        size_t n = strlen(out);
        if (n + 4 < out_sz) {
            snprintf(out + n, out_sz - n, "/%u", (unsigned)plen);
        }
    }
}

static int remote_index(cpe_tcp_snapshot_t *s, const char *remote_ip)
{
    uint32_t i;
    int free_i = -1;

    for (i = 0; i < s->remote_count; i++) {
        if (strcmp(s->remotes[i].remote_ip, remote_ip) == 0) {
            return (int)i;
        }
    }
    if (s->remote_count < CPE_TCP_REMOTE_MAX) {
        free_i = (int)s->remote_count;
        memset(&s->remotes[free_i], 0, sizeof(s->remotes[free_i]));
        snprintf(s->remotes[free_i].remote_ip,
                 sizeof(s->remotes[free_i].remote_ip), "%s", remote_ip);
        s->remote_count++;
        return free_i;
    }
    /* Evict lowest pkt_count slot. */
    {
        uint32_t best = 0;
        for (i = 1; i < CPE_TCP_REMOTE_MAX; i++) {
            if (s->remotes[i].pkt_count < s->remotes[best].pkt_count) {
                best = i;
            }
        }
        memset(&s->remotes[best], 0, sizeof(s->remotes[best]));
        snprintf(s->remotes[best].remote_ip, sizeof(s->remotes[best].remote_ip),
                 "%s", remote_ip);
        return (int)best;
    }
}

static int prefix_index(cpe_tcp_snapshot_t *s, const char *prefix)
{
    uint32_t i;

    for (i = 0; i < s->prefix_count; i++) {
        if (strcmp(s->prefixes[i].prefix, prefix) == 0) {
            return (int)i;
        }
    }
    if (s->prefix_count < CPE_TCP_PREFIX_MAX) {
        int idx = (int)s->prefix_count;
        memset(&s->prefixes[idx], 0, sizeof(s->prefixes[idx]));
        snprintf(s->prefixes[idx].prefix, sizeof(s->prefixes[idx].prefix), "%s",
                 prefix);
        s->prefix_count++;
        return idx;
    }
    {
        uint32_t best = 0;
        for (i = 1; i < CPE_TCP_PREFIX_MAX; i++) {
            if (s->prefixes[i].pkt_count < s->prefixes[best].pkt_count) {
                best = i;
            }
        }
        memset(&s->prefixes[best], 0, sizeof(s->prefixes[best]));
        snprintf(s->prefixes[best].prefix, sizeof(s->prefixes[best].prefix),
                 "%s", prefix);
        return (int)best;
    }
}

static int flow_is_retrans(cpe_tcp_state_t *st, uint32_t sip, uint32_t dip,
                           uint16_t sport, uint16_t dport, uint32_t seq)
{
    size_t i;
    for (i = 0; i < sizeof(st->flows) / sizeof(st->flows[0]); i++) {
        if (!st->flows[i].used) {
            continue;
        }
        if (st->flows[i].sip == sip && st->flows[i].dip == dip &&
            st->flows[i].sport == sport && st->flows[i].dport == dport) {
            /* Same 4-tuple SYN seen again → retransmission / retry. */
            st->flows[i].seq = seq;
            return 1;
        }
    }
    st->flows[st->flow_i].sip = sip;
    st->flows[st->flow_i].dip = dip;
    st->flows[st->flow_i].sport = sport;
    st->flows[st->flow_i].dport = dport;
    st->flows[st->flow_i].seq = seq;
    st->flows[st->flow_i].used = 1;
    st->flow_i = (st->flow_i + 1) % (sizeof(st->flows) / sizeof(st->flows[0]));
    return 0;
}

static void apply_packet(cpe_tcp_state_t *st, const cpe_tcp_packet_t *pkt)
{
    cpe_tcp_snapshot_t *s = &st->snap;
    char remote_ip[CPE_TCP_IP_MAX];
    char local_ip[CPE_TCP_IP_MAX];
    uint16_t rport, lport;
    int ri, pi;
    uint32_t sip, dip;
    int is_syn, is_fin, is_rst;
    int retrans = 0;
    char pfx[CPE_TCP_PREFIX_STR_MAX];

    sip = ip4_parse(pkt->src_ip);
    dip = ip4_parse(pkt->dst_ip);

    /* Prefer public as remote when one side is private. */
    if (!pkt->is_ipv6 && sip && dip) {
        int sp = is_private_v4(sip);
        int dp = is_private_v4(dip);
        if (sp && !dp) {
            snprintf(local_ip, sizeof(local_ip), "%s", pkt->src_ip);
            snprintf(remote_ip, sizeof(remote_ip), "%s", pkt->dst_ip);
            lport = pkt->src_port;
            rport = pkt->dst_port;
        } else if (dp && !sp) {
            snprintf(local_ip, sizeof(local_ip), "%s", pkt->dst_ip);
            snprintf(remote_ip, sizeof(remote_ip), "%s", pkt->src_ip);
            lport = pkt->dst_port;
            rport = pkt->src_port;
        } else {
            snprintf(local_ip, sizeof(local_ip), "%s", pkt->src_ip);
            snprintf(remote_ip, sizeof(remote_ip), "%s", pkt->dst_ip);
            lport = pkt->src_port;
            rport = pkt->dst_port;
        }
    } else {
        snprintf(local_ip, sizeof(local_ip), "%s", pkt->src_ip);
        snprintf(remote_ip, sizeof(remote_ip), "%s", pkt->dst_ip);
        lport = pkt->src_port;
        rport = pkt->dst_port;
    }

    is_syn = (pkt->flags & CPE_TCP_FLAG_SYN) && !(pkt->flags & CPE_TCP_FLAG_ACK);
    /* Count SYN+ACK as syn for completeness (handshake presence). */
    if (!is_syn && (pkt->flags & CPE_TCP_FLAG_SYN)) {
        is_syn = 1; /* SYN-ACK still indicates connection setup traffic */
    }
    is_fin = (pkt->flags & CPE_TCP_FLAG_FIN) != 0;
    is_rst = (pkt->flags & CPE_TCP_FLAG_RST) != 0;

    if (is_syn && !pkt->is_ipv6 && sip && dip) {
        retrans = flow_is_retrans(st, sip, dip, pkt->src_port, pkt->dst_port,
                                  pkt->seq);
    }

    s->pkt_total++;
    s->bytes_total += pkt->ip_len;
    if (is_syn) {
        s->syn_total++;
    }
    if (is_fin) {
        s->fin_total++;
    }
    if (is_rst) {
        s->rst_total++;
    }
    if (retrans) {
        s->syn_retrans_total++;
    }

    ri = remote_index(s, remote_ip);
    if (ri >= 0) {
        cpe_tcp_remote_t *r = &s->remotes[ri];
        snprintf(r->local_ip, sizeof(r->local_ip), "%s", local_ip);
        r->remote_port = rport;
        r->local_port = lport;
        r->pkt_count++;
        r->bytes_est += pkt->ip_len;
        r->last_seen_ms = mono_ms();
        if (is_syn) {
            r->syn_count++;
        }
        if (is_fin) {
            r->fin_count++;
        }
        if (is_rst) {
            r->rst_count++;
        }
        if (retrans) {
            r->syn_retrans++;
        }
    }

    if (!pkt->is_ipv6) {
        uint32_t raddr = ip4_parse(remote_ip);
        if (raddr) {
            prefix_from_ip4(raddr, st->prefix_len ? st->prefix_len : 24, pfx,
                            sizeof(pfx));
            pi = prefix_index(s, pfx);
            if (pi >= 0) {
                cpe_tcp_prefix_t *p = &s->prefixes[pi];
                p->pkt_count++;
                p->bytes_est += pkt->ip_len;
                if (is_syn) {
                    p->syn_count++;
                }
                if (is_fin) {
                    p->fin_count++;
                }
                if (is_rst) {
                    p->rst_count++;
                }
                if (retrans) {
                    p->syn_retrans++;
                }
                /* Approximate unique remotes via bump once per remote touch. */
                if (ri >= 0 && s->remotes[ri].pkt_count == 1) {
                    p->remote_count++;
                }
            }
        }
    }

    iso_now(s->ts_iso, sizeof(s->ts_iso));
}

static void on_nflog_payload(void *opaque, const uint8_t *payload,
                             size_t payload_len, uint16_t hw_protocol,
                             uint32_t mark, uint64_t ts_sec, uint64_t ts_usec)
{
    cpe_tcp_state_t *st = (cpe_tcp_state_t *)opaque;
    cpe_tcp_packet_t pkt;

    (void)hw_protocol;
    (void)mark;
    (void)ts_sec;
    (void)ts_usec;

    if (!st) {
        return;
    }
    st->snap.pkts_parsed++;
    if (cpe_tcp_parse_ip_packet(payload, payload_len, &pkt) != 0) {
        /* May be non-TCP or truncated below TCP hdr. */
        if (payload_len >= 1) {
            uint8_t ver = (uint8_t)(payload[0] >> 4);
            if (ver == 4 && payload_len >= 10 && payload[9] != IPPROTO_TCP) {
                st->snap.pkts_non_tcp++;
            } else if (ver == 6 && payload_len >= 7 &&
                       payload[6] != IPPROTO_TCP) {
                st->snap.pkts_non_tcp++;
            } else {
                st->snap.pkts_parse_fail++;
            }
        } else {
            st->snap.pkts_parse_fail++;
        }
        return;
    }
    apply_packet(st, &pkt);
}

/* ---- Public agent API (declared in cpe_agent.h) ---- */

/* Implemented with state accessor provided by agent_core. */

int cpe_agent_tcp_open(cpe_agent_t *a)
{
    cpe_tcp_state_t *st;
    const cpe_agent_config_t *cfg;
    char err[128];
    int fd;

    if (!a || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    cfg = cpe_agent_config(a);
    if (!st || !cfg) {
        return -1;
    }
    if (st->fd >= 0) {
        return 0;
    }
    st->group = cfg->tcp_nflog_group ? cfg->tcp_nflog_group : NFLOG_GROUP_DEFAULT;
    st->copy_range =
        cfg->tcp_nflog_size ? cfg->tcp_nflog_size : NFLOG_COPY_RANGE_DEFAULT;
    st->prefix_len = cfg->tcp_prefix_len ? (uint8_t)cfg->tcp_prefix_len : 24;
    st->emit_interval_ms =
        cfg->tcp_emit_interval_ms ? cfg->tcp_emit_interval_ms : 10000;
    st->emit_top_n = cfg->tcp_emit_top_n ? cfg->tcp_emit_top_n : 20;
    st->enabled = cfg->tcp_stats_enabled;
    st->snap.nflog_group = st->group;
    st->snap.prefix_len = st->prefix_len;

    if (!st->enabled) {
        return 0;
    }

    err[0] = '\0';
    fd = nflog_netlink_open(st->group, st->copy_range, err, sizeof(err));
    if (fd < 0) {
        if (err[0]) {
            /* Truncate safely into open_err (may be shorter than err). */
            size_t el = strlen(err);
            if (el >= sizeof(st->open_err)) {
                el = sizeof(st->open_err) - 1;
            }
            memcpy(st->open_err, err, el);
            st->open_err[el] = '\0';
        } else {
            snprintf(st->open_err, sizeof(st->open_err), "nflog open failed");
        }
        st->open_ok = 0;
        return -1;
    }
    (void)nflog_netlink_set_nonblock(fd);
    st->fd = fd;
    st->open_ok = 1;
    st->open_err[0] = '\0';
    return 0;
}

void cpe_agent_tcp_close(cpe_agent_t *a)
{
    cpe_tcp_state_t *st = a ? cpe_agent_tcp_state(a) : NULL;
    if (!st) {
        return;
    }
    if (st->fd >= 0) {
        nflog_netlink_close(st->fd);
        st->fd = -1;
    }
    st->open_ok = 0;
}

int cpe_agent_tcp_poll(cpe_agent_t *a, unsigned max_msgs)
{
    cpe_tcp_state_t *st;
    uint8_t buf[8192];
    unsigned n = 0;
    unsigned limit = max_msgs ? max_msgs : 64;
    int rd;
    int walked;
    int total_pkts = 0;

    if (!a || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    if (!st) {
        return -1;
    }
    if (!st->enabled) {
        return 0;
    }
    if (st->fd < 0) {
        if (cpe_agent_tcp_open(a) != 0) {
            return 0; /* soft: no privileges yet */
        }
    }
    if (st->fd < 0) {
        return 0;
    }

    while (n < limit) {
        rd = nflog_netlink_recv(st->fd, buf, sizeof(buf));
        if (rd == 0) {
            break;
        }
        if (rd < 0) {
            break;
        }
        walked = nflog_netlink_walk(buf, (size_t)rd, on_nflog_payload, st);
        if (walked > 0) {
            total_pkts += walked;
        }
        n++;
    }
    return total_pkts;
}

int cpe_agent_tcp_feed_payload(cpe_agent_t *a, const uint8_t *ip_pkt,
                               size_t len)
{
    cpe_tcp_state_t *st;
    cpe_tcp_packet_t pkt;

    if (!a || !ip_pkt || len == 0 || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    if (!st) {
        return -1;
    }
    st->snap.pkts_parsed++;
    if (cpe_tcp_parse_ip_packet(ip_pkt, len, &pkt) != 0) {
        st->snap.pkts_parse_fail++;
        return -1;
    }
    apply_packet(st, &pkt);
    return 0;
}

int cpe_agent_tcp_feed_nflog(cpe_agent_t *a, const uint8_t *nl_msg, size_t len)
{
    cpe_tcp_state_t *st;

    if (!a || !nl_msg || len == 0 || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    if (!st) {
        return -1;
    }
    return nflog_netlink_walk(nl_msg, len, on_nflog_payload, st);
}

int cpe_agent_tcp_snapshot(const cpe_agent_t *a, cpe_tcp_snapshot_t *out)
{
    const cpe_tcp_state_t *st;

    if (!a || !out) {
        return -1;
    }
    st = cpe_agent_tcp_state_const(a);
    if (!st) {
        return -1;
    }
    *out = st->snap;
    return 0;
}

int cpe_agent_tcp_remote(const cpe_agent_t *a, const char *remote_ip,
                         cpe_tcp_remote_t *out)
{
    const cpe_tcp_state_t *st;
    uint32_t i;

    if (!a || !remote_ip || !out) {
        return -1;
    }
    st = cpe_agent_tcp_state_const(a);
    if (!st) {
        return -1;
    }
    for (i = 0; i < st->snap.remote_count; i++) {
        if (strcmp(st->snap.remotes[i].remote_ip, remote_ip) == 0) {
            *out = st->snap.remotes[i];
            return 0;
        }
    }
    return -1;
}

int cpe_agent_tcp_prefix(const cpe_agent_t *a, const char *prefix,
                         cpe_tcp_prefix_t *out)
{
    const cpe_tcp_state_t *st;
    uint32_t i;

    if (!a || !prefix || !out) {
        return -1;
    }
    st = cpe_agent_tcp_state_const(a);
    if (!st) {
        return -1;
    }
    for (i = 0; i < st->snap.prefix_count; i++) {
        if (strcmp(st->snap.prefixes[i].prefix, prefix) == 0) {
            *out = st->snap.prefixes[i];
            return 0;
        }
    }
    return -1;
}

void cpe_agent_tcp_reset(cpe_agent_t *a)
{
    cpe_tcp_state_t *st;
    uint16_t group;
    uint8_t plen;

    if (!a || cpe_agent_tcp_state_ensure(a) != 0) {
        return;
    }
    st = cpe_agent_tcp_state(a);
    if (!st) {
        return;
    }
    group = st->snap.nflog_group;
    plen = st->snap.prefix_len;
    memset(&st->snap, 0, sizeof(st->snap));
    memset(st->flows, 0, sizeof(st->flows));
    st->flow_i = 0;
    st->snap.nflog_group = group;
    st->snap.prefix_len = plen;
    iso_now(st->snap.ts_iso, sizeof(st->snap.ts_iso));
}

static int cmp_remote_pkts(const void *x, const void *y)
{
    const cpe_tcp_remote_t *a = (const cpe_tcp_remote_t *)x;
    const cpe_tcp_remote_t *b = (const cpe_tcp_remote_t *)y;
    if (a->pkt_count < b->pkt_count) {
        return 1;
    }
    if (a->pkt_count > b->pkt_count) {
        return -1;
    }
    return 0;
}

static int cmp_prefix_pkts(const void *x, const void *y)
{
    const cpe_tcp_prefix_t *a = (const cpe_tcp_prefix_t *)x;
    const cpe_tcp_prefix_t *b = (const cpe_tcp_prefix_t *)y;
    if (a->pkt_count < b->pkt_count) {
        return 1;
    }
    if (a->pkt_count > b->pkt_count) {
        return -1;
    }
    return 0;
}

int cpe_agent_tcp_emit(cpe_agent_t *a, unsigned top_n)
{
    cpe_tcp_state_t *st;
    const cpe_agent_config_t *cfg;
    cpe_tcp_snapshot_t snap;
    char line[CPE_TCP_NDJSON_MAX];
    unsigned n_rem;
    unsigned n_pfx;
    unsigned i;
    int lines = 0;
    cpe_tcp_remote_t rem_sorted[CPE_TCP_REMOTE_MAX];
    cpe_tcp_prefix_t pfx_sorted[CPE_TCP_PREFIX_MAX];

    if (!a || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    cfg = cpe_agent_config(a);
    if (!st || !cfg) {
        return -1;
    }

    iso_now(st->snap.ts_iso, sizeof(st->snap.ts_iso));
    snap = st->snap;

    if (cpe_tcp_format_ndjson(cfg->router_id, "summary", &snap, NULL, NULL,
                              line, sizeof(line)) < 0) {
        return -1;
    }
    if (cpe_agent_spool_push_line(a, line) == 0) {
        lines++;
    }

    n_rem = snap.remote_count;
    if (n_rem > CPE_TCP_REMOTE_MAX) {
        n_rem = CPE_TCP_REMOTE_MAX;
    }
    memcpy(rem_sorted, snap.remotes, n_rem * sizeof(rem_sorted[0]));
    if (n_rem > 1) {
        qsort(rem_sorted, n_rem, sizeof(rem_sorted[0]), cmp_remote_pkts);
    }
    if (top_n == 0) {
        top_n = st->emit_top_n ? st->emit_top_n : 20;
    }
    if (top_n > n_rem) {
        top_n = n_rem;
    }
    for (i = 0; i < top_n; i++) {
        if (cpe_tcp_format_ndjson(cfg->router_id, "remote", &snap,
                                  &rem_sorted[i], NULL, line,
                                  sizeof(line)) < 0) {
            continue;
        }
        if (cpe_agent_spool_push_line(a, line) == 0) {
            lines++;
        }
    }

    n_pfx = snap.prefix_count;
    if (n_pfx > CPE_TCP_PREFIX_MAX) {
        n_pfx = CPE_TCP_PREFIX_MAX;
    }
    memcpy(pfx_sorted, snap.prefixes, n_pfx * sizeof(pfx_sorted[0]));
    if (n_pfx > 1) {
        qsort(pfx_sorted, n_pfx, sizeof(pfx_sorted[0]), cmp_prefix_pkts);
    }
    {
        unsigned lim = top_n;
        if (lim > n_pfx) {
            lim = n_pfx;
        }
        for (i = 0; i < lim; i++) {
            if (cpe_tcp_format_ndjson(cfg->router_id, "prefix", &snap, NULL,
                                      &pfx_sorted[i], line, sizeof(line)) < 0) {
                continue;
            }
            if (cpe_agent_spool_push_line(a, line) == 0) {
                lines++;
            }
        }
    }

    st->last_emit_ms = mono_ms();
    return lines;
}

int cpe_agent_tcp_tick(cpe_agent_t *a)
{
    cpe_tcp_state_t *st;
    const cpe_agent_config_t *cfg;
    uint64_t now;
    int polled;

    if (!a || cpe_agent_tcp_state_ensure(a) != 0) {
        return -1;
    }
    st = cpe_agent_tcp_state(a);
    cfg = cpe_agent_config(a);
    if (!st || !cfg || !cfg->tcp_stats_enabled) {
        return 0;
    }
    st->enabled = 1;
    st->prefix_len =
        cfg->tcp_prefix_len ? (uint8_t)cfg->tcp_prefix_len : st->prefix_len;
    st->snap.prefix_len = st->prefix_len;
    st->snap.nflog_group =
        cfg->tcp_nflog_group ? cfg->tcp_nflog_group : st->snap.nflog_group;
    st->emit_interval_ms = cfg->tcp_emit_interval_ms
                               ? cfg->tcp_emit_interval_ms
                               : st->emit_interval_ms;
    st->emit_top_n = cfg->tcp_emit_top_n ? cfg->tcp_emit_top_n : st->emit_top_n;

    polled = cpe_agent_tcp_poll(a, 128);
    (void)polled;

    now = mono_ms();
    if (st->last_emit_ms == 0 ||
        now - st->last_emit_ms >= (uint64_t)st->emit_interval_ms) {
        return cpe_agent_tcp_emit(a, st->emit_top_n);
    }
    return 0;
}

const char *cpe_agent_tcp_last_error(const cpe_agent_t *a)
{
    const cpe_tcp_state_t *st = a ? cpe_agent_tcp_state_const(a) : NULL;
    if (!st || !st->open_err[0]) {
        return NULL;
    }
    return st->open_err;
}

int cpe_agent_tcp_fd(const cpe_agent_t *a)
{
    const cpe_tcp_state_t *st = a ? cpe_agent_tcp_state_const(a) : NULL;
    return st ? st->fd : -1;
}
