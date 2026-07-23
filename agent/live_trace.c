/**
 * @file live_trace.c
 * @brief Host-owned traceroute / mtr → hop table + cpe_perf summary.
 *
 * libnetdiag remains syscall-free. This file owns sockets:
 *   1) UDP + IP_RECVERR (Linux; classic traceroute ports)
 *   2) ICMP echo with IP_TTL (SOCK_DGRAM / SOCK_RAW fallback)
 *
 * Synthetic demo path is C-only (tests/fuzz); not registered on Lua.
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/errqueue.h>
#include <linux/types.h>
#endif

#ifndef CPE_TRACE_BASE_PORT
#define CPE_TRACE_BASE_PORT 33434
#endif

struct cpe_icmp_echo {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t  payload[8];
};

enum probe_outcome {
    PROBE_TIMEOUT = 0,
    PROBE_HOP,       /* ICMP Time Exceeded (or equivalent) */
    PROBE_DEST       /* destination reached */
};

static uint16_t icmp_cksum(const void *data, size_t len)
{
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len) {
        sum += *(const uint8_t *)p;
    }
    while (sum >> 16) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint64_t mono_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
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
    ms = (int)(ts.tv_nsec / 1000000);
    if (!gmtime_r(&sec, &tm)) {
        snprintf(out, n, "1970-01-01T00:00:00.000Z");
        return;
    }
    {
        int y = tm.tm_year + 1900;
        if (y < 0) {
            y = 0;
        }
        if (y > 9999) {
            y = 9999;
        }
        snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, tm.tm_mon + 1,
                 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
    }
}

static void hop_init(cpe_trace_hop_t *h, int hop)
{
    memset(h, 0, sizeof(*h));
    h->hop = hop;
    h->min_rtt_ms = 0.0;
}

static void hop_record(cpe_trace_hop_t *h, int success, const char *addr,
                       double rtt_ms, int reached_dest)
{
    h->sent++;
    if (!success) {
        h->timeouts++;
        if (h->sent > 0) {
            h->loss = (float)h->timeouts / (float)h->sent;
        }
        return;
    }
    h->replies++;
    if (addr && addr[0]) {
        snprintf(h->addr, sizeof(h->addr), "%s", addr);
    }
    h->last_rtt_ms = rtt_ms;
    if (h->replies == 1) {
        h->min_rtt_ms = rtt_ms;
        h->max_rtt_ms = rtt_ms;
        h->avg_rtt_ms = rtt_ms;
    } else {
        if (rtt_ms < h->min_rtt_ms) {
            h->min_rtt_ms = rtt_ms;
        }
        if (rtt_ms > h->max_rtt_ms) {
            h->max_rtt_ms = rtt_ms;
        }
        h->avg_rtt_ms =
            ((h->avg_rtt_ms * (double)(h->replies - 1)) + rtt_ms) /
            (double)h->replies;
    }
    if (reached_dest) {
        h->reached_dest = 1;
    }
    if (h->sent > 0) {
        h->loss = (float)h->timeouts / (float)h->sent;
    }
}

static int open_icmp_socket(int *is_raw_out)
{
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd >= 0) {
        if (is_raw_out) {
            *is_raw_out = 0;
        }
        return fd;
    }
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd >= 0 && is_raw_out) {
        *is_raw_out = 1;
    }
    return fd;
}

static const uint8_t *icmp_payload(const uint8_t *buf, size_t n, size_t *out_len,
                                   int is_raw)
{
    size_t ihl;

    if (!buf || n < 8) {
        return NULL;
    }
    if (!is_raw) {
        *out_len = n;
        return buf;
    }
    if (n < 20) {
        return NULL;
    }
    ihl = (size_t)(buf[0] & 0x0f) * 4u;
    if (ihl < 20 || n < ihl + 8) {
        return NULL;
    }
    *out_len = n - ihl;
    return buf + ihl;
}

#if defined(__linux__)
/**
 * Wait for UDP probe result via IP_RECVERR (Time Exceeded / Port Unreach).
 */
static enum probe_outcome udp_wait_probe(int fd, uint32_t timeout_ms,
                                         char *addr_out, size_t addr_len,
                                         double *rtt_ms_out, uint64_t t0_ns)
{
    struct pollfd pfd;
    uint64_t t1_ns;
    int remaining = (int)timeout_ms;

    if (remaining < 1) {
        remaining = 1;
    }

    for (;;) {
        pfd.fd = fd;
        pfd.events = POLLIN | POLLERR;
        pfd.revents = 0;
        if (poll(&pfd, 1, remaining) <= 0) {
            return PROBE_TIMEOUT;
        }

        {
            char cbuf[512];
            char dbuf[64];
            struct iovec iov;
            struct msghdr msg;
            struct sockaddr_in offender;
            struct cmsghdr *cmsg;
            ssize_t nr;

            memset(&msg, 0, sizeof(msg));
            memset(&offender, 0, sizeof(offender));
            iov.iov_base = dbuf;
            iov.iov_len = sizeof(dbuf);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);
            msg.msg_name = &offender;
            msg.msg_namelen = sizeof(offender);

            nr = recvmsg(fd, &msg, MSG_ERRQUEUE);
            if (nr < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* Normal data path (rare for closed ports) */
                    if (pfd.revents & POLLIN) {
                        struct sockaddr_in from;
                        socklen_t flen = sizeof(from);
                        nr = recvfrom(fd, dbuf, sizeof(dbuf), 0,
                                      (struct sockaddr *)&from, &flen);
                        if (nr >= 0) {
                            t1_ns = mono_ns();
                            if (addr_out && addr_len) {
                                inet_ntop(AF_INET, &from.sin_addr, addr_out,
                                          (socklen_t)addr_len);
                            }
                            if (rtt_ms_out && t1_ns >= t0_ns) {
                                *rtt_ms_out =
                                    (double)(t1_ns - t0_ns) / 1000000.0;
                            }
                            return PROBE_DEST;
                        }
                    }
                    return PROBE_TIMEOUT;
                }
                return PROBE_TIMEOUT;
            }

            t1_ns = mono_ns();
            if (rtt_ms_out && t1_ns >= t0_ns) {
                *rtt_ms_out = (double)(t1_ns - t0_ns) / 1000000.0;
            }

            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_IP &&
                    cmsg->cmsg_type == IP_RECVERR) {
                    struct sock_extended_err *ee =
                        (struct sock_extended_err *)CMSG_DATA(cmsg);
                    struct sockaddr_in *sin;

                    if (!ee) {
                        continue;
                    }
                    sin = (struct sockaddr_in *)SO_EE_OFFENDER(ee);
                    if (sin && sin->sin_family == AF_INET && addr_out &&
                        addr_len) {
                        inet_ntop(AF_INET, &sin->sin_addr, addr_out,
                                  (socklen_t)addr_len);
                    }
                    if (ee->ee_origin == SO_EE_ORIGIN_ICMP ||
                        ee->ee_origin == SO_EE_ORIGIN_LOCAL) {
                        if (ee->ee_type == ICMP_TIME_EXCEEDED) {
                            return PROBE_HOP;
                        }
                        if (ee->ee_type == ICMP_DEST_UNREACH) {
                            /* Port unreachable ⇒ reached target host */
                            if (ee->ee_code == ICMP_PORT_UNREACH) {
                                return PROBE_DEST;
                            }
                            /* Other unreach: still a hop response */
                            return PROBE_HOP;
                        }
                    }
                }
            }
            /* Got errqueue message we could not classify — treat as hop */
            return PROBE_HOP;
        }
    }
}

static int probe_udp_once(const struct sockaddr_in *dst_base, int ttl,
                          uint16_t port, uint32_t timeout_ms, char *addr_out,
                          size_t addr_len, double *rtt_ms_out)
{
    int fd;
    int on = 1;
    struct sockaddr_in dst;
    uint8_t payload[32];
    uint64_t t0_ns;
    enum probe_outcome oc;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
        close(fd);
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        close(fd);
        return -1;
    }

    dst = *dst_base;
    dst.sin_port = htons(port);
    memset(payload, 0, sizeof(payload));
    snprintf((char *)payload, sizeof(payload), "cpe%02d", ttl);

    t0_ns = mono_ns();
    if (sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&dst,
               sizeof(dst)) < 0) {
        close(fd);
        return -1;
    }

    if (addr_out && addr_len) {
        addr_out[0] = '\0';
    }
    if (rtt_ms_out) {
        *rtt_ms_out = 0.0;
    }
    oc = udp_wait_probe(fd, timeout_ms, addr_out, addr_len, rtt_ms_out, t0_ns);
    close(fd);

    if (oc == PROBE_TIMEOUT) {
        return 0;
    }
    if (oc == PROBE_DEST) {
        return 2;
    }
    return 1; /* hop */
}
#else  /* !__linux__ */
static int probe_udp_once(const struct sockaddr_in *dst_base, int ttl,
                          uint16_t port, uint32_t timeout_ms, char *addr_out,
                          size_t addr_len, double *rtt_ms_out)
{
    (void)dst_base;
    (void)ttl;
    (void)port;
    (void)timeout_ms;
    (void)addr_out;
    (void)addr_len;
    (void)rtt_ms_out;
    return -1;
}
#endif

static int probe_icmp_once(const struct sockaddr_in *dst, int ttl,
                           uint16_t echo_id, uint16_t echo_seq,
                           uint32_t timeout_ms, char *addr_out, size_t addr_len,
                           double *rtt_ms_out)
{
    int fd;
    int is_raw = 0;
    struct cpe_icmp_echo req;
    uint8_t rbuf[512];
    struct pollfd pfd;
    uint64_t t0_ns, t1_ns;
    ssize_t nr;
    const uint8_t *icm;
    size_t icm_len = 0;
    struct sockaddr_in from;
    socklen_t flen;

    fd = open_icmp_socket(&is_raw);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        /* Some SOCK_DGRAM paths reject TTL; continue anyway */
        (void)errno;
    }

    memset(&req, 0, sizeof(req));
    req.type = 8;
    req.code = 0;
    req.id = htons(echo_id);
    req.seq = htons(echo_seq);
    memcpy(req.payload, "cpeagent", 8);
    req.checksum = 0;
    req.checksum = icmp_cksum(&req, sizeof(req));

    t0_ns = mono_ns();
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)dst, sizeof(*dst)) <
        0) {
        close(fd);
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, (int)(timeout_ms ? timeout_ms : 1)) <= 0 ||
        !(pfd.revents & POLLIN)) {
        close(fd);
        return 0;
    }

    flen = sizeof(from);
    memset(&from, 0, sizeof(from));
    nr = recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &flen);
    t1_ns = mono_ns();
    close(fd);
    if (nr <= 0) {
        return 0;
    }

    if (addr_out && addr_len && from.sin_family == AF_INET) {
        inet_ntop(AF_INET, &from.sin_addr, addr_out, (socklen_t)addr_len);
    }
    if (rtt_ms_out && t1_ns >= t0_ns) {
        *rtt_ms_out = (double)(t1_ns - t0_ns) / 1000000.0;
    }

    icm = icmp_payload(rbuf, (size_t)nr, &icm_len, is_raw);
    if (!icm || icm_len < 8) {
        return 1; /* got something from a hop */
    }
    if (icm[0] == 0) {
        /* Echo reply — destination */
        return 2;
    }
    if (icm[0] == 11) {
        /* Time exceeded */
        return 1;
    }
    if (icm[0] == 3) {
        /* Dest unreachable — often means we reached the host */
        return 2;
    }
    return 1;
}

static int resolve_target(const cpe_agent_t *a, const char *target_opt,
                          char *out, size_t out_len, struct sockaddr_in *dst)
{
    const cpe_agent_config_t *cfg;
    const char *target;

    if (!a || !out || !out_len || !dst) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    target = (target_opt && target_opt[0]) ? target_opt : cfg->demo_target;
    if (!target || !target[0]) {
        return -1;
    }
    if (strlen(target) >= out_len) {
        return -1;
    }
    snprintf(out, out_len, "%s", target);
    memset(dst, 0, sizeof(*dst));
    dst->sin_family = AF_INET;
    if (inet_pton(AF_INET, target, &dst->sin_addr) != 1) {
        return -1;
    }
    return 0;
}

static int emit_summary(cpe_agent_t *a, const cpe_trace_result_t *tr,
                        const char *probe_name)
{
    cpe_perf_sample_t sample;
    char line[CPE_NDJSON_LINE_MAX];
    const cpe_agent_config_t *cfg;
    double rtt = 0.0;
    float loss = 1.0f;
    int i;

    if (!a || !tr || !probe_name) {
        return -1;
    }
    cfg = cpe_agent_config(a);

    if (tr->reached && tr->dest_rtt_ms > 0.0) {
        rtt = tr->dest_rtt_ms;
        loss = 0.0f;
    } else if (tr->hop_count > 0) {
        const cpe_trace_hop_t *last = &tr->hops[tr->hop_count - 1];
        rtt = last->last_rtt_ms;
        loss = last->loss;
    }

    memset(&sample, 0, sizeof(sample));
    snprintf(sample.probe, sizeof(sample.probe), "%s", probe_name);
    snprintf(sample.target, sizeof(sample.target), "%s", tr->target);
    sample.rtt_ms = rtt;
    sample.loss = loss;
    snprintf(sample.ts_iso, sizeof(sample.ts_iso), "%s", tr->ts_iso);
    snprintf(sample.meta, sizeof(sample.meta),
             "{\"hops\":%d,\"reached\":%s,\"method\":\"%s\",\"probes\":%d,"
             "\"demo\":false}",
             tr->hop_count, tr->reached ? "true" : "false", tr->method,
             tr->probes_per_hop);

    if (cpe_agent_set_last_sample(a, &sample) != 0) {
        return -1;
    }
    if (cpe_perf_format_ndjson(cfg->router_id, &sample, line, sizeof(line)) <
        0) {
        return -1;
    }
    if (cpe_agent_spool_push_line(a, line) != 0) {
        return -1;
    }

    /* Optional per-hop NDJSON (compact) for Vector/CH correlation. */
    for (i = 0; i < tr->hop_count; i++) {
        const cpe_trace_hop_t *h = &tr->hops[i];
        char hop_line[CPE_NDJSON_LINE_MAX];
        cpe_perf_sample_t hs;
        int n;

        memset(&hs, 0, sizeof(hs));
        snprintf(hs.probe, sizeof(hs.probe), "%s_hop", probe_name);
        if (h->addr[0]) {
            snprintf(hs.target, sizeof(hs.target), "%s", h->addr);
        } else {
            snprintf(hs.target, sizeof(hs.target), "*");
        }
        hs.rtt_ms = h->last_rtt_ms;
        hs.loss = h->loss;
        snprintf(hs.ts_iso, sizeof(hs.ts_iso), "%s", tr->ts_iso);
        n = snprintf(hs.meta, sizeof(hs.meta),
                     "{\"hop\":%d,\"sent\":%u,\"replies\":%u,\"dest\":%s,"
                     "\"path\":\"%s\"}",
                     h->hop, (unsigned)h->sent, (unsigned)h->replies,
                     h->reached_dest ? "true" : "false", tr->target);
        if (n < 0 || (size_t)n >= sizeof(hs.meta)) {
            continue;
        }
        if (cpe_perf_format_ndjson(cfg->router_id, &hs, hop_line,
                                   sizeof(hop_line)) < 0) {
            continue;
        }
        (void)cpe_agent_spool_push_line(a, hop_line);
    }
    return 0;
}

static int run_trace(cpe_agent_t *a, const char *target_opt, int max_ttl,
                     int probes_per_hop, uint32_t timeout_ms,
                     const char *probe_name, cpe_trace_result_t *out_opt)
{
    cpe_trace_result_t tr;
    struct sockaddr_in dst;
    char target[CPE_PERF_TARGET_MAX];
    int ttl;
    int use_udp = 1;
    uint16_t echo_id;
    uint16_t echo_seq = 0;
    static uint16_t port_seq;

    if (!a || !probe_name) {
        return -1;
    }
    if (max_ttl <= 0) {
        max_ttl = 30;
    }
    if (max_ttl > CPE_TRACE_HOP_MAX) {
        max_ttl = CPE_TRACE_HOP_MAX;
    }
    if (probes_per_hop <= 0) {
        probes_per_hop = 1;
    }
    if (probes_per_hop > 16) {
        probes_per_hop = 16;
    }
    if (timeout_ms == 0) {
        timeout_ms = cpe_agent_config(a)->probe_timeout_ms
                         ? cpe_agent_config(a)->probe_timeout_ms
                         : 1000;
    }

    if (resolve_target(a, target_opt, target, sizeof(target), &dst) != 0) {
        return -1;
    }

    memset(&tr, 0, sizeof(tr));
    snprintf(tr.target, sizeof(tr.target), "%s", target);
    iso_now(tr.ts_iso, sizeof(tr.ts_iso));
    tr.max_ttl = max_ttl;
    tr.probes_per_hop = probes_per_hop;
    snprintf(tr.method, sizeof(tr.method), "udp");

    echo_id = (uint16_t)(getpid() & 0xffff);

    /* Prefer UDP+IP_RECVERR when the kernel exposes it (Linux). */
#if defined(__linux__)
    {
        int tfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int on = 1;
        if (tfd < 0 ||
            setsockopt(tfd, SOL_IP, IP_RECVERR, &on, sizeof(on)) != 0) {
            use_udp = 0;
            snprintf(tr.method, sizeof(tr.method), "icmp");
        }
        if (tfd >= 0) {
            close(tfd);
        }
    }
#else
    use_udp = 0;
    snprintf(tr.method, sizeof(tr.method), "icmp");
#endif

    for (ttl = 1; ttl <= max_ttl; ttl++) {
        cpe_trace_hop_t *hop = &tr.hops[tr.hop_count];
        int p;
        int hop_reached = 0;

        hop_init(hop, ttl);

        for (p = 0; p < probes_per_hop; p++) {
            char addr[CPE_PERF_TARGET_MAX];
            double rtt = 0.0;
            int pr;

            addr[0] = '\0';
            if (use_udp) {
                uint16_t port =
                    (uint16_t)(CPE_TRACE_BASE_PORT + ((port_seq++) % 2000));
                pr = probe_udp_once(&dst, ttl, port, timeout_ms, addr,
                                    sizeof(addr), &rtt);
                if (pr < 0) {
                    use_udp = 0;
                    snprintf(tr.method, sizeof(tr.method), "icmp");
                    echo_seq++;
                    pr = probe_icmp_once(&dst, ttl, echo_id, echo_seq,
                                         timeout_ms, addr, sizeof(addr), &rtt);
                }
            } else {
                echo_seq++;
                pr = probe_icmp_once(&dst, ttl, echo_id, echo_seq, timeout_ms,
                                     addr, sizeof(addr), &rtt);
            }

            if (pr < 0) {
                hop_record(hop, 0, NULL, 0.0, 0);
            } else if (pr == 0) {
                hop_record(hop, 0, NULL, 0.0, 0);
            } else if (pr == 2) {
                hop_record(hop, 1, addr[0] ? addr : target, rtt, 1);
                hop_reached = 1;
                tr.reached = 1;
                tr.dest_rtt_ms = rtt;
            } else {
                hop_record(hop, 1, addr, rtt, 0);
            }
        }

        tr.hop_count++;
        if (hop_reached) {
            break;
        }
    }

    if (cpe_agent_set_last_trace(a, &tr) != 0) {
        return -1;
    }
    if (emit_summary(a, &tr, probe_name) != 0) {
        return -1;
    }
    if (out_opt) {
        *out_opt = tr;
    }
    return 0;
}

int cpe_agent_traceroute(cpe_agent_t *a, const char *target_opt, int max_ttl,
                         uint32_t timeout_ms, cpe_trace_result_t *out_opt)
{
    return run_trace(a, target_opt, max_ttl, 1, timeout_ms, "traceroute",
                     out_opt);
}

int cpe_agent_mtr(cpe_agent_t *a, const char *target_opt, int max_ttl,
                  int probes_per_hop, uint32_t timeout_ms,
                  cpe_trace_result_t *out_opt)
{
    if (probes_per_hop <= 0) {
        probes_per_hop = 3;
    }
    return run_trace(a, target_opt, max_ttl, probes_per_hop, timeout_ms, "mtr",
                     out_opt);
}

int cpe_agent_demo_traceroute(cpe_agent_t *a, const char *target_opt,
                              int max_ttl, cpe_trace_result_t *out_opt)
{
    cpe_trace_result_t tr;
    const char *target;
    const cpe_agent_config_t *cfg;
    int hops;
    int i;

    if (!a) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    target = (target_opt && target_opt[0]) ? target_opt : cfg->demo_target;
    if (!target || !target[0]) {
        target = "1.1.1.1";
    }
    if (max_ttl <= 0) {
        max_ttl = 5;
    }
    if (max_ttl > CPE_TRACE_HOP_MAX) {
        max_ttl = CPE_TRACE_HOP_MAX;
    }
    hops = max_ttl < 4 ? max_ttl : 4;

    memset(&tr, 0, sizeof(tr));
    snprintf(tr.target, sizeof(tr.target), "%s", target);
    iso_now(tr.ts_iso, sizeof(tr.ts_iso));
    snprintf(tr.method, sizeof(tr.method), "demo");
    tr.max_ttl = max_ttl;
    tr.probes_per_hop = 1;
    tr.reached = 1;
    tr.hop_count = hops;

    for (i = 0; i < hops; i++) {
        cpe_trace_hop_t *h = &tr.hops[i];
        hop_init(h, i + 1);
        h->sent = 1;
        h->replies = 1;
        h->last_rtt_ms = 1.0 * (i + 1);
        h->avg_rtt_ms = h->last_rtt_ms;
        h->min_rtt_ms = h->last_rtt_ms;
        h->max_rtt_ms = h->last_rtt_ms;
        h->loss = 0.0f;
        if (i + 1 < hops) {
            snprintf(h->addr, sizeof(h->addr), "10.0.%d.1", i + 1);
        } else {
            snprintf(h->addr, sizeof(h->addr), "%s", target);
            h->reached_dest = 1;
            tr.dest_rtt_ms = h->last_rtt_ms;
        }
    }

    if (cpe_agent_set_last_trace(a, &tr) != 0) {
        return -1;
    }
    /* Demo still emits summary for dialectic spool tests. */
    {
        cpe_perf_sample_t sample;
        char line[CPE_NDJSON_LINE_MAX];

        memset(&sample, 0, sizeof(sample));
        snprintf(sample.probe, sizeof(sample.probe), "traceroute");
        snprintf(sample.target, sizeof(sample.target), "%s", tr.target);
        sample.rtt_ms = tr.dest_rtt_ms;
        sample.loss = 0.0f;
        snprintf(sample.ts_iso, sizeof(sample.ts_iso), "%s", tr.ts_iso);
        snprintf(sample.meta, sizeof(sample.meta),
                 "{\"hops\":%d,\"reached\":true,\"method\":\"demo\","
                 "\"probes\":1,\"demo\":true}",
                 tr.hop_count);
        if (cpe_agent_set_last_sample(a, &sample) != 0) {
            return -1;
        }
        if (cpe_perf_format_ndjson(cfg->router_id, &sample, line, sizeof(line)) <
            0) {
            return -1;
        }
        if (cpe_agent_spool_push_line(a, line) != 0) {
            return -1;
        }
    }
    if (out_opt) {
        *out_opt = tr;
    }
    return 0;
}
