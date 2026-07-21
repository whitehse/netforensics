/**
 * @file live_ping.c
 * @brief Host-owned ICMP echo probe → cpe_perf sample (F4).
 *
 * libnetdiag remains syscall-free: this file owns the socket; parsers get
 * reply bytes when available. RTT is measured on the host clock.
 */

#define _POSIX_C_SOURCE 200809L

#include "cpe_agent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct cpe_icmp_echo {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t  payload[8];
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

static uint64_t mono_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
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

int cpe_agent_live_ping_tick(cpe_agent_t *a)
{
    int fd;
    int is_raw = 0;
    struct sockaddr_in dst;
    struct cpe_icmp_echo req;
    uint8_t rbuf[256];
    ssize_t nr;
    const uint8_t *icmp;
    size_t icmp_len = 0;
    struct pollfd pfd;
    uint64_t t0, t1;
    uint32_t timeout_ms;
    cpe_perf_sample_t sample;
    char line[CPE_NDJSON_LINE_MAX];
    double rtt_ms = 0.0;
    float loss = 1.0f;
    int replied = 0;
    static uint16_t seq;
    uint16_t id;
    const cpe_agent_config_t *cfg;

    if (!a) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    if (!cfg || cfg->demo_target[0] == '\0') {
        return -1;
    }

    timeout_ms = cfg->probe_timeout_ms ? cfg->probe_timeout_ms : 1000;
    id = (uint16_t)(getpid() & 0xffff);

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, cfg->demo_target, &dst.sin_addr) != 1) {
        return -1;
    }

    fd = open_icmp_socket(&is_raw);
    if (fd < 0) {
        return -1;
    }

    seq++;
    memset(&req, 0, sizeof(req));
    req.type = 8;
    req.code = 0;
    req.id = htons(id);
    req.seq = htons(seq);
    memcpy(req.payload, "cpeagent", 8);
    req.checksum = 0;
    req.checksum = icmp_cksum(&req, sizeof(req));

    t0 = mono_ms();
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&dst,
               sizeof(dst)) < 0) {
        close(fd);
        return -1;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, (int)timeout_ms) > 0 && (pfd.revents & POLLIN)) {
        nr = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        t1 = mono_ms();
        if (nr > 0) {
            icmp = icmp_payload(rbuf, (size_t)nr, &icmp_len, is_raw);
            if (icmp && icmp_len >= 8 && icmp[0] == 0) {
                uint16_t rseq = (uint16_t)((icmp[6] << 8) | icmp[7]);
                if (rseq == seq) {
                    replied = 1;
                    loss = 0.0f;
                    rtt_ms = (t1 >= t0) ? (double)(t1 - t0) : 0.0;
                    (void)cpe_agent_feed_icmp_echo_reply(a, icmp, icmp_len, t1);
                }
            }
        }
    } else {
        (void)errno;
    }
    close(fd);

    memset(&sample, 0, sizeof(sample));
    snprintf(sample.probe, sizeof(sample.probe), "ping");
    snprintf(sample.target, sizeof(sample.target), "%s", cfg->demo_target);
    sample.rtt_ms = replied ? rtt_ms : 0.0;
    sample.loss = loss;
    iso_now(sample.ts_iso, sizeof(sample.ts_iso));
    snprintf(sample.meta, sizeof(sample.meta),
             "{\"replies\":%d,\"timeouts\":%d,\"demo\":false,\"raw\":%s}",
             replied ? 1 : 0, replied ? 0 : 1, is_raw ? "true" : "false");

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
    return 0;
}
