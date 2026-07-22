/**
 * @file live_arping.c
 * @brief Host-owned ARP request/reply probe → cpe_perf sample (probe=arping).
 *
 * libnetdiag arping remains syscall-free; this file owns AF_PACKET sockets.
 * Requires CAP_NET_RAW / root for live probes on typical Linux/OpenWrt.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "cpe_agent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

#include "netdiag.h"

#pragma pack(push, 1)
struct cpe_eth_arp {
    uint8_t  eth_dst[6];
    uint8_t  eth_src[6];
    uint16_t eth_type;
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
};
#pragma pack(pop)

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

static void mac_fmt(char *out, size_t n, const uint8_t mac[6])
{
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

/**
 * Pick default L3 interface: first non-* default route in /proc/net/route.
 * Falls back to "br-lan", then "eth0".
 */
static int pick_iface(char *out, size_t out_sz)
{
    FILE *fp;
    char line[256];
    char ifname[IFNAMSIZ];
    unsigned dest, gateway, flags;
    int found = 0;

    if (!out || out_sz < 2) {
        return -1;
    }

    fp = fopen("/proc/net/route", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            /* skip header */
        }
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%15s %x %x %x", ifname, &dest, &gateway, &flags) >=
                4) {
                if (dest == 0 && (flags & 1u) && strcmp(ifname, "lo") != 0) {
                    snprintf(out, out_sz, "%s", ifname);
                    found = 1;
                    break;
                }
            }
        }
        fclose(fp);
    }
    if (found) {
        return 0;
    }

    /* Common OpenWrt LAN bridge names */
    {
        static const char *const candidates[] = {"br-lan", "br0", "lan", "eth0",
                                                 "eth1", NULL};
        size_t i;
        for (i = 0; candidates[i]; i++) {
            if (if_nametoindex(candidates[i]) != 0) {
                snprintf(out, out_sz, "%s", candidates[i]);
                return 0;
            }
        }
    }
    snprintf(out, out_sz, "eth0");
    return 0;
}

static int iface_addrs(const char *ifname, int *ifindex_out, uint8_t mac_out[6],
                       uint8_t ip_out[4])
{
    int fd;
    struct ifreq ifr;

    if (!ifname || !ifindex_out || !mac_out || !ip_out) {
        return -1;
    }
    memset(mac_out, 0, 6);
    memset(ip_out, 0, 4);
    *ifindex_out = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    /* IFNAMSIZ is typically 16; truncate safely */
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(fd, SIOCGIFINDEX, &ifr) != 0) {
        close(fd);
        return -1;
    }
    *ifindex_out = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    }

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        memcpy(ip_out, &sin->sin_addr.s_addr, 4);
    }

    close(fd);
    return (*ifindex_out > 0) ? 0 : -1;
}

static int is_arp_reply_for(const uint8_t *frame, size_t n, const uint8_t tpa[4],
                            uint8_t mac_out[6])
{
    const struct cpe_eth_arp *p;

    if (!frame || n < sizeof(struct cpe_eth_arp) || !tpa || !mac_out) {
        return 0;
    }
    p = (const struct cpe_eth_arp *)frame;
    if (ntohs(p->eth_type) != 0x0806) {
        return 0;
    }
    if (ntohs(p->htype) != 1 || ntohs(p->ptype) != 0x0800) {
        return 0;
    }
    if (p->hlen != 6 || p->plen != 4) {
        return 0;
    }
    if (ntohs(p->oper) != 2) {
        return 0;
    }
    /* Responder claims our target IP in spa */
    if (memcmp(p->spa, tpa, 4) != 0) {
        return 0;
    }
    memcpy(mac_out, p->sha, 6);
    return 1;
}

static int emit_arping_sample(cpe_agent_t *a, const char *target, double rtt_ms,
                              float loss, int replied, int demo,
                              const char *mac_str, const char *ifname)
{
    cpe_perf_sample_t sample;
    char line[CPE_NDJSON_LINE_MAX];
    const cpe_agent_config_t *cfg;
    char meta[CPE_PERF_META_MAX];

    if (!a) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    if (!cfg) {
        return -1;
    }

    memset(&sample, 0, sizeof(sample));
    snprintf(sample.probe, sizeof(sample.probe), "arping");
    snprintf(sample.target, sizeof(sample.target), "%s",
             target && target[0] ? target : "");
    sample.rtt_ms = replied ? rtt_ms : 0.0;
    sample.loss = loss;
    iso_now(sample.ts_iso, sizeof(sample.ts_iso));

    if (demo) {
        snprintf(meta, sizeof(meta),
                 "{\"replies\":%d,\"timeouts\":%d,\"demo\":true,\"mac\":\"%s\"}",
                 replied ? 1 : 0, replied ? 0 : 1,
                 mac_str && mac_str[0] ? mac_str : "00:00:00:00:00:00");
    } else {
        snprintf(meta, sizeof(meta),
                 "{\"replies\":%d,\"timeouts\":%d,\"demo\":false,\"mac\":\"%s\","
                 "\"if\":\"%s\"}",
                 replied ? 1 : 0, replied ? 0 : 1,
                 mac_str && mac_str[0] ? mac_str : "",
                 ifname && ifname[0] ? ifname : "");
    }
    snprintf(sample.meta, sizeof(sample.meta), "%s", meta);

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

int cpe_agent_demo_arping(cpe_agent_t *a, const char *ipv4_opt)
{
    const cpe_agent_config_t *cfg;
    const char *target;
    arping_ctx *ap;
    netdiag_event_t ev;
    netdiag_stats_t st;
    uint8_t fake[42];
    uint64_t now_ms;
    char mac[24];

    if (!a) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    if (!cfg) {
        return -1;
    }
    target = (ipv4_opt && ipv4_opt[0]) ? ipv4_opt : cfg->demo_target;
    if (!target || !target[0]) {
        return -1;
    }

    /* Feed a synthetic Ethernet+ARP reply into libnetdiag for stats. */
    ap = arping_create(NETDIAG_ROLE_REQUESTER);
    if (!ap) {
        return -1;
    }
    memset(fake, 0, sizeof(fake));
    /* ethertype ARP at 12..13, oper reply at 20..21 (offset 20 = d[20], d[21]) */
    fake[12] = 0x08;
    fake[13] = 0x06;
    fake[21] = 2; /* ARP reply (oper low byte when big-endian layout in wire) */
    /* sha at offset 22 */
    fake[22] = 0x02;
    fake[23] = 0x00;
    fake[24] = 0x00;
    fake[25] = 0x00;
    fake[26] = 0x00;
    fake[27] = 0x01;

    now_ms = mono_ns() / 1000000ull;
    (void)arping_feed_input_with_ts(ap, fake, sizeof(fake), now_ms + 1);
    (void)arping_process(ap, now_ms + 2);
    while (arping_next_event(ap, &ev) == 1) {
    }
    (void)arping_get_stats(ap, &st);
    arping_destroy(ap);

    {
        static const uint8_t demo_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        double rtt = st.avg_latency_ms ? (double)st.avg_latency_ms : 1.0;

        mac_fmt(mac, sizeof(mac), demo_mac);
        return emit_arping_sample(a, target, rtt, 0.0f, 1, 1, mac, NULL);
    }
}

int cpe_agent_demo_arping_tick(cpe_agent_t *a)
{
    return cpe_agent_demo_arping(a, NULL);
}

int cpe_agent_arping(cpe_agent_t *a, const char *ipv4_opt, const char *ifname_opt)
{
#ifndef __linux__
    (void)a;
    (void)ipv4_opt;
    (void)ifname_opt;
    return -1;
#else
    const cpe_agent_config_t *cfg;
    const char *target;
    char ifname[CPE_CFG_IFACE_MAX];
    int ifindex = 0;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    struct in_addr ina;
    int fd = -1;
    struct sockaddr_ll sll;
    struct cpe_eth_arp req;
    uint8_t rbuf[256];
    struct pollfd pfd;
    uint32_t timeout_ms;
    uint64_t t0_ns, t1_ns;
    double rtt_ms = 0.0;
    float loss = 1.0f;
    int replied = 0;
    uint8_t peer_mac[6];
    char mac_str[24];
    ssize_t nr;
    int deadline_left;

    if (!a) {
        return -1;
    }
    cfg = cpe_agent_config(a);
    if (!cfg) {
        return -1;
    }

    target = (ipv4_opt && ipv4_opt[0]) ? ipv4_opt : cfg->demo_target;
    if (!target || !target[0]) {
        return -1;
    }
    if (inet_pton(AF_INET, target, &ina) != 1) {
        return -1;
    }
    memcpy(dst_ip, &ina.s_addr, 4);

    if (ifname_opt && ifname_opt[0]) {
        snprintf(ifname, sizeof(ifname), "%s", ifname_opt);
    } else if (cfg->arping_if[0]) {
        snprintf(ifname, sizeof(ifname), "%s", cfg->arping_if);
    } else {
        if (pick_iface(ifname, sizeof(ifname)) != 0) {
            return -1;
        }
    }

    if (iface_addrs(ifname, &ifindex, src_mac, src_ip) != 0) {
        return -1;
    }

    timeout_ms = cfg->probe_timeout_ms ? cfg->probe_timeout_ms : 1000;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        close(fd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    memset(req.eth_dst, 0xff, 6);
    memcpy(req.eth_src, src_mac, 6);
    req.eth_type = htons(0x0806);
    req.htype = htons(1);
    req.ptype = htons(0x0800);
    req.hlen = 6;
    req.plen = 4;
    req.oper = htons(1); /* request */
    memcpy(req.sha, src_mac, 6);
    memcpy(req.spa, src_ip, 4);
    memset(req.tha, 0, 6);
    memcpy(req.tpa, dst_ip, 4);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);

    t0_ns = mono_ns();
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&sll,
               sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    memset(peer_mac, 0, sizeof(peer_mac));
    mac_str[0] = '\0';
    deadline_left = (int)timeout_ms;

    while (deadline_left > 0) {
        int waited;
        uint64_t before = mono_ns();

        pfd.fd = fd;
        pfd.events = POLLIN;
        waited = poll(&pfd, 1, deadline_left);
        if (waited <= 0) {
            break;
        }
        if (!(pfd.revents & POLLIN)) {
            break;
        }
        nr = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        t1_ns = mono_ns();
        if (nr > 0 &&
            is_arp_reply_for(rbuf, (size_t)nr, dst_ip, peer_mac)) {
            replied = 1;
            loss = 0.0f;
            if (t1_ns >= t0_ns) {
                rtt_ms = (double)(t1_ns - t0_ns) / 1000000.0;
            }
            mac_fmt(mac_str, sizeof(mac_str), peer_mac);
            break;
        }
        {
            uint64_t after = mono_ns();
            int elapsed_ms =
                (int)((after > before ? after - before : 0) / 1000000ull);
            if (elapsed_ms < 1) {
                elapsed_ms = 1;
            }
            deadline_left -= elapsed_ms;
        }
    }
    (void)errno;
    close(fd);

    return emit_arping_sample(a, target, rtt_ms, loss, replied, 0, mac_str,
                              ifname);
#endif /* __linux__ */
}

int cpe_agent_live_arping_tick(cpe_agent_t *a)
{
    return cpe_agent_arping(a, NULL, NULL);
}
