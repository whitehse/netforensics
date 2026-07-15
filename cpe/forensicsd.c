#define _POSIX_C_SOURCE 200809L

/**
 * forensicsd — OpenWrt CPE forensics daemon.
 *
 * Modes:
 *   --demo     emit synthetic nfct/nl80211 NDJSON (no privileges)
 *   --netlink  subscribe to NETLINK_NETFILTER conntrack NEW/DESTROY
 *              and emit NDJSON for each decoded event (needs CAP_NET_ADMIN)
 *
 * Real CTA attribute decode is iterative in libnetdiag; raw nlmsg frames
 * still produce PARTIAL/typed events via nfct_feed_input.
 */

#include "netforensics.h"
#include "nl80211_parse.h"
#include "nfct_netlink.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_sig(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static void wr16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void emit_nfct_events(nfct_ctx *nfct, const char *router_id, uint64_t ts)
{
    nfct_event_t nev;
    nf_flow_obs_t obs;
    char line[512];
    char detail[256];

    while (nfct_next_event(nfct, &nev) == 1) {
        if (nf_obs_from_nfct(&nev, router_id, ts, &obs) == 0) {
            if (nf_obs_format(&obs, line, sizeof(line)) == 0) {
                puts(line);
            }
        } else {
            /* Partial / incomplete CTA decode — still log for pipeline debug */
            nfct_event_to_string(&nev, detail, sizeof(detail));
            printf("{\"type\":\"cpe_nat_raw\",\"router\":\"%s\",\"ts\":%llu,"
                   "\"detail\":\"%s\"}\n",
                   router_id, (unsigned long long)ts, detail);
        }
        fflush(stdout);
    }
}

static int run_demo(const char *router_id)
{
    nfct_ctx *nfct = nfct_create(NFCT_ROLE_COLLECTOR);
    nl80211_parse_ctx *wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    uint8_t synth[32];
    uint8_t wsynth[20];
    nl80211_event_t wev;

    if (!nfct || !wifi) {
        fprintf(stderr, "forensicsd: create failed\n");
        return 1;
    }

    printf("# forensicsd demo mode router_id=%s\n", router_id);

    memset(synth, 0, sizeof(synth));
    wr32_be(synth, 0x4E464354u);
    synth[4] = 1;
    synth[5] = 6;
    wr32_be(synth + 8, 0xC0A80132u);
    wr16_be(synth + 12, 12345);
    wr32_be(synth + 14, 0x08080808u);
    wr16_be(synth + 18, 53);
    wr32_be(synth + 20, 0xCB007109u);
    wr16_be(synth + 24, 54321);
    wr32_be(synth + 26, 0x08080808u);
    wr16_be(synth + 30, 53);
    nfct_feed_input(nfct, synth, sizeof(synth));
    emit_nfct_events(nfct, router_id, 1700000000000ull);

    memset(wsynth, 0, sizeof(wsynth));
    wr32_be(wsynth, 0x38323131u);
    wsynth[4] = 0xaa;
    wsynth[5] = 0xbb;
    wsynth[6] = 0xcc;
    wsynth[7] = 0xdd;
    wsynth[8] = 0xee;
    wsynth[9] = 0xff;
    wr32_be(wsynth + 10, (uint32_t)(int32_t)-65);
    wsynth[14] = 25;
    wsynth[15] = 7;
    wr32_be(wsynth + 16, 3);
    nl80211_parse_feed_input(wifi, wsynth, sizeof(wsynth));
    while (nl80211_parse_next_event(wifi, &wev) == 1) {
        char wbuf[256];
        nl80211_event_to_string(&wev, wbuf, sizeof(wbuf));
        printf("{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"detail\":\"%s\"}\n",
               router_id, wbuf);
    }

    nfct_destroy(nfct);
    nl80211_parse_destroy(wifi);
    return 0;
}

static int run_netlink(const char *router_id, int join_update)
{
    char err[256];
    uint8_t buf[8192];
    nfct_ctx *nfct;
    int fd;
    struct pollfd pfd;

    nfct = nfct_create(NFCT_ROLE_COLLECTOR);
    if (!nfct) {
        fprintf(stderr, "forensicsd: nfct_create failed\n");
        return 1;
    }

    fd = nfct_netlink_open(join_update, err, sizeof(err));
    if (fd < 0) {
        fprintf(stderr, "forensicsd: netlink open failed: %s\n", err);
        fprintf(stderr, "hint: run as root or with CAP_NET_ADMIN; "
                        "ensure nf_conntrack_events=1\n");
        nfct_destroy(nfct);
        return 1;
    }

    if (nfct_netlink_set_nonblock(fd) != 0) {
        fprintf(stderr, "forensicsd: set nonblock: %s\n", strerror(errno));
        nfct_netlink_close(fd);
        nfct_destroy(nfct);
        return 1;
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    fprintf(stderr,
            "forensicsd: netlink conntrack listening (router_id=%s groups=NEW%sDESTROY)\n",
            router_id, join_update ? ",UPDATE," : ",");

    pfd.fd = fd;
    pfd.events = POLLIN;

    while (!g_stop) {
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "forensicsd: poll: %s\n", strerror(errno));
            break;
        }
        if (pr == 0) {
            continue;
        }
        if (pfd.revents & (POLLERR | POLLHUP)) {
            fprintf(stderr, "forensicsd: netlink hangup/error\n");
            break;
        }
        if (pfd.revents & POLLIN) {
            for (;;) {
                int n = nfct_netlink_recv(fd, buf, sizeof(buf));
                if (n == 0) {
                    break;
                }
                if (n < 0) {
                    fprintf(stderr, "forensicsd: recv: %s\n", strerror(errno));
                    g_stop = 1;
                    break;
                }
                if (nfct_feed_input(nfct, buf, (size_t)n) != 0) {
                    fprintf(stderr, "forensicsd: nfct_feed_input error\n");
                }
                emit_nfct_events(nfct, router_id, now_ms());
            }
        }
    }

    nfct_netlink_close(fd);
    nfct_destroy(nfct);
    fprintf(stderr, "forensicsd: netlink shutdown\n");
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--demo|--netlink] [--router-id ID] [--update]\n"
            "  --demo        synthetic frames to stdout (default)\n"
            "  --netlink     live NETLINK_NETFILTER conntrack events\n"
            "  --router-id   CPE identifier string (default cpe-demo-001)\n"
            "  --update      also join NFNLGRP_CONNTRACK_UPDATE\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *router_id = "cpe-demo-001";
    int mode_netlink = 0;
    int join_update = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--demo") == 0) {
            mode_netlink = 0;
            continue;
        }
        if (strcmp(argv[i], "--netlink") == 0) {
            mode_netlink = 1;
            continue;
        }
        if (strcmp(argv[i], "--update") == 0) {
            join_update = 1;
            continue;
        }
        if (strcmp(argv[i], "--router-id") == 0 && i + 1 < argc) {
            router_id = argv[++i];
            continue;
        }
        fprintf(stderr, "unknown arg: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    if (mode_netlink) {
        return run_netlink(router_id, join_update);
    }
    return run_demo(router_id);
}
