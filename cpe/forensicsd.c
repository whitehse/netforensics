#define _POSIX_C_SOURCE 200809L

/**
 * forensicsd — OpenWrt CPE forensics daemon.
 *
 * Modes:
 *   --demo     emit synthetic nfct/nl80211 NDJSON (no privileges)
 *   --netlink  subscribe to NETLINK_NETFILTER conntrack NEW/DESTROY
 *              and emit NDJSON for each decoded event (needs CAP_NET_ADMIN)
 *
 * CTA decode (IPv4/IPv6 + DESTROY id) is in libnetdiag nfct; NDJSON includes
 * event, ip_version, ct_id when available.
 */

#include "netforensics.h"
#include "nl80211_parse.h"
#include "nl80211_netlink.h"
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
    char line[768];
    char detail[256];

    while (nfct_next_event(nfct, &nev) == 1) {
        if (nf_obs_from_nfct(&nev, router_id, ts, &obs) == 0) {
            if (nf_obs_format(&obs, line, sizeof(line)) == 0) {
                puts(line);
            }
        } else {
            /* Partial / incomplete CTA decode — still log for pipeline debug */
            nfct_event_to_string(&nev, detail, sizeof(detail));
            if (nev.has_id) {
                printf("{\"type\":\"cpe_nat_raw\",\"router\":\"%s\",\"ts\":%llu,"
                       "\"event\":\"%s\",\"ct_id\":%u,\"detail\":\"%s\"}\n",
                       router_id, (unsigned long long)ts,
                       nev.is_destroy ? "DESTROY" : "PARTIAL",
                       (unsigned)nev.id, detail);
            } else {
                printf("{\"type\":\"cpe_nat_raw\",\"router\":\"%s\",\"ts\":%llu,"
                       "\"detail\":\"%s\"}\n",
                       router_id, (unsigned long long)ts, detail);
            }
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
        if (wev.type == NL80211_EVENT_STATION && wev.has_mac) {
            printf("{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"ts\":%llu,"
                   "\"client_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                   "\"rssi\":%d,\"snr\":%d,\"mcs\":%u,\"tx_retries\":%u,"
                   "\"freq_mhz\":%u}\n",
                   router_id, (unsigned long long)now_ms(),
                   wev.client_mac[0], wev.client_mac[1], wev.client_mac[2],
                   wev.client_mac[3], wev.client_mac[4], wev.client_mac[5],
                   (int)wev.signal_dbm, (int)wev.snr_db,
                   (unsigned)wev.mcs_index, (unsigned)wev.tx_retries,
                   (unsigned)wev.frequency_mhz);
        } else {
            char wbuf[256];
            nl80211_event_to_string(&wev, wbuf, sizeof(wbuf));
            printf("{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"detail\":\"%s\"}\n",
                   router_id, wbuf);
        }
        fflush(stdout);
    }

    nfct_destroy(nfct);
    nl80211_parse_destroy(wifi);
    return 0;
}

static void emit_wifi_events(nl80211_parse_ctx *wifi, const char *router_id,
                             uint64_t ts)
{
    nl80211_event_t wev;
    while (nl80211_parse_next_event(wifi, &wev) == 1) {
        if (wev.type == NL80211_EVENT_STATION && wev.has_mac) {
            printf("{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"ts\":%llu,"
                   "\"client_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                   "\"rssi\":%d,\"snr\":%d,\"mcs\":%u,\"tx_retries\":%u,"
                   "\"freq_mhz\":%u}\n",
                   router_id, (unsigned long long)ts,
                   wev.client_mac[0], wev.client_mac[1], wev.client_mac[2],
                   wev.client_mac[3], wev.client_mac[4], wev.client_mac[5],
                   (int)wev.signal_dbm, (int)wev.snr_db,
                   (unsigned)wev.mcs_index, (unsigned)wev.tx_retries,
                   (unsigned)wev.frequency_mhz);
            fflush(stdout);
        }
    }
}

static void wifi_dump_once(int wfd, int family_id, int ifindex,
                           nl80211_parse_ctx *wifi, const char *router_id)
{
    char err[128];
    uint8_t buf[8192];
    int n;

    if (wfd < 0 || family_id <= 0 || ifindex <= 0 || !wifi) {
        return;
    }
    if (nl80211_netlink_dump_stations(wfd, family_id, ifindex, err,
                                      sizeof(err)) != 0) {
        fprintf(stderr, "forensicsd: wifi dump: %s\n", err);
        return;
    }
    for (;;) {
        n = nl80211_netlink_recv(wfd, buf, sizeof(buf));
        if (n == 0) {
            break;
        }
        if (n < 0) {
            break;
        }
        /* Done when NLMSG_DONE appears — still feed all for parse */
        (void)nl80211_parse_feed_input(wifi, buf, (size_t)n);
        emit_wifi_events(wifi, router_id, now_ms());
        /* Detect NLMSG_DONE (type 0x3) in multi-part dump */
        {
            size_t off = 0;
            int done = 0;
            while (off + 16 <= (size_t)n) {
                uint32_t len = ((uint32_t)buf[off]) |
                               ((uint32_t)buf[off + 1] << 8) |
                               ((uint32_t)buf[off + 2] << 16) |
                               ((uint32_t)buf[off + 3] << 24);
                uint16_t type = (uint16_t)buf[off + 4] |
                                ((uint16_t)buf[off + 5] << 8);
                if (len < 16 || off + len > (size_t)n) {
                    break;
                }
                if (type == 0x3 /* NLMSG_DONE */) {
                    done = 1;
                }
                off += (len + 3u) & ~3u;
            }
            if (done) {
                break;
            }
        }
    }
}

static int run_netlink(const char *router_id, int join_update,
                       const char *wifi_if, int wifi_interval_ms)
{
    char err[256];
    uint8_t buf[8192];
    nfct_ctx *nfct;
    nl80211_parse_ctx *wifi = NULL;
    int fd;
    int wfd = -1;
    int family_id = 0;
    int ifindex = -1;
    struct pollfd pfds[2];
    int npfd = 1;
    uint64_t last_wifi_ms = 0;

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

    if (wifi_if && wifi_if[0]) {
        ifindex = nf_if_nametoindex(wifi_if);
        if (ifindex < 0) {
            fprintf(stderr, "forensicsd: wifi if %s not found (continuing without)\n",
                    wifi_if);
        } else {
            wfd = nl80211_netlink_open(&family_id, err, sizeof(err));
            if (wfd < 0) {
                fprintf(stderr, "forensicsd: nl80211 open: %s (continuing without)\n",
                        err);
            } else {
                (void)nl80211_netlink_set_nonblock(wfd);
                wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
                if (!wifi) {
                    nl80211_netlink_close(wfd);
                    wfd = -1;
                } else {
                    npfd = 2;
                    if (wifi_interval_ms <= 0) {
                        wifi_interval_ms = 5000;
                    }
                    fprintf(stderr,
                            "forensicsd: wifi station dump if=%s ifindex=%d "
                            "interval_ms=%d\n",
                            wifi_if, ifindex, wifi_interval_ms);
                }
            }
        }
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    fprintf(stderr,
            "forensicsd: netlink conntrack listening (router_id=%s groups=NEW%sDESTROY)\n",
            router_id, join_update ? ",UPDATE," : ",");

    pfds[0].fd = fd;
    pfds[0].events = POLLIN;
    if (npfd == 2) {
        pfds[1].fd = wfd;
        pfds[1].events = POLLIN;
    }

    last_wifi_ms = now_ms();
    while (!g_stop) {
        int timeout = 1000;
        int pr;
        uint64_t now;

        if (wfd >= 0 && wifi_interval_ms > 0) {
            uint64_t elapsed = now_ms() - last_wifi_ms;
            if (elapsed >= (uint64_t)wifi_interval_ms) {
                timeout = 0;
            } else {
                timeout = (int)((uint64_t)wifi_interval_ms - elapsed);
                if (timeout > 1000) {
                    timeout = 1000;
                }
            }
        }

        pr = poll(pfds, (nfds_t)npfd, timeout);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "forensicsd: poll: %s\n", strerror(errno));
            break;
        }

        now = now_ms();
        if (wfd >= 0 && wifi &&
            (now - last_wifi_ms) >= (uint64_t)wifi_interval_ms) {
            wifi_dump_once(wfd, family_id, ifindex, wifi, router_id);
            last_wifi_ms = now;
        }

        if (pr == 0) {
            continue;
        }
        if (pfds[0].revents & (POLLERR | POLLHUP)) {
            fprintf(stderr, "forensicsd: netlink hangup/error\n");
            break;
        }
        if (pfds[0].revents & POLLIN) {
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

    nl80211_netlink_close(wfd);
    if (wifi) {
        nl80211_parse_destroy(wifi);
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
            "          [--wifi-if IFACE] [--wifi-interval-ms N]\n"
            "  --demo        synthetic frames to stdout (default)\n"
            "  --netlink     live NETLINK_NETFILTER conntrack events\n"
            "  --router-id   CPE identifier string (default cpe-demo-001)\n"
            "  --update      also join NFNLGRP_CONNTRACK_UPDATE\n"
            "  --wifi-if     periodic nl80211 station dump on IFACE\n"
            "  --wifi-interval-ms  dump period (default 5000)\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *router_id = "cpe-demo-001";
    const char *wifi_if = NULL;
    int mode_netlink = 0;
    int join_update = 0;
    int wifi_interval_ms = 5000;
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
        if (strcmp(argv[i], "--wifi-if") == 0 && i + 1 < argc) {
            wifi_if = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--wifi-interval-ms") == 0 && i + 1 < argc) {
            wifi_interval_ms = atoi(argv[++i]);
            continue;
        }
        fprintf(stderr, "unknown arg: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    if (mode_netlink) {
        return run_netlink(router_id, join_update, wifi_if, wifi_interval_ms);
    }
    return run_demo(router_id);
}
