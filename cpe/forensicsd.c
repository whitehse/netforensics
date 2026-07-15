/**
 * forensicsd — OpenWrt CPE forensics daemon (scaffold).
 *
 * Production path: AF_NETLINK NETLINK_NETFILTER + nl80211 genl.
 * Scaffold path: emit NDJSON from synthetic nfct/nl80211 frames so the
 * pipeline can be tested without kernel privileges.
 */

#include "netforensics.h"
#include "nl80211_parse.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

int main(int argc, char **argv)
{
    const char *router_id = "cpe-demo-001";
    nfct_ctx *nfct;
    nl80211_parse_ctx *wifi;
    nfct_event_t nev;
    nl80211_event_t wev;
    nf_flow_obs_t obs;
    char line[512];
    uint8_t synth[32];
    uint8_t wsynth[20];
    int demo = 1;

    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("forensicsd [--demo]\n");
        return 0;
    }

    printf("# forensicsd 0.1.0 scaffold (router_id=%s)\n", router_id);

    nfct = nfct_create(NFCT_ROLE_COLLECTOR);
    wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    if (!nfct || !wifi) {
        fprintf(stderr, "create failed\n");
        return 1;
    }

    if (demo) {
        /* Synthetic NAT NEW: lan 192.168.1.50:12345 -> wan 203.0.113.9:54321 proto TCP */
        memset(synth, 0, sizeof(synth));
        wr32_be(synth, 0x4E464354u);
        synth[4] = 1; /* NEW */
        synth[5] = 6; /* TCP */
        wr32_be(synth + 8, 0xC0A80132u);  /* 192.168.1.50 */
        wr16_be(synth + 12, 12345);
        wr32_be(synth + 14, 0x08080808u); /* 8.8.8.8 */
        wr16_be(synth + 18, 53);
        wr32_be(synth + 20, 0xCB007109u); /* 203.0.113.9 */
        wr16_be(synth + 24, 54321);
        wr32_be(synth + 26, 0x08080808u);
        wr16_be(synth + 30, 53);
        nfct_feed_input(nfct, synth, sizeof(synth));

        while (nfct_next_event(nfct, &nev) == 1) {
            if (nf_obs_from_nfct(&nev, router_id, 1700000000000ull, &obs) == 0) {
                nf_obs_format(&obs, line, sizeof(line));
                puts(line);
            }
        }

        memset(wsynth, 0, sizeof(wsynth));
        wr32_be(wsynth, 0x38323131u);
        wsynth[4] = 0xaa;
        wsynth[5] = 0xbb;
        wsynth[6] = 0xcc;
        wsynth[7] = 0xdd;
        wsynth[8] = 0xee;
        wsynth[9] = 0xff;
        wr32_be(wsynth + 10, (uint32_t)(int32_t)-65); /* RSSI */
        wsynth[14] = 25;  /* SNR */
        wsynth[15] = 7;   /* MCS */
        wr32_be(wsynth + 16, 3);
        nl80211_parse_feed_input(wifi, wsynth, sizeof(wsynth));
        while (nl80211_parse_next_event(wifi, &wev) == 1) {
            char wbuf[256];
            nl80211_event_to_string(&wev, wbuf, sizeof(wbuf));
            printf("{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"detail\":\"%s\"}\n",
                   router_id, wbuf);
        }
    }

    nfct_destroy(nfct);
    nl80211_parse_destroy(wifi);
    return 0;
}
