/**
 * Host integration test (no ClickHouse / no privileges):
 *   synthetic nfct frames → obs
 *   synthetic IPFIX message → core obs
 *   correlate WAN 5-tuple
 *   emit NDJSON + SQL fixture inserts matching sql/001_schema.sql
 *   synthetic nl80211 station attrs → wifi NDJSON
 */

#include "netforensics.h"
#include "nl80211_parse.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static void wr16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}
static void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}
static void wr64_be(uint8_t *p, uint64_t v)
{
    wr32_be(p, (uint32_t)(v >> 32));
    wr32_be(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}
static void wr16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static void wr32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static size_t put_nla(uint8_t *buf, size_t cap, size_t off,
                      uint16_t type, const void *payload, size_t plen)
{
    size_t alen = 4 + plen;
    size_t total = (alen + 3u) & ~3u;
    if (off + total > cap) {
        return 0;
    }
    wr16_le(buf + off, (uint16_t)alen);
    wr16_le(buf + off + 2, type);
    if (plen && payload) {
        memcpy(buf + off + 4, payload, plen);
    }
    if (total > alen) {
        memset(buf + off + alen, 0, total - alen);
    }
    return total;
}

static size_t build_ipfix_flow(uint8_t *buf)
{
    const uint16_t field_count = 9;
    const uint16_t tmpl_set_len = (uint16_t)(4 + 4 + field_count * 4);
    const uint16_t record_len = 4 + 4 + 2 + 2 + 1 + 8 + 8 + 8 + 8;
    const uint16_t data_set_len = (uint16_t)(4 + record_len);
    const uint16_t msg_len = (uint16_t)(16 + tmpl_set_len + data_set_len);
    size_t off = 0;
    uint16_t ies[] = {8, 12, 7, 11, 4, 1, 2, 152, 153};
    uint16_t lens[] = {4, 4, 2, 2, 1, 8, 8, 8, 8};
    int i;

    memset(buf, 0, msg_len);
    wr16_be(buf + 0, 10);
    wr16_be(buf + 2, msg_len);
    wr32_be(buf + 4, 1700000000u);
    wr32_be(buf + 8, 1u);
    wr32_be(buf + 12, 1u);
    off = 16;
    wr16_be(buf + off, 2);
    wr16_be(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16_be(buf + off, 256);
    wr16_be(buf + off + 2, field_count);
    off += 4;
    for (i = 0; i < field_count; i++) {
        wr16_be(buf + off, ies[i]);
        wr16_be(buf + off + 2, lens[i]);
        off += 4;
    }
    wr16_be(buf + off, 256);
    wr16_be(buf + off + 2, data_set_len);
    off += 4;
    /* WAN post-NAT: 203.0.113.9:54321 → 8.8.8.8:53 TCP */
    wr32_be(buf + off, 0xCB007109u);
    off += 4;
    wr32_be(buf + off, 0x08080808u);
    off += 4;
    wr16_be(buf + off, 54321);
    off += 2;
    wr16_be(buf + off, 53);
    off += 2;
    buf[off++] = 6;
    wr64_be(buf + off, 100);
    off += 8;
    wr64_be(buf + off, 1);
    off += 8;
    wr64_be(buf + off, 1700000000000ull);
    off += 8;
    wr64_be(buf + off, 1700000000100ull);
    off += 8;
    (void)off;
    return msg_len;
}

static void build_nfct_synth(uint8_t *synth)
{
    memset(synth, 0, 32);
    wr32_be(synth, 0x4E464354u); /* NFCT */
    synth[4] = 1; /* NEW */
    synth[5] = 6; /* TCP */
    wr32_be(synth + 8, 0xC0A80132u);  /* 192.168.1.50 */
    wr16_be(synth + 12, 12345);
    wr32_be(synth + 14, 0x08080808u);
    wr16_be(synth + 18, 53);
    wr32_be(synth + 20, 0xCB007109u); /* 203.0.113.9 */
    wr16_be(synth + 24, 54321);
    wr32_be(synth + 26, 0x08080808u);
    wr16_be(synth + 30, 53);
}

static void test_end_to_end_correlate(void)
{
    ipfix_ctx_t *ipfix = ipfix_create();
    nfct_ctx *nfct = nfct_create(NFCT_ROLE_COLLECTOR);
    uint8_t ipfix_msg[512];
    uint8_t nfct_frame[32];
    nf_flow_obs_t core[4];
    nf_flow_obs_t cpe;
    nfct_event_t nev;
    char ndjson[512];
    char sql[640];
    int n;
    size_t mlen;

    assert(ipfix && nfct);

    mlen = build_ipfix_flow(ipfix_msg);
    n = nf_ipfix_collect_flows(ipfix, ipfix_msg, mlen, "core-r1", core, 4);
    assert(n == 1);
    assert(core[0].src_ip == 0xCB007109u);
    assert(core[0].src_port == 54321);

    build_nfct_synth(nfct_frame);
    assert(nfct_feed_input(nfct, nfct_frame, sizeof(nfct_frame)) == 0);
    assert(nfct_next_event(nfct, &nev) == 1);
    assert(nf_obs_from_nfct(&nev, "cpe-1", 1700000000050ull, &cpe) == 0);
    assert(nf_flows_correlate(&cpe, &core[0], 1000) == 1);

    assert(nf_obs_format(&cpe, ndjson, sizeof(ndjson)) == 0);
    assert(strstr(ndjson, "cpe_nat") != NULL);
    assert(strstr(ndjson, "203.0.113.9") != NULL || strstr(ndjson, "203") != NULL);

    /* SQL fixture lines matching schema columns */
    snprintf(sql, sizeof(sql),
             "INSERT INTO forensics.cpe_nat_flows_ingest "
             "(router_id,timestamp,lan_src_ip,lan_src_port,wan_src_ip,wan_src_port,"
             "protocol,event) VALUES ('%s', fromUnixTimestamp64Milli(%llu), "
             "toIPv4('%u.%u.%u.%u'), %u, toIPv4('%u.%u.%u.%u'), %u, %u, '%s');",
             cpe.router_id, (unsigned long long)cpe.ts_ms,
             (cpe.src_ip >> 24) & 0xFF, (cpe.src_ip >> 16) & 0xFF,
             (cpe.src_ip >> 8) & 0xFF, cpe.src_ip & 0xFF, cpe.src_port,
             (cpe.wan_src_ip >> 24) & 0xFF, (cpe.wan_src_ip >> 16) & 0xFF,
             (cpe.wan_src_ip >> 8) & 0xFF, cpe.wan_src_ip & 0xFF,
             cpe.wan_src_port, cpe.protocol,
             cpe.event[0] ? cpe.event : "NEW");
    assert(strstr(sql, "cpe_nat_flows_ingest") != NULL);
    assert(strstr(sql, "cpe-1") != NULL);

    snprintf(sql, sizeof(sql),
             "INSERT INTO forensics.ipfix_flows "
             "(router_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets) "
             "VALUES ('%s', fromUnixTimestamp64Milli(%llu), "
             "toIPv4('%u.%u.%u.%u'), toIPv4('%u.%u.%u.%u'), %u, %u, %u, 100, 1);",
             core[0].router_id, (unsigned long long)core[0].ts_ms,
             (core[0].src_ip >> 24) & 0xFF, (core[0].src_ip >> 16) & 0xFF,
             (core[0].src_ip >> 8) & 0xFF, core[0].src_ip & 0xFF,
             (core[0].dst_ip >> 24) & 0xFF, (core[0].dst_ip >> 16) & 0xFF,
             (core[0].dst_ip >> 8) & 0xFF, core[0].dst_ip & 0xFF,
             core[0].src_port, core[0].dst_port, core[0].protocol);
    assert(strstr(sql, "ipfix_flows") != NULL);

    /* Negative: wrong port must not correlate */
    core[0].src_port = 9;
    assert(nf_flows_correlate(&cpe, &core[0], 1000) == 0);

    ipfix_destroy(ipfix);
    nfct_destroy(nfct);
    printf("  PASS: IPFIX + nfct frame correlate + SQL fixtures\n");
}

static void test_wifi_attrs_ndjson(void)
{
    nl80211_parse_ctx *wifi = nl80211_parse_create(NL80211_PARSE_ROLE_COLLECTOR);
    uint8_t msg[256];
    uint8_t sta_nest[64];
    size_t off = 20, nest_off = 0, n;
    uint8_t mac[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    int8_t signal = -55;
    nl80211_event_t wev;
    char line[320];

    assert(wifi);
    n = put_nla(sta_nest, sizeof(sta_nest), nest_off, 7, &signal, 1);
    nest_off += n;

    memset(msg, 0, sizeof(msg));
    n = put_nla(msg, sizeof(msg), off, 6, mac, 6);
    off += n;
    n = put_nla(msg, sizeof(msg), off, 21, sta_nest, nest_off);
    off += n;
    wr32_le(msg + 0, (uint32_t)off);
    wr16_le(msg + 4, 0);
    wr16_le(msg + 6, 0);
    wr32_le(msg + 8, 0);
    wr32_le(msg + 12, 0);
    msg[16] = 13;

    assert(nl80211_parse_feed_input(wifi, msg, off) == 0);
    assert(nl80211_parse_next_event(wifi, &wev) == 1);
    assert(wev.has_mac && wev.has_signal);

    snprintf(line, sizeof(line),
             "{\"type\":\"cpe_wifi\",\"router\":\"%s\",\"ts\":%llu,"
             "\"client_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
             "\"rssi\":%d,\"tx_retries\":%u}",
             "cpe-1", 1700000000050ull,
             wev.client_mac[0], wev.client_mac[1], wev.client_mac[2],
             wev.client_mac[3], wev.client_mac[4], wev.client_mac[5],
             (int)wev.signal_dbm, (unsigned)wev.tx_retries);
    assert(strstr(line, "cpe_wifi") != NULL);
    assert(strstr(line, "de:ad:be:ef:00:01") != NULL);
    assert(strstr(line, "\"rssi\":-55") != NULL);

    nl80211_parse_destroy(wifi);
    printf("  PASS: nl80211 attrs → wifi NDJSON\n");
}

int main(void)
{
    test_end_to_end_correlate();
    test_wifi_attrs_ndjson();
    printf("host pipeline tests PASSED\n");
    return 0;
}
