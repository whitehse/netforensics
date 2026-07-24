/**
 * @file test_cpe_tcp_stats.c
 * @brief Unit tests for TCP NFLOG parse + aggregation (no CAP_NET_ADMIN).
 */
#include "cpe_agent.h"
#include "cpe_tcp_stats.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Minimal IPv4 + TCP SYN: 192.168.1.10:54321 → 45.57.10.1:443 */
static void build_syn(uint8_t *pkt, size_t *len_out)
{
    /* IP header 20 + TCP 20 */
    static const uint8_t frame[] = {
        /* IPv4 */
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x0a, /* 192.168.1.10 */
        0x2d, 0x39, 0x0a, 0x01, /* 45.57.10.1 */
        /* TCP */
        0xd4, 0x31,             /* sport 54321 */
        0x01, 0xbb,             /* dport 443 */
        0x00, 0x00, 0x00, 0x01, /* seq */
        0x00, 0x00, 0x00, 0x00, /* ack */
        0x50, 0x02,             /* doff=5, flags=SYN */
        0x72, 0x10, 0x00, 0x00, 0x00, 0x00};
    memcpy(pkt, frame, sizeof(frame));
    *len_out = sizeof(frame);
}

static void build_rst(uint8_t *pkt, size_t *len_out)
{
    static const uint8_t frame[] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        0x2d, 0x39, 0x0a, 0x01, /* 45.57.10.1 */
        0xc0, 0xa8, 0x01, 0x0a, /* 192.168.1.10 */
        0x01, 0xbb, 0xd4, 0x31, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x04, /* RST */
        0x72, 0x10, 0x00, 0x00, 0x00, 0x00};
    memcpy(pkt, frame, sizeof(frame));
    *len_out = sizeof(frame);
}

static void test_parse_syn(void)
{
    uint8_t pkt[64];
    size_t len = 0;
    cpe_tcp_packet_t p;

    build_syn(pkt, &len);
    assert(cpe_tcp_parse_ip_packet(pkt, len, &p) == 0);
    assert(strcmp(p.src_ip, "192.168.1.10") == 0);
    assert(strcmp(p.dst_ip, "45.57.10.1") == 0);
    assert(p.src_port == 54321);
    assert(p.dst_port == 443);
    assert((p.flags & CPE_TCP_FLAG_SYN) != 0);
    assert((p.flags & CPE_TCP_FLAG_ACK) == 0);
    printf("  PASS: parse SYN\n");
}

static void test_aggregate_and_emit(void)
{
    cpe_agent_t *a;
    cpe_agent_config_t cfg;
    uint8_t pkt[64];
    size_t len = 0;
    cpe_tcp_snapshot_t snap;
    cpe_tcp_remote_t rem;
    cpe_tcp_prefix_t pfx;
    char line[CPE_TCP_NDJSON_MAX];
    int n;

    a = cpe_agent_create();
    assert(a);
    cfg = *cpe_agent_config(a);
    cfg.tcp_stats_enabled = 1;
    cfg.tcp_prefix_len = 16; /* Netflix-ish CDN blocks often /16 */
    cfg.tcp_emit_top_n = 5;
    assert(cpe_agent_apply_config(a, &cfg) == 0);

    build_syn(pkt, &len);
    assert(cpe_agent_tcp_feed_payload(a, pkt, len) == 0);
    assert(cpe_agent_tcp_feed_payload(a, pkt, len) == 0); /* retrans */

    build_rst(pkt, &len);
    assert(cpe_agent_tcp_feed_payload(a, pkt, len) == 0);

    assert(cpe_agent_tcp_snapshot(a, &snap) == 0);
    assert(snap.pkt_total == 3);
    assert(snap.syn_total >= 2);
    assert(snap.rst_total >= 1);
    assert(snap.syn_retrans_total >= 1);
    assert(snap.remote_count >= 1);

    assert(cpe_agent_tcp_remote(a, "45.57.10.1", &rem) == 0);
    assert(rem.syn_count >= 2);
    assert(rem.rst_count >= 1);
    assert(rem.syn_retrans >= 1);
    assert(cpe_tcp_loss_hint(rem.syn_count, rem.fin_count, rem.rst_count,
                             rem.syn_retrans) > 0.0f);

    assert(cpe_agent_tcp_prefix(a, "45.57.0.0/16", &pfx) == 0);
    assert(pfx.pkt_count >= 3);
    assert(pfx.bytes_est > 0);

    n = cpe_tcp_format_ndjson("cpe-test", "summary", &snap, NULL, NULL, line,
                              sizeof(line));
    assert(n > 0);
    assert(strstr(line, "\"type\":\"cpe_tcp\"") != NULL);
    assert(strstr(line, "\"scope\":\"summary\"") != NULL);

    n = cpe_agent_tcp_emit(a, 5);
    assert(n >= 1);
    assert(cpe_agent_spool_depth(a) >= 1);

    cpe_agent_tcp_reset(a);
    assert(cpe_agent_tcp_snapshot(a, &snap) == 0);
    assert(snap.pkt_total == 0);

    cpe_agent_destroy(a);
    printf("  PASS: aggregate + emit + reset\n");
}

static void test_yaml_tcp_config(void)
{
    const char *yaml =
        "router_id: cpe-tcp-1\n"
        "demo:\n"
        "  enabled: true\n"
        "  target: \"1.1.1.1\"\n"
        "tcp_stats:\n"
        "  enabled: true\n"
        "  nflog_group: 5\n"
        "  nflog_size: 60\n"
        "  emit_interval_ms: 15000\n"
        "  emit_top_n: 10\n"
        "  prefix_len: 24\n";
    cpe_agent_config_t cfg;
    char err[128];

    assert(cpe_agent_config_load_yaml_buf(yaml, strlen(yaml), &cfg, err,
                                          sizeof(err)) == 0);
    assert(cfg.tcp_stats_enabled == 1);
    assert(cfg.tcp_nflog_group == 5);
    assert(cfg.tcp_nflog_size == 60);
    assert(cfg.tcp_emit_interval_ms == 15000);
    assert(cfg.tcp_emit_top_n == 10);
    assert(cfg.tcp_prefix_len == 24);
    printf("  PASS: yaml tcp_stats\n");
}

int main(void)
{
    printf("cpe_tcp_stats:\n");
    test_parse_syn();
    test_aggregate_and_emit();
    test_yaml_tcp_config();
    printf("all passed\n");
    return 0;
}
