#include "netforensics.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}
static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

static size_t build_flow_message(uint8_t *buf)
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
    wr16(buf + 0, 10);
    wr16(buf + 2, msg_len);
    wr32(buf + 4, 1700000000u);
    wr32(buf + 8, 1u);
    wr32(buf + 12, 1u);
    off = 16;
    wr16(buf + off, 2);
    wr16(buf + off + 2, tmpl_set_len);
    off += 4;
    wr16(buf + off, 256);
    wr16(buf + off + 2, field_count);
    off += 4;
    for (i = 0; i < field_count; i++) {
        wr16(buf + off, ies[i]);
        wr16(buf + off + 2, lens[i]);
        off += 4;
    }
    wr16(buf + off, 256);
    wr16(buf + off + 2, data_set_len);
    off += 4;
    /* src 203.0.113.9 sport 54321 dst 8.8.8.8 dport 53 proto 6 */
    wr32(buf + off, 0xCB007109u);
    off += 4;
    wr32(buf + off, 0x08080808u);
    off += 4;
    wr16(buf + off, 54321);
    off += 2;
    wr16(buf + off, 53);
    off += 2;
    buf[off++] = 6;
    wr64(buf + off, 100);
    off += 8;
    wr64(buf + off, 1);
    off += 8;
    wr64(buf + off, 1700000000000ull);
    off += 8;
    wr64(buf + off, 1700000000100ull);
    off += 8;
    (void)off;
    return msg_len;
}

int main(void)
{
    ipfix_ctx_t *ctx = ipfix_create();
    uint8_t msg[512];
    size_t mlen;
    nf_flow_obs_t flows[4];
    nf_flow_obs_t cpe;
    nfct_event_t nev;
    int n;
    char line[256];

    assert(ctx);
    mlen = build_flow_message(msg);
    n = nf_ipfix_collect_flows(ctx, msg, mlen, "core-r1", flows, 4);
    assert(n == 1);
    assert(flows[0].src_ip == 0xCB007109u);
    assert(flows[0].src_port == 54321);

    memset(&nev, 0, sizeof(nev));
    nev.type = NFCT_EVENT_NEW;
    nev.protocol = 6;
    nev.lan_src_ip = 0xC0A80132u;
    nev.lan_src_port = 12345;
    nev.lan_dst_ip = 0x08080808u;
    nev.lan_dst_port = 53;
    nev.wan_src_ip = 0xCB007109u;
    nev.wan_src_port = 54321;
    nev.has_lan = 1;
    nev.has_wan = 1;
    assert(nf_obs_from_nfct(&nev, "cpe-1", 1700000000050ull, &cpe) == 0);
    assert(nf_flows_correlate(&cpe, &flows[0], 1000) == 1);

    assert(nf_obs_format(&cpe, line, sizeof(line)) == 0);
    assert(strstr(line, "cpe_nat") != NULL);

    printf("correlate test PASSED\n");
    ipfix_destroy(ctx);
    return 0;
}
