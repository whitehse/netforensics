/**
 * Unit test: flow_acct NDJSON + feed_event path (no netlink privileges).
 */
#include "cpe_agent.h"
#include "cpe_flow_acct.h"
#include "nfct.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    cpe_agent_t *a;
    cpe_agent_config_t cfg;
    nfct_event_t ev;
    cpe_flow_snapshot_t snap;
    char line[CPE_NDJSON_LINE_MAX];
    cpe_flow_entry_t e;
    size_t depth0, depth1;

    a = cpe_agent_create();
    assert(a);
    cpe_agent_config_defaults(&cfg);
    snprintf(cfg.router_id, sizeof(cfg.router_id), "test-cpe");
    snprintf(cfg.emit_mode, sizeof(cfg.emit_mode), "stdout");
    cfg.flow_acct_enabled = 1;
    cfg.flow_emit_destroy = 1;
    cfg.flow_emit_new = 0;
    cfg.demo_mode = 1;
    assert(cpe_agent_apply_config(a, &cfg) == 0);

    /* Force-enabled state even if open failed without CAP_NET_ADMIN. */
    {
        cpe_flow_state_t *st = cpe_agent_flow_state(a);
        assert(st);
        st->enabled = 1;
        st->emit_destroy = 1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = NFCT_EVENT_NEW;
    ev.protocol = 6;
    ev.has_lan = 1;
    ev.has_wan = 1;
    ev.lan_src_ip = 0xC0A80132u;
    ev.lan_src_port = 12345;
    ev.lan_dst_ip = 0x08080808u;
    ev.lan_dst_port = 443;
    ev.wan_src_ip = 0xCB007109u;
    ev.wan_src_port = 54321;
    ev.has_id = 1;
    ev.id = 0xabcdu;
    ev.has_counters = 1;
    ev.orig_packets = 10;
    ev.orig_bytes = 1000;
    ev.reply_packets = 20;
    ev.reply_bytes = 50000;
    assert(cpe_agent_flow_feed_event(a, &ev) >= 0);

    assert(cpe_agent_flow_snapshot(a, &snap) == 0);
    assert(snap.flow_count >= 1);
    assert(snap.flows[0].bytes_up == 1000);
    assert(snap.flows[0].bytes_down == 50000);

    depth0 = cpe_agent_spool_depth(a);
    memset(&ev, 0, sizeof(ev));
    ev.type = NFCT_EVENT_DESTROY;
    ev.is_destroy = 1;
    ev.protocol = 6;
    ev.has_lan = 1;
    ev.has_wan = 1;
    ev.lan_src_ip = 0xC0A80132u;
    ev.lan_src_port = 12345;
    ev.lan_dst_ip = 0x08080808u;
    ev.lan_dst_port = 443;
    ev.wan_src_ip = 0xCB007109u;
    ev.wan_src_port = 54321;
    ev.has_id = 1;
    ev.id = 0xabcdu;
    ev.has_counters = 1;
    ev.orig_packets = 40;
    ev.orig_bytes = 12000;
    ev.reply_packets = 620;
    ev.reply_bytes = 890000;
    assert(cpe_agent_flow_feed_event(a, &ev) > 0);
    depth1 = cpe_agent_spool_depth(a);
    assert(depth1 > depth0);

    memset(&e, 0, sizeof(e));
    snprintf(e.flow_id, sizeof(e.flow_id), "deadbeef");
    e.proto = 6;
    e.ip_version = 4;
    snprintf(e.lan_ip, sizeof(e.lan_ip), "192.168.1.50");
    e.lan_port = 12345;
    snprintf(e.remote_ip, sizeof(e.remote_ip), "8.8.8.8");
    e.remote_port = 443;
    snprintf(e.wan_ip, sizeof(e.wan_ip), "203.0.113.9");
    e.wan_port = 54321;
    e.bytes_up = 12000;
    e.bytes_down = 890000;
    e.orig_bytes = 12000;
    e.reply_bytes = 890000;
    snprintf(e.state, sizeof(e.state), "DESTROY");
    assert(cpe_flow_format_ndjson("r1", "destroy", &e, line, sizeof(line)) > 0);
    assert(strstr(line, "\"type\":\"cpe_flow\"") != NULL);
    assert(strstr(line, "\"event\":\"destroy\"") != NULL);
    assert(strstr(line, "\"bytes_down\":890000") != NULL);

    cpe_agent_destroy(a);
    printf("test_cpe_flow_acct PASSED\n");
    return 0;
}
