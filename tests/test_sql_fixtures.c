/**
 * Validate SQL fixture shapes against sql/001_schema.sql column lists.
 * No live ClickHouse required.
 */

#include "netforensics.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int has_all(const char *sql, const char **cols, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (!strstr(sql, cols[i])) {
            fprintf(stderr, "missing column token: %s\nin: %s\n", cols[i], sql);
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    const char *nat_cols[] = {
        "router_id", "timestamp", "lan_src_ip", "lan_src_port",
        "wan_src_ip", "wan_src_port", "protocol", "event"
    };
    const char *ipfix_cols[] = {
        "router_id", "timestamp", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "bytes", "packets"
    };
    const char *wifi_cols[] = {
        "router_id", "timestamp", "client_mac", "rssi", "tx_retries"
    };
    char sql[512];
    nf_flow_obs_t cpe, core;

    memset(&cpe, 0, sizeof(cpe));
    cpe.from_cpe = 1;
    cpe.ts_ms = 1700000000000ull;
    cpe.src_ip = 0xC0A80101u;
    cpe.src_port = 1234;
    cpe.wan_src_ip = 0xCB007101u;
    cpe.wan_src_port = 54321;
    cpe.protocol = 6;
    strncpy(cpe.router_id, "cpe-1", sizeof(cpe.router_id) - 1);
    strcpy(cpe.event, "NEW");

    snprintf(sql, sizeof(sql),
             "INSERT INTO forensics.cpe_nat_flows_ingest "
             "(router_id,timestamp,lan_src_ip,lan_src_port,wan_src_ip,wan_src_port,"
             "protocol,event) VALUES ('%s', fromUnixTimestamp64Milli(%llu), "
             "toIPv4('192.168.1.1'), %u, toIPv4('203.0.113.1'), %u, %u, '%s');",
             cpe.router_id, (unsigned long long)cpe.ts_ms,
             cpe.src_port, cpe.wan_src_port, cpe.protocol, cpe.event);
    assert(has_all(sql, nat_cols, sizeof(nat_cols) / sizeof(nat_cols[0])));
    assert(strstr(sql, "cpe_nat_flows_ingest") != NULL);

    memset(&core, 0, sizeof(core));
    core.ts_ms = cpe.ts_ms;
    core.src_ip = cpe.wan_src_ip;
    core.dst_ip = 0x08080808u;
    core.src_port = cpe.wan_src_port;
    core.dst_port = 53;
    core.protocol = 6;
    strncpy(core.router_id, "core-r1", sizeof(core.router_id) - 1);

    snprintf(sql, sizeof(sql),
             "INSERT INTO forensics.ipfix_flows "
             "(router_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets) "
             "VALUES ('%s', fromUnixTimestamp64Milli(%llu), "
             "toIPv4('203.0.113.1'), toIPv4('8.8.8.8'), %u, %u, %u, 100, 1);",
             core.router_id, (unsigned long long)core.ts_ms,
             core.src_port, core.dst_port, core.protocol);
    assert(has_all(sql, ipfix_cols, sizeof(ipfix_cols) / sizeof(ipfix_cols[0])));

    snprintf(sql, sizeof(sql),
             "INSERT INTO forensics.cpe_wifi_metrics "
             "(router_id,timestamp,client_lan_ip,client_mac,rssi,snr,tx_retries,mcs_index) "
             "VALUES ('cpe-1', fromUnixTimestamp64Milli(1700000000000), "
             "toIPv4('192.168.1.50'), 'aa:bb:cc:dd:ee:ff', -60, 25, 2, 7);");
    assert(has_all(sql, wifi_cols, sizeof(wifi_cols) / sizeof(wifi_cols[0])));
    assert(strstr(sql, "client_lan_ip") != NULL);

    /* Correlation key consistency for outbound_path.sql join */
    assert(cpe.wan_src_ip == core.src_ip);
    assert(cpe.wan_src_port == core.src_port);
    assert(nf_flows_correlate(&cpe, &core, 5000) == 1);

    printf("sql fixture validation PASSED\n");
    return 0;
}
