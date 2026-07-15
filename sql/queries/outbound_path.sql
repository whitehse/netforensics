-- Outbound forward path tracer (MODULE 4.1)
-- Parameters: {ts}, {lan_ip}

WITH
    toDateTime64({ts:String}, 3, 'UTC') AS t0
SELECT
    n.router_id AS cpe_id,
    n.lan_src_ip,
    n.wan_src_ip,
    n.wan_src_port,
    w.rssi,
    w.tx_retries,
    f.router_id AS core_router,
    f.dst_ip,
    f.next_hop,
    f.bgp_dst_as
FROM forensics.cpe_nat_flows AS n
LEFT JOIN forensics.cpe_wifi_metrics AS w
    ON w.router_id = n.router_id
   AND w.client_lan_ip = n.lan_src_ip
   AND w.timestamp BETWEEN t0 - INTERVAL 2 SECOND AND t0 + INTERVAL 2 SECOND
LEFT JOIN forensics.ipfix_flows AS f
    ON f.src_ip = n.wan_src_ip
   AND f.src_port = n.wan_src_port
   AND f.timestamp BETWEEN t0 - INTERVAL 2 SECOND AND t0 + INTERVAL 2 SECOND
WHERE n.lan_src_ip = toIPv4({lan_ip:String})
  AND n.timestamp BETWEEN t0 - INTERVAL 1 SECOND AND t0 + INTERVAL 1 SECOND
ORDER BY n.timestamp
LIMIT 100;
