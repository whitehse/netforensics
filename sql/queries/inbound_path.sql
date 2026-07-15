-- Inbound reverse path tracer (MODULE 4.2)
-- Parameters: {ts}, {wan_ip}, {wan_port}

WITH
    toDateTime64({ts:String}, 3, 'UTC') AS t0
SELECT
    f.router_id AS core_router,
    f.src_ip AS internet_src,
    f.dst_ip AS wan_ip,
    f.dst_port AS wan_port,
    n.lan_src_ip AS internal_host,
    n.lan_src_port,
    w.rssi,
    w.tx_retries,
    w.mcs_index
FROM forensics.ipfix_flows AS f
LEFT JOIN forensics.cpe_nat_flows AS n
    ON n.wan_src_ip = f.dst_ip
   AND n.wan_src_port = f.dst_port
   AND n.timestamp BETWEEN t0 - INTERVAL 2 SECOND AND t0 + INTERVAL 2 SECOND
LEFT JOIN forensics.cpe_wifi_metrics AS w
    ON w.router_id = n.router_id
   AND w.client_lan_ip = n.lan_src_ip
   AND w.timestamp BETWEEN t0 - INTERVAL 2 SECOND AND t0 + INTERVAL 2 SECOND
WHERE f.dst_ip = toIPv4({wan_ip:String})
  AND f.dst_port = {wan_port:UInt16}
  AND f.timestamp BETWEEN t0 - INTERVAL 1 SECOND AND t0 + INTERVAL 1 SECOND
ORDER BY f.timestamp
LIMIT 100;
