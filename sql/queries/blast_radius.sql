-- Blast radius analysis (MODULE 4.3)
-- Parameters: {t_start}, {t_end}, customer IP list via temporary table or array

WITH
    toDateTime64({t_start:String}, 3, 'UTC') AS t0,
    toDateTime64({t_end:String}, 3, 'UTC') AS t1
SELECT
    'wifi' AS root_class,
    w.router_id AS key,
    countDistinct(n.lan_src_ip) AS affected_hosts,
    avg(w.rssi) AS avg_rssi,
    avg(w.tx_retries) AS avg_retries
FROM forensics.cpe_nat_flows AS n
JOIN forensics.cpe_wifi_metrics AS w
    ON w.router_id = n.router_id
   AND w.client_lan_ip = n.lan_src_ip
WHERE n.timestamp BETWEEN t0 AND t1
GROUP BY w.router_id

UNION ALL

SELECT
    'core' AS root_class,
    f.router_id AS key,
    countDistinct(f.src_ip) AS affected_hosts,
    0 AS avg_rssi,
    0 AS avg_retries
FROM forensics.ipfix_flows AS f
WHERE f.timestamp BETWEEN t0 AND t1
GROUP BY f.router_id

UNION ALL

SELECT
    'bgp_as' AS root_class,
    toString(f.bgp_dst_as) AS key,
    countDistinct(f.src_ip) AS affected_hosts,
    0 AS avg_rssi,
    0 AS avg_retries
FROM forensics.ipfix_flows AS f
WHERE f.timestamp BETWEEN t0 AND t1
  AND f.bgp_dst_as != 0
GROUP BY f.bgp_dst_as

ORDER BY affected_hosts DESC
LIMIT 50;
