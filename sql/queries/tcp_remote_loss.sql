-- Packet-loss ranking for TCP control-plane events (NFLOG SYN/FIN/RST).
-- Parameters: {router_id:String}, optional time window.

SELECT
    remote_ip,
    sum(syn) AS syns,
    sum(fin) AS fins,
    sum(rst) AS rsts,
    sum(syn_retrans) AS retrans,
    sum(pkts) AS pkts,
    sum(bytes) AS ctrl_bytes,
    avg(loss_hint) AS avg_loss_hint,
    max(ts) AS last_seen
FROM forensics.cpe_tcp_stats
WHERE scope = 'remote'
  AND router_id = {router_id:String}
  AND ts > now() - INTERVAL 1 HOUR
GROUP BY remote_ip
HAVING pkts > 0
ORDER BY avg_loss_hint DESC, rsts DESC
LIMIT 50;
