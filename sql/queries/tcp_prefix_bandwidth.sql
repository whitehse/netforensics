-- Control-plane traffic rollup by remote network prefix.
-- Useful for CDN / OTT views (e.g. Netflix address space) until full
-- bandwidth rules or QUIC accounting are added.
--
-- Filter example: AND prefix LIKE '45.57.%'  -- sample Netflix CDN block

SELECT
    prefix,
    sum(bytes) AS ctrl_bytes,
    sum(pkts) AS ctrl_pkts,
    sum(syn) AS syns,
    sum(fin) AS fins,
    sum(rst) AS rsts,
    sum(syn_retrans) AS retrans,
    max(remotes) AS remotes_seen,
    avg(loss_hint) AS avg_loss_hint,
    max(ts) AS last_seen
FROM forensics.cpe_tcp_stats
WHERE scope = 'prefix'
  AND router_id = {router_id:String}
  AND ts > now() - INTERVAL 1 HOUR
GROUP BY prefix
ORDER BY ctrl_bytes DESC
LIMIT 50;
