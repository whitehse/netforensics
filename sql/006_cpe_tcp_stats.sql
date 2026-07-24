-- CPE TCP control-plane stats from NFLOG (SYN/FIN/RST) — type=cpe_tcp.
-- Apply inside ClickHouse database forensics (after 001_schema.sql).
-- Vector path: route type=="cpe_tcp" → this table.
-- edgehost path: also dual-writes typed rows (see edgehost/sql/clickhouse/002).

CREATE TABLE IF NOT EXISTS forensics.cpe_tcp_stats
(
    router_id    LowCardinality(String),
    ts           DateTime64(3, 'UTC'),
    scope        LowCardinality(String),  -- summary | remote | prefix
    remote_ip    String DEFAULT '',
    local_ip     String DEFAULT '',
    prefix       String DEFAULT '',       -- e.g. 45.57.0.0/16
    remote_port  UInt16 DEFAULT 0,
    local_port   UInt16 DEFAULT 0,
    syn          UInt32,
    fin          UInt32,
    rst          UInt32,
    syn_retrans  UInt32,
    pkts         UInt32,
    bytes        UInt64,
    remotes      UInt32 DEFAULT 0,        -- summary/prefix unique remotes
    loss_hint    Float32,                 -- ranking signal, not true loss%
    prefix_len   UInt8 DEFAULT 0,
    nflog_group  UInt16 DEFAULT 5,
    meta         String DEFAULT '{}'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (router_id, scope, remote_ip, prefix, ts);

-- Loss to a particular remote IP (last hour)
-- SELECT remote_ip, sum(rst) AS rsts, sum(syn_retrans) AS retrans,
--        avg(loss_hint) AS avg_loss
-- FROM forensics.cpe_tcp_stats
-- WHERE scope = 'remote' AND router_id = {router:String}
--   AND ts > now() - INTERVAL 1 HOUR
-- GROUP BY remote_ip
-- ORDER BY avg_loss DESC
-- LIMIT 20;

-- Bandwidth-ish (bytes of control packets) to a remote network (e.g. Netflix CDN)
-- SELECT prefix, sum(bytes) AS ctrl_bytes, sum(pkts) AS ctrl_pkts,
--        sum(syn) AS syns, sum(rst) AS rsts, avg(loss_hint) AS loss
-- FROM forensics.cpe_tcp_stats
-- WHERE scope = 'prefix' AND prefix LIKE '45.57.%'
--   AND ts > now() - INTERVAL 1 HOUR
-- GROUP BY prefix
-- ORDER BY ctrl_bytes DESC;
