-- netforensics ClickHouse schema (MODULE 3)
-- Apply on a dedicated database; adjust cluster/macros as needed.

CREATE DATABASE IF NOT EXISTS forensics;

-- Prefer async inserts on ingest sessions:
--   SET async_insert = 1, async_insert_busy_timeout_ms = 1000;

CREATE TABLE IF NOT EXISTS forensics.bgp_updates
(
    router_id   LowCardinality(String),
    prefix      String,
    timestamp   DateTime64(3, 'UTC'),
    sign        Int8,              -- +1 advert, -1 withdraw
    as_path     Array(UInt32),
    next_hop    IPv4,
    peer_asn    UInt32
)
ENGINE = VersionedCollapsingMergeTree(sign, timestamp)
ORDER BY (router_id, prefix, timestamp);

CREATE TABLE IF NOT EXISTS forensics.ipfix_flows
(
    router_id     LowCardinality(String),
    timestamp     DateTime64(3, 'UTC'),
    src_ip        IPv4,
    dst_ip        IPv4,
    src_port      UInt16,
    dst_port      UInt16,
    protocol      UInt8,
    bytes         UInt64,
    packets       UInt64,
    bgp_src_as    UInt32 DEFAULT 0,
    bgp_dst_as    UInt32 DEFAULT 0,
    next_hop      IPv4 DEFAULT toIPv4('0.0.0.0'),
    ingress_if    UInt32 DEFAULT 0,
    egress_if     UInt32 DEFAULT 0
)
ENGINE = MergeTree
ORDER BY (timestamp, src_ip, dst_ip);

CREATE TABLE IF NOT EXISTS forensics.cpe_nat_flows_ingest
(
    router_id     LowCardinality(String),
    timestamp     DateTime64(3, 'UTC'),
    lan_src_ip    IPv4,
    lan_src_port  UInt16,
    wan_src_ip    IPv4,
    wan_src_port  UInt16,
    protocol      UInt8,
    event         LowCardinality(String)  -- NEW / DESTROY
)
ENGINE = MergeTree
ORDER BY (timestamp, router_id);

CREATE TABLE IF NOT EXISTS forensics.cpe_nat_flows
(
    router_id     LowCardinality(String),
    timestamp     DateTime64(3, 'UTC'),
    lan_src_ip    IPv4,
    lan_src_port  UInt16,
    wan_src_ip    IPv4,
    wan_src_port  UInt16,
    protocol      UInt8,
    event         LowCardinality(String)
)
ENGINE = MergeTree
ORDER BY (timestamp, wan_src_ip, wan_src_port);

CREATE MATERIALIZED VIEW IF NOT EXISTS forensics.cpe_nat_flows_mv
TO forensics.cpe_nat_flows
AS SELECT * FROM forensics.cpe_nat_flows_ingest;

CREATE TABLE IF NOT EXISTS forensics.cpe_wifi_metrics
(
    router_id       LowCardinality(String),
    timestamp       DateTime64(3, 'UTC'),
    client_lan_ip   IPv4,
    client_mac      String,
    rssi            Int16,
    snr             Int16,
    tx_retries      UInt32,
    mcs_index       UInt8
)
ENGINE = MergeTree
ORDER BY (timestamp, client_lan_ip, client_mac);
