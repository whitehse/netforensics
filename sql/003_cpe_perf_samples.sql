-- CPE performance samples (Track 2 / N-A05).
-- Apply inside ClickHouse database forensics (same as sql/001_schema.sql).
-- Does not supersede ADR-002 fan-in; extends NDJSON types with type=cpe_perf.

CREATE TABLE IF NOT EXISTS forensics.cpe_perf_samples
(
    router_id   LowCardinality(String),
    ts          DateTime64(3, 'UTC'),
    probe       LowCardinality(String),  -- 'ping', 'arping', 'http_rtt', ...
    target      String,
    rtt_ms      Float64,
    loss        Float32,
    meta        String                   -- small JSON; keep small for insert path
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (router_id, probe, ts);

-- Optional lab path when Vector uses async insert / Null staging:
-- CREATE TABLE forensics.cpe_perf_samples_ingest AS forensics.cpe_perf_samples
-- ENGINE = Null;
