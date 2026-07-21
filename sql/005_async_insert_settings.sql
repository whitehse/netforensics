-- MODULE 3: async insert settings for Vector → ClickHouse ingest sessions.
-- Prefer applying on the ingest user / profile, not globally on analytical users.

-- Example profile for the Vector service account:
-- CREATE USER IF NOT EXISTS vector_ingest IDENTIFIED BY '…';
-- GRANT INSERT ON forensics.* TO vector_ingest;

-- Session-level (Vector can send as query settings / HTTP headers):
--   async_insert=1
--   wait_for_async_insert=0
--   async_insert_busy_timeout_ms=1000
--   async_insert_max_data_size=10000000

-- Server defaults (optional; site-specific):
-- SET GLOBAL async_insert = 1;  -- not all CH versions support GLOBAL

-- Recommended ClickHouse settings for 20k CPE fan-in (document in ops runbook):
--   max_insert_block_size = 1048576
--   min_insert_block_size_rows = 10000
--   async_insert_threads = 4

-- Verify under load:
--   SELECT * FROM system.asynchronous_inserts;
--   SELECT * FROM system.metrics WHERE metric LIKE '%AsyncInsert%';
