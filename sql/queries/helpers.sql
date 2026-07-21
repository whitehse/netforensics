-- MODULE 4: parameter helpers for path tracers.
-- Use with ClickHouse HTTP parameterized queries or client bindings.
--
-- Common parameters:
--   {router_id:String}  CPE or core router id
--   {ts:String}         ISO-like or 'YYYY-MM-DD HH:MM:SS.mmm'
--   {window_sec:UInt32} half-window around ts (default 2)
--   {lan_ip:String}     client LAN IPv4
--   {wan_ip:String}     CPE WAN IPv4
--   {wan_port:UInt16}   CPE WAN port
--   {t_start:String}    blast window start
--   {t_end:String}      blast window end

-- Example: bound window around a single event time
-- WITH
--   toDateTime64({ts:String}, 3, 'UTC') AS t0,
--   {window_sec:UInt32} AS w
-- SELECT ... WHERE timestamp BETWEEN t0 - toIntervalSecond(w) AND t0 + toIntervalSecond(w)

-- Filter by router_id (CPE perf history)
SELECT
    router_id,
    ts,
    probe,
    target,
    rtt_ms,
    loss
FROM forensics.cpe_perf_samples
WHERE router_id = {router_id:String}
  AND ts BETWEEN toDateTime64({t_start:String}, 3, 'UTC')
             AND toDateTime64({t_end:String}, 3, 'UTC')
ORDER BY ts DESC
LIMIT 500;

-- Count NAT events for a CPE in a window (ops health)
SELECT
    count() AS nat_events,
    countIf(event = 'NEW') AS news,
    countIf(event = 'DESTROY') AS destroys
FROM forensics.cpe_nat_flows
WHERE router_id = {router_id:String}
  AND timestamp BETWEEN toDateTime64({t_start:String}, 3, 'UTC')
                    AND toDateTime64({t_end:String}, 3, 'UTC');
