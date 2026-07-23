-- Traceroute / mtr path report (live).
--   ./cpe_agent --lua-file examples/lua/traceroute_report.lua
-- Optional globals:
--   target = "1.1.1.1"
--   max_ttl = 20
--   probes = 3          -- if set, use mtr instead of single-probe traceroute
--   timeout_ms = 800

local t = target or cpe.config().target or "1.1.1.1"
local ttl = max_ttl or 20
local to = timeout_ms or 1000

local tr
if probes and probes > 1 then
  print(string.format("mtr %s probes=%d max_ttl=%d", t, probes, ttl))
  tr = cpe.mtr(t, probes, ttl, to)
else
  print(string.format("traceroute %s max_ttl=%d", t, ttl))
  tr = cpe.traceroute(t, ttl, to)
end

print(string.format("method=%s reached=%s hops=%d dest_rtt=%.3f ms",
                    tr.method, tostring(tr.reached), tr.hop_count,
                    tr.dest_rtt_ms or 0))

for _, h in ipairs(tr.hops) do
  local addr = (h.addr and h.addr ~= "") and h.addr or "*"
  print(string.format(
    "  %2d  %-16s  last=%7.3f  avg=%7.3f  min=%7.3f  max=%7.3f  loss=%.0f%%  sent=%u",
    h.hop, addr, h.rtt_ms or 0, h.avg_rtt_ms or 0, h.min_rtt_ms or 0,
    h.max_rtt_ms or 0, (h.loss or 0) * 100, h.sent or 0))
end

if cpe.ndjson then
  local line = cpe.ndjson()
  if line then
    print("--- summary cpe_perf ---")
    print(line)
  end
end

return tr
