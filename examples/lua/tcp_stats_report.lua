-- TCP NFLOG control-plane report (SYN/FIN/RST).
-- Usage:
--   cpe_agent --lua-file examples/lua/tcp_stats_report.lua --config /etc/cpe_agent/cpe_agent.yaml
--
-- On device: enable tcp_stats in YAML, install iptables NFLOG rules for group 5,
-- then poll/emit. Without CAP_NET_ADMIN this script still prints empty stats.

local function printf(fmt, ...)
  print(string.format(fmt, ...))
end

-- Prefer config; allow optional group override from global.
local group = nflog_group or nil
if group then
  local ok, err = cpe.tcp_open(group)
  if not ok then
    printf("tcp_open failed: %s (continuing with feed-only / empty)", tostring(err))
  end
else
  -- Ensure enabled if YAML did not; open default group 5.
  local c = cpe.config()
  if not c.tcp_stats then
    local ok, err = cpe.tcp_open(5)
    if not ok then
      printf("tcp_open failed: %s", tostring(err))
    end
  else
    cpe.tcp_poll(256)
  end
end

local n = cpe.tcp_poll(256)
printf("polled packets: %s", tostring(n))

local s = cpe.tcp_stats()
if not s then
  print("no tcp stats")
  return
end

printf("summary group=%s syn=%s fin=%s rst=%s retrans=%s pkts=%s bytes=%s loss_hint=%.4f",
  tostring(s.nflog_group), tostring(s.syn), tostring(s.fin), tostring(s.rst),
  tostring(s.syn_retrans), tostring(s.pkts), tostring(s.bytes), s.loss_hint or 0)

print("--- top remotes ---")
local remotes = cpe.tcp_by_ip() or {}
table.sort(remotes, function(a, b) return (a.pkts or 0) > (b.pkts or 0) end)
for i, r in ipairs(remotes) do
  if i > 15 then break end
  printf("%s  syn=%s rst=%s retrans=%s pkts=%s bytes=%s loss=%.4f",
    r.remote_ip, tostring(r.syn), tostring(r.rst), tostring(r.syn_retrans),
    tostring(r.pkts), tostring(r.bytes), r.loss_hint or 0)
end

print("--- prefixes ---")
local prefixes = cpe.tcp_by_prefix() or {}
table.sort(prefixes, function(a, b) return (a.bytes or 0) > (b.bytes or 0) end)
for i, p in ipairs(prefixes) do
  if i > 15 then break end
  printf("%s  pkts=%s bytes=%s loss=%.4f",
    p.prefix, tostring(p.pkts), tostring(p.bytes), p.loss_hint or 0)
end

local lines = cpe.tcp_emit(10)
printf("emitted cpe_tcp lines: %s", tostring(lines))
local flushed = cpe.emit()
printf("flushed spool lines: %s", tostring(flushed))
