-- Example tool script: sequential live pings.
--   ./cpe_agent --config live.yaml --lua-file examples/lua/ping_sweep.lua
--
-- Optional: set global `targets` before dofile from the REPL:
--   targets = {"10.0.0.1", "1.1.1.1"}
--   cpe.dofile("examples/lua/ping_sweep.lua")

local list = targets or {
  "1.1.1.1",
  "8.8.8.8",
}

local results = {}
for _, ip in ipairs(list) do
  local ok, s = pcall(function()
    return cpe.live_ping(ip)
  end)
  if ok and s then
    results[#results + 1] = s
    print(string.format("%-18s rtt=%8.3f ms  loss=%.4f",
                        s.target, s.rtt_ms, s.loss))
  else
    print(string.format("%-18s ERROR %s", ip, tostring(s)))
  end
end
return results
