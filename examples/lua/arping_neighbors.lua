-- Example: ARP a few LAN hosts (live).
--   ./cpe_agent --lua-file examples/lua/arping_neighbors.lua
-- Needs CAP_NET_RAW / root. Override:
--   targets = {"192.168.1.1","192.168.1.2"}; iface = "br-lan"

local list = targets or {
  "192.168.1.1",
}
local ifc = iface or nil

if ifc then
  cpe.set_iface(ifc)
end

local results = {}
for _, ip in ipairs(list) do
  local ok, s = pcall(function()
    return cpe.arping(ip, ifc)
  end)
  if ok and s then
    results[#results + 1] = s
    print(string.format("%-16s rtt=%8.3f ms  meta=%s", s.target, s.rtt_ms,
                        s.meta or ""))
  else
    print(ip, "ERROR", tostring(s))
  end
end
return results
