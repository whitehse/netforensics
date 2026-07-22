-- Wi-Fi state + station report.
--   ./cpe_agent --lua-file examples/lua/wifi_report.lua
-- Live dump needs nl80211 (often CAP_NET_ADMIN). Force demo:
--   demo = true

local use_demo = demo
if use_demo == nil then
  use_demo = false
end

print("ifaces:", table.concat(cpe.wifi_list(), ", "))

local w
if use_demo then
  w = cpe.demo_wifi_stats(true)
else
  local ok, res = pcall(function()
    return cpe.wifi_stats(iface, true)
  end)
  if ok then
    w = res
  else
    print("live wifi_stats failed, falling back to demo:", res)
    w = cpe.demo_wifi_stats(true)
  end
end

local i = w.iface
print(string.format("iface=%s up=%s running=%s operstate=%s mac=%s stations=%d valid=%s",
                    i.ifname, tostring(i.up), tostring(i.running), i.operstate,
                    i.mac, w.station_count, tostring(w.stations_valid)))
if w.err then
  print("note:", w.err)
end

for _, sta in ipairs(w.stations) do
  print(string.format("  %s  rssi=%d  snr=%d  mcs=%d  rx=%u  tx=%u  retries=%u",
                      sta.mac, sta.rssi, sta.snr, sta.mcs, sta.rx_bytes,
                      sta.tx_bytes, sta.tx_retries))
end

return w
