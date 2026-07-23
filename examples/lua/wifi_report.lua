-- Wi-Fi state + station report (live nl80211).
--   ./cpe_agent --lua-file examples/lua/wifi_report.lua
-- Live dump needs nl80211 (often CAP_NET_ADMIN). Optional:
--   iface = "wlan0"

print("ifaces:", table.concat(cpe.wifi_list(), ", "))

local ok, w = pcall(function()
  return cpe.wifi_stats(iface, true)
end)
if not ok then
  error("wifi_stats failed: " .. tostring(w))
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
