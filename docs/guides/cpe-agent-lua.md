# CPE agent Lua environment

`cpe_agent` can embed **Lua 5.4** for interactive exploration and as the
script surface for a future **AI harness / agent** that runs network tools.

Build flag: `-DCPE_AGENT_WITH_LUA=ON` (default when
`third_party/lua-5.4.7` and `third_party/linenoise` are present).

---

## Why Lua here

| Role | How Lua fits |
|------|----------------|
| **Human REPL** | Line-edited prompt (`--lua` / `--repl`) to call tools by hand |
| **Tool scripts** | Small `.lua` files that encapsulate probes / analysis |
| **AI harness** | Model selects a tool → harness runs Lua → returns structured tables / NDJSON |
| **Policy** | Optional later: gate which tools an AI may call (see libharness policy) |

The C agent remains the privileged surface (ICMP sockets, spool, config).
Lua never opens sockets directly; it only calls the `cpe.*` bindings.

**Synthetic demo probes are not on the Lua surface.** Demo ticks
(`cpe_agent_demo_ping_tick`, `cpe_agent_demo_arping`, `cpe_agent_demo_wifi_dump`)
remain C APIs for fuzzing, dialectic tests, and CLI `--demo` / `--once`.
Lua tools always take live network actions.

---

## Starting modes

```bash
# Interactive REPL (linenoise: up-arrow history, Ctrl-D / quit / exit)
./cpe_agent --lua
./cpe_agent --repl --config test.yaml --router-id lab-1
./cpe_agent --lua --history /tmp/cpe_hist

# One-shot eval (live ICMP; needs CAP_NET_RAW / ping capability)
./cpe_agent --lua-eval "print(cpe.live_ping('127.0.0.1').rtt_ms)"

# Run a tool script then exit
./cpe_agent --lua-file tools/ping_sweep.lua --config test.yaml

# Combine: load script, then drop into REPL
./cpe_agent --lua-file tools/lib.lua --lua
```

Without `--lua` / `--lua-eval` / `--lua-file`, behaviour is unchanged
(timer loop or `--once` / `--demo`). Process-level demo remains available
via YAML `demo.enabled` / CLI for unprivileged smoke; it is not a Lua tool.

History defaults to `~/.cpe_agent_history`, or `/tmp/cpe_agent_history` if
`HOME` is unset.

---

## The `cpe` table (exposed tools)

| Function | Returns | Notes |
|----------|---------|--------|
| `cpe.help()` | — | Print API summary |
| `cpe.config()` | table | `router_id`, `target`, `demo` (read-only process flag), `interval_ms`, … |
| `cpe.set_target(ip)` | bool | Probe destination (ping + arping) |
| `cpe.set_router_id(id)` | bool | Device id in NDJSON |
| `cpe.set_interval(ms)` | bool | Sample period for timer mode |
| `cpe.set_iface(name)` | bool | Default L2 interface for arping |
| `cpe.set_wifi_if(name)` | bool | Default Wi‑Fi iface for nl80211 |
| `cpe.live_ping([ip])` | sample table | Live ICMP; optional target override |
| `cpe.arping([ip],[iface])` | sample table | Live ARP (AF_PACKET / CAP_NET_RAW) |
| `cpe.traceroute([ip],[max_ttl],[timeout_ms])` | path table | Live hop path (UDP+IP_RECVERR or ICMP) |
| `cpe.mtr([ip],[probes],[max_ttl],[timeout_ms])` | path table | Multi-probe per hop (default 3) |
| `cpe.last_trace()` | path table or nil | Last traceroute/mtr result |
| `cpe.wifi_list()` | string array | Wireless-looking interfaces |
| `cpe.wifi_state([iface])` | table | operstate, up, running, mac, mtu |
| `cpe.wifi_stats([iface],[emit])` | snapshot | iface + stations (nl80211) |
| `cpe.last_wifi()` | snapshot or nil | Last Wi‑Fi dump |
| `cpe.sample()` | sample table | One **live** ICMP tick (never synthetic) |
| `cpe.last_sample()` | sample or nil | In-memory last result |
| `cpe.latency()` | string | JSON for `get_local_latency` |
| `cpe.ndjson()` | string | Last sample as `cpe_perf` line |
| `cpe.emit()` | int | Flush spool (`stdout` / file / https) |
| `cpe.spool_depth()` / `cpe.spool_drops()` | int | Spool stats |
| `cpe.reload([path])` | bool | Re-read YAML |
| `cpe.dofile(path)` | — | Run another script in this state |
| `cpe.tcp_open([group])` | bool[, err] | Enable + bind NFLOG group (default 5) |
| `cpe.tcp_poll([max])` | int | Drain NFLOG; return packets processed |
| `cpe.tcp_stats()` | table | Summary SYN/FIN/RST/bytes/`loss_hint` |
| `cpe.tcp_by_ip([ip])` | table or array | One remote or all remotes |
| `cpe.tcp_by_prefix([cidr])` | table or array | One prefix or all (CDN rollups) |
| `cpe.tcp_emit([top_n])` | int | Push `cpe_tcp` NDJSON to spool |
| `cpe.tcp_reset()` | bool | Clear TCP counters |

Not exposed (C / CLI only): `set_demo`, `demo_ping`, `demo_arping`,
`demo_wifi_stats`.

### Sample table shape

```lua
{
  probe  = "ping",
  target = "1.1.1.1",
  rtt_ms = 14.567,   -- sub-ms on live probes
  loss   = 0.0,
  ts     = "2026-07-22T02:29:25.434Z",
  meta   = "{\"replies\":1,\"timeouts\":0,\"demo\":false,\"raw\":true}",
}
```

### Traceroute / mtr result shape

```lua
{
  target = "1.1.1.1",
  ts = "2026-07-22T12:00:00.000Z",
  method = "udp",          -- or "icmp"
  max_ttl = 30,
  probes = 1,              -- probes per hop (mtr > 1)
  hop_count = 8,
  reached = true,
  dest_rtt_ms = 12.345,
  hops = {
    {
      hop = 1,
      addr = "192.168.1.1",
      sent = 1, replies = 1, timeouts = 0,
      rtt_ms = 1.2, avg_rtt_ms = 1.2, min_rtt_ms = 1.2, max_rtt_ms = 1.2,
      loss = 0.0,
      reached_dest = false,
    },
    -- ...
  },
}
```

Also emits summary `cpe_perf` with `probe=traceroute` or `probe=mtr`, plus
optional per-hop lines (`probe=traceroute_hop` / `mtr_hop`).

---

## REPL examples

```text
cpe> cpe.help()
cpe> cpe.config()
cpe> cpe.live_ping("192.168.1.1")
{probe=ping, target=192.168.1.1, rtt_ms=1.234, loss=0, ...}

cpe> cpe.set_iface("br-lan")
cpe> cpe.arping("192.168.1.1")          -- live; needs CAP_NET_RAW
cpe> cpe.arping("192.168.1.1", "eth0")  -- explicit iface
-- meta includes mac + if, e.g. {"mac":"aa:bb:..","if":"br-lan",...}

cpe> tr = cpe.traceroute("1.1.1.1", 20, 800)
cpe> print(tr.reached, tr.hop_count, tr.method)
cpe> for _,h in ipairs(tr.hops) do
...   print(h.hop, h.addr ~= "" and h.addr or "*", h.rtt_ms, h.loss)
... end
cpe> m = cpe.mtr("1.1.1.1", 5, 15)     -- 5 probes/hop, max 15 hops
cpe> cpe.last_trace()

cpe> cpe.wifi_list()
cpe> cpe.wifi_state("wlan0")
cpe> w = cpe.wifi_stats("wlan0", true)  -- live nl80211; emit cpe_wifi NDJSON
cpe> for _,sta in ipairs(w.stations) do
...   print(sta.mac, sta.rssi, sta.mcs, sta.tx_bytes)
... end

cpe> cpe.set_target("8.8.8.8")
cpe> s = cpe.live_ping()
cpe> print(s.rtt_ms, s.loss)
cpe> print(cpe.ndjson())

cpe> for _,ip in ipairs{"192.168.1.1","1.1.1.1","8.8.8.8"} do
...   local r = cpe.live_ping(ip)
...   print(ip, r and r.rtt_ms or "fail")
... end

-- TCP NFLOG stats (needs iptables NFLOG group + CAP_NET_ADMIN)
cpe> cpe.tcp_open(5)
cpe> cpe.tcp_poll(128)
cpe> s = cpe.tcp_stats(); print(s.syn, s.rst, s.loss_hint)
cpe> r = cpe.tcp_by_ip("45.57.10.1"); print(r and r.loss_hint)
cpe> for _,p in ipairs(cpe.tcp_by_prefix() or {}) do
...   print(p.prefix, p.bytes, p.loss_hint)
... end
cpe> cpe.tcp_emit(10); cpe.emit()

cpe> quit
```

Expressions are auto-prefixed with `return` when possible, so bare
`cpe.config()` prints the table.

---

## Writing tool scripts (for humans or AI)

### Minimal tool: single probe

`tools/ping_once.lua`:

```lua
-- Usage: cpe_agent --lua-file tools/ping_once.lua
-- Optional env-style args via globals set by harness later.

local target = target or "1.1.1.1"
local s = cpe.live_ping(target)
if not s then
  error("no sample")
end
print(cpe.ndjson())
return s
```

### Sweep tool (exploration)

`tools/ping_sweep.lua`:

```lua
local targets = targets or {
  "192.168.1.1",
  "1.1.1.1",
  "8.8.8.8",
}

local results = {}
for _, ip in ipairs(targets) do
  local ok, s = pcall(cpe.live_ping, ip)
  if ok and s then
    results[#results + 1] = s
    print(string.format("%-16s  rtt=%.3f ms  loss=%.4f",
                        s.target, s.rtt_ms, s.loss))
  else
    print(ip, "ERROR", s)
  end
end
return results
```

```bash
./cpe_agent --config live.yaml --lua-file tools/ping_sweep.lua
```

### Analysis sketch

```lua
-- Compare last two live RTTs (caller runs live_ping twice first)
local function classify(s)
  if not s then return "missing" end
  if s.loss >= 1.0 then return "timeout" end
  if s.rtt_ms < 5 then return "excellent" end
  if s.rtt_ms < 30 then return "ok" end
  if s.rtt_ms < 100 then return "degraded" end
  return "poor"
end

local s = cpe.last_sample()
return { class = classify(s), sample = s, ndjson = cpe.ndjson() }
```

---

## AI harness integration (planned primary use)

The long-term host is an **embedded AI agent** (libharness / similar) that:

1. Exposes tools to the model as OpenAI-style function schemas  
2. When the model calls a tool, the host runs a **Lua script** (or `cpe.*` call)  
3. Returns a **JSON-serializable table** (or NDJSON string) as the tool result  

### Suggested contract

```text
Model  →  tool_call{ name="live_ping", arguments={target="1.1.1.1"} }
Host   →  Lua:  return cpe.live_ping(arguments.target)
Host   →  tool_result JSON from the sample table
Model  →  continues analysis / next tool
```

### Tool registration sketch (host side, C or Lua)

```lua
-- Registered by harness bootstrap (not shipped as production AI yet)
tools = {
  {
    name = "live_ping",
    description = "ICMP echo from this CPE; returns rtt_ms, loss, target",
    parameters = {
      type = "object",
      properties = { target = { type = "string" } },
      required = { "target" },
    },
    -- implementation: Lua chunk or path
    script = "return cpe.live_ping(target)",
  },
  {
    name = "traceroute",
    description = "Hop-by-hop path to target; returns hops[], reached, method",
    parameters = {
      type = "object",
      properties = {
        target = { type = "string" },
        max_ttl = { type = "integer" },
      },
      required = { "target" },
    },
    script = "return cpe.traceroute(target, max_ttl)",
  },
  {
    name = "mtr",
    description = "Multi-probe path stats per hop (loss/avg/min/max RTT)",
    parameters = {
      type = "object",
      properties = {
        target = { type = "string" },
        probes = { type = "integer" },
        max_ttl = { type = "integer" },
      },
      required = { "target" },
    },
    script = "return cpe.mtr(target, probes, max_ttl)",
  },
  {
    name = "get_local_latency",
    description = "Last sample as JSON string",
    script = "return cpe.latency()",
  },
  {
    name = "set_probe_target",
    description = "Set default probe destination",
    parameters = { properties = { target = { type = "string" } } },
    script = "return cpe.set_target(target)",
  },
}
```

### Safety notes for AI-driven tools

- Prefer **allow-listed** scripts / `cpe.*` only (no `os.execute` in production policy).  
- Live ICMP may need CAP_NET_RAW / `ping_group_range`; do not register synthetic demo tools for the model.  
- Bound target strings (already enforced in C: max length).  
- Rate-limit tool calls on CPE flash/CPU budgets.  
- Emit path should stay **NDJSON → Vector**, not direct DB from device.

### Relationship to libharness

`libharness` already has optional Lua policy bindings (`harness_lua_init`).
The `cpe.*` table is the **device tool surface**; harness remains the
**session / soul / tool-router**. Future work can call `cpe_lua_state()` and
register additional tables, or bridge `get_local_latency` into both.

---

## Architecture

```text
┌─────────────────────────────────────────────┐
│  cpe_agent process                          │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │ linenoise   │───▶│ Lua 5.4 VM          │ │
│  │ REPL / AI   │    │  global cpe.*       │ │
│  └─────────────┘    └──────────┬──────────┘ │
│                                │            │
│                     ┌──────────▼──────────┐ │
│                     │ cpe_agent_lib (C)   │ │
│                     │  live ping/arping   │ │
│                     │  spool / emit       │ │
│                     │  config / reload    │ │
│                     │  demo* = C tests    │ │
│                     └─────────────────────┘ │
└─────────────────────────────────────────────┘
         │ cpe_perf NDJSON
         ▼
   stdout / spool → Vector → ClickHouse
```

---

## Build / size notes

| Item | Source |
|------|--------|
| Lua 5.4.7 | `third_party/lua-5.4.7/` (static `lua_embed`) |
| linenoise | `third_party/linenoise/` (static) |
| Disable | `-DCPE_AGENT_WITH_LUA=OFF` |

Field static `ipq807x_32` builds can include Lua; binary grows on the order of
a few hundred KB. Omit Lua only if flash is extremely tight.

```bash
cmake -B build -S . -DCPE_AGENT_WITH_LUA=ON
cmake --build build --target cpe_agent test_cpe_agent_lua
./build/cpe_agent --lua-eval "print(cpe.live_ping('127.0.0.1').rtt_ms)"
./build/test_cpe_agent_lua
```

---

## Non-goals (for now)

- Full sandboxed multi-user multi-tenant Lua isolation  
- Shipping a complete on-device LLM weights  
- Replacing Vector/ClickHouse with Lua-side storage  
- Arbitrary shell from Lua in production policy  
- Exposing synthetic demo probes to Lua / AI tools  

The REPL and `cpe.*` tools are the foundation: humans validate tools today;
the AI harness orchestrates the same scripts tomorrow.
