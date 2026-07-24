# Running cpe_agent as a persistent daemon → edgehost → ClickHouse

## Architecture (two binaries)

```text
┌──────────────────────────────┐     HTTP(S) NDJSON
│  cpe_agent  (daemon)         │ ──────────────────────────────► edgehost
│  - sample timer (ping/…)     │   POST /api/v1/telemetry/events
│  - NFLOG TCP stats           │                                        │
│  - emit.mode=http|https      │                                        ▼
│  - UDS control socket        │                                 ClickHouse
└────────────▲─────────────────┘                              (typed tables)
             │ Unix domain socket
             │ /var/run/netforensics/cpe_agent.sock
┌────────────┴─────────────────┐
│  cpe_ctl  (human / AI)       │
│  - Lua REPL                  │
│  - status / tcp_stats / …    │
└──────────────────────────────┘
```

| Binary | Role |
|--------|------|
| **`cpe_agent`** | Long-running **daemon**: collect stats, spool/POST to edgehost, listen on UDS |
| **`cpe_ctl`** | Interactive **client**: Lua + one-shot queries over the UDS |

**Important:** the CPE never opens a production ClickHouse or Postgres client.
It talks only to **edgehost proxies** (telemetry, optional OpenAI URL in config).
edgehost dual-writes telemetry into ClickHouse (and other backends).

---

## 1. Persistent collection → edgehost → ClickHouse

### 1a. edgehost side

```yaml
# edgehost config fragment
plugins:
  clickhouse:
    enabled: true
    host: 127.0.0.1
    port: 8123
    database: edgehost
    events_table: edgehost.e7_netconf_events
    tcp_stats_table: edgehost.cpe_tcp_stats
    telemetry_proxy: true
    telemetry_user: cpe_ingest
    telemetry_password: "change-me"
```

```bash
clickhouse-client --multiquery < edgehost/sql/clickhouse/001_e7_netconf_events.sql
clickhouse-client --multiquery < edgehost/sql/clickhouse/002_cpe_tcp_stats.sql
# start edgehost with the YAML above
```

### 1b. CPE agent YAML (field)

`/etc/cpe_agent/cpe_agent.yaml`:

```yaml
router_id: cpe-42

emit:
  mode: http          # or https with mbedTLS

egress:
  url: "http://edgehost.example:18080/api/v1/telemetry/events"
  username: cpe_ingest
  password: "change-me"

demo:
  enabled: false      # live ICMP
  target: "1.1.1.1"
  interval_ms: 60000  # sample every 60s
  timeout_ms: 1000

tcp_stats:
  enabled: true
  nflog_group: 5
  emit_interval_ms: 30000
  prefix_len: 24

ipc:
  socket: /var/run/netforensics/cpe_agent.sock

# Optional: document edgehost OpenAI proxy for operators / future tools
# proxies:
#   openai_url: "http://edgehost.example:18080/api/v1/openai/..."
```

### 1c. Host NFLOG rules (for TCP stats)

```bash
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags RST RST \
  -j NFLOG --nflog-group 5 --nflog-size 60
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags FIN FIN \
  -j NFLOG --nflog-group 5 --nflog-size 60
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags SYN SYN \
  -m conntrack --ctstate NEW -j NFLOG --nflog-group 5 --nflog-size 60
```

### 1d. Run the daemon

**Foreground (lab):**

```bash
mkdir -p /var/run/netforensics /var/spool/netforensics
./build/cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id cpe-42
# stderr: cpe_agent: control socket /var/run/netforensics/cpe_agent.sock
```

**systemd:**

```bash
# deploy/cpe_agent.service — install and enable
sudo systemctl enable --now cpe_agent
sudo systemctl status cpe_agent
# SIGHUP reloads YAML
sudo systemctl reload cpe_agent   # if configured; else kill -HUP
```

**OpenWrt procd:**

```bash
/etc/init.d/cpe-agent start
/etc/init.d/cpe-agent reload   # HUP
```

Capabilities: `CAP_NET_RAW` (live ICMP), `CAP_NET_ADMIN` (NFLOG). In LXC use
host netns (ADR-009).

Without `--once` / `--lua`, the process **runs until SIGTERM** and keeps sampling
+ flushing to edgehost.

### 1e. Verify pipeline

```bash
# On CPE
cpe_ctl status
cpe_ctl tcp_stats

# On edgehost / CH
clickhouse-client -q "
  SELECT event_type, count() FROM edgehost.e7_netconf_events
  WHERE source='cpe_agent' AND event_time > now() - INTERVAL 1 HOUR
  GROUP BY event_type"

clickhouse-client -q "
  SELECT remote_ip, sum(rst), avg(loss_hint)
  FROM edgehost.cpe_tcp_stats
  WHERE scope='remote' AND ts > now() - INTERVAL 1 HOUR
  GROUP BY remote_ip ORDER BY avg(loss_hint) DESC LIMIT 10"
```

---

## 2. Human front-end: `cpe_ctl`

```bash
# One-shot
cpe_ctl status
cpe_ctl tcp_stats
cpe_ctl tcp_by_ip 45.57.10.1
cpe_ctl --socket /var/run/netforensics/cpe_agent.sock spool

# Interactive Lua (queries daemon; no local collection)
cpe_ctl --lua
cpe_ctl> cpe.help()
cpe_ctl> cpe.status()
cpe_ctl> s = cpe.tcp_stats(); print(s.syn, s.rst, s.loss_hint)
cpe_ctl> cpe.tcp_by_prefix()
```

Protocol: newline-delimited JSON on the UDS (`docs` / `include/cpe_ipc.h`).

```bash
# Manual
echo '{"op":"tcp_stats"}' | socat - UNIX-CONNECT:/var/run/netforensics/cpe_agent.sock
```

---

## 3. Proxy model (what “interfaces with ClickHouse / Postgres / OpenAI” means)

| Backend | On CPE daemon | How |
|---------|---------------|-----|
| ClickHouse | **No direct client** | `emit.mode=http` → edgehost telemetry → CH |
| Postgres | **No direct client** | edgehost owns PG (ONT status, CA, …) |
| OpenAI | Optional URL in config | edgehost OpenAI proxy; not a CPE OpenAI SDK |

Config keys:

- `egress.url` — telemetry (required for http/https emit)
- `proxies.openai_url` — recorded in `cpe_ctl status` for operators
- `proxies.postgres_url` — reserved / status only

---

## 4. CLI cheat sheet

```bash
# Daemon
cpe_agent --config /etc/cpe_agent/cpe_agent.yaml --router-id cpe-42
cpe_agent --config … --socket /tmp/cpe.sock
cpe_agent --config … --no-ipc

# Client
cpe_ctl status
cpe_ctl --lua
cpe_ctl --lua-eval "print(cpe.tcp_stats()._json)"
```

Embedded `cpe_agent --lua` still exists for offline/local tools, but the
**supported interactive path** against a running collector is **`cpe_ctl`**.
