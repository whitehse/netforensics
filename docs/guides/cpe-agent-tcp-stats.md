# CPE agent TCP stats (NFLOG)

Analyze TCP control-plane health from **NFLOG** captures of SYN (new/retrans),
FIN, and RST on the CPE (Calix u6.3 / OpenWrt). Emits `type=cpe_tcp` NDJSON to
Vector or edgehost → ClickHouse. Lua exposes query surfaces for remotes and
remote-network prefixes (CDN rollups). QUIC analysis is planned to share the
same query patterns later.

## Host iptables (insert in reverse order)

```bash
# 3. RST (connection resets / network artifacts)
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags RST RST \
  -j NFLOG --nflog-group 5 --nflog-size 60
# 2. FIN (connection closures)
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags FIN FIN \
  -j NFLOG --nflog-group 5 --nflog-size 60
# 1. SYN NEW (new connections + SYN retransmissions)
iptables -I FORWARD 1 -p tcp -m tcp --tcp-flags SYN SYN \
  -m conntrack --ctstate NEW \
  -j NFLOG --nflog-group 5 --nflog-size 60
```

`--nflog-size 60` is enough for IPv4/TCP headers. Group **5** is the default;
change both iptables and agent config together.

Requires **CAP_NET_ADMIN** (and host netns if containerized — ADR-009).

## Agent config

Field profile: `config/cpe_agent.field.yaml` (NFLOG **5** → CH proxy
`http://174.128.129.0:18082/api/v1/telemetry/events`).

```yaml
emit:
  mode: http
egress:
  url: "http://174.128.129.0:18082/api/v1/telemetry/events"
  username: cpe_ingest
  password: "change-me"

tcp_stats:
  enabled: true
  nflog_group: 5            # nflog:5
  nflog_size: 60
  emit_interval_ms: 10000   # summary + top-N emit period
  emit_top_n: 20
  prefix_len: 24            # use 16 for larger CDN blocks

ipc:
  socket: /var/run/netforensics/cpe_agent.sock
```

## What is measured

| Signal | Source | Use |
|--------|--------|-----|
| `syn` / `syn_retrans` | SYN (+ retrans of same 4-tuple) | Setup pressure / loss |
| `fin` | FIN | Clean closures |
| `rst` | RST | Aborts / middlebox artifacts |
| `loss_hint` | RST + retrans / control events | Ranking bad remotes (not true loss%) |
| `bytes` / `pkts` | IP total length of **logged** packets | Control-plane volume only |

**Bandwidth caveat:** these rules do **not** sample data packets. `bytes` is
control-plane size only. Full stream bandwidth needs additional NFLOG rules,
conntrack accounting, or IPFIX. Prefix rollups still rank which networks see
the most control-plane activity (useful for Netflix/CDN investigation).

## NDJSON (`type=cpe_tcp`)

```json
{"type":"cpe_tcp","ts":"…","router_id":"cpe-1","scope":"summary","syn":10,"fin":8,"rst":2,"syn_retrans":1,"pkts":20,"bytes":800,"remotes":5,"prefixes":3,"loss_hint":0.12,"prefix_len":24,"nflog_group":5,…}
{"type":"cpe_tcp","scope":"remote","remote_ip":"45.57.10.1","syn":3,"rst":1,"syn_retrans":1,"loss_hint":0.25,…}
{"type":"cpe_tcp","scope":"prefix","prefix":"45.57.0.0/16","bytes":1200,"loss_hint":0.1,…}
```

## Lua (on-demand retrieval)

**Against the running daemon** (`cpe_ctl` — preferred for operators/AI):

```bash
cpe_ctl tcp_stats
cpe_ctl --lua-eval "print(cpe.tcp_stats().loss_hint)"
cpe_ctl --lua-eval "for _,p in ipairs(cpe.tcp_by_prefix()) do print(p.prefix,p.bytes) end"
```

**Embedded on `cpe_agent`** (same `cpe.*` API):

```lua
cpe.tcp_open(5)
cpe.tcp_poll(128)
print(cpe.tcp_stats().loss_hint)
print(cpe.tcp_by_ip("1.1.1.1"))
for _,p in ipairs(cpe.tcp_by_prefix()) do print(p.prefix, p.bytes) end
cpe.tcp_emit(10); cpe.emit()   -- push cpe_tcp NDJSON + flush to CH proxy
```

Example script: `examples/lua/tcp_stats_report.lua`.

## Storage / retrieval

| Path | Table |
|------|--------|
| Vector | `forensics.cpe_tcp_stats` (`sql/006_cpe_tcp_stats.sql`) |
| edgehost | dual-write `edgehost.cpe_tcp_stats` + wrap in `e7_netconf_events` |

SQL helpers:

- `sql/queries/tcp_remote_loss.sql` — loss ranking by remote IP
- `sql/queries/tcp_prefix_bandwidth.sql` — prefix / CDN view

```bash
clickhouse-client --multiquery < sql/006_cpe_tcp_stats.sql
# edgehost:
clickhouse-client --multiquery < ../edgehost/sql/clickhouse/002_cpe_tcp_stats.sql
```

## Future: QUIC

QUIC will reuse the same **remote / prefix / loss_hint** query model. Planned
as a sibling `type=cpe_quic` (or shared stream stats table) once UDP/QUIC
NFLOG or DPI hooks exist on the CPE.