# CPE flow bandwidth accounting (conntrack)

Per-stream upload/download bytes from the CPE conntrack table, emitted as
`type=cpe_flow` NDJSON to edgehost → ClickHouse `edgehost.cpe_flows`.

## Requirements

1. **Accounting sysctl** (otherwise counters are zero / missing):

```bash
sysctl -w net.netfilter.nf_conntrack_acct=1
# persist: echo net.netfilter.nf_conntrack_acct=1 >> /etc/sysctl.conf
```

2. **CAP_NET_ADMIN** (or root) for `NETLINK_NETFILTER` conntrack multicast + dump.

3. edgehost telemetry proxy (lab: `:18082`) and CH password configured.

## Config

```yaml
flow_acct:
  enabled: true
  poll_interval_ms: 200      # drain netlink
  dump_interval_ms: 200      # active table dump
  sample_emit_ms: 2000       # top-N live samples
  sample_top_n: 32
  max_flows: 1024
  emit_destroy: true         # final account on teardown
  emit_new: false
  join_update: true
```

Field profile: `config/cpe_agent.field.yaml`.

## Signals

| Event | Meaning |
|-------|---------|
| `event=destroy` | Connection teardown; final `bytes_up` / `bytes_down` |
| `event=sample` | Top-N by rate every `sample_emit_ms` |
| `event=new` | Optional (noisy); identity also on `cpe_nat` |

**Orientation (CPE WAN view):**

- `bytes_up` / `orig_bytes` — LAN → internet (upload)
- `bytes_down` / `reply_bytes` — internet → LAN (download)

## On-box ops (live table on the CPE)

Requires running `cpe_agent` with `flow_acct.enabled: true` and the control
socket.

```bash
cpe_ctl flow_stats          # counters / open_ok
cpe_ctl flow_list           # live conntrack table snapshot
cpe_ctl flow_list 64        # optional limit
cpe_ctl flow_tick           # force one poll/dump pass
```

## Historical flows (ClickHouse)

`cpe_ctl` can query **ClickHouse HTTP** for stored `cpe_flow` rows. Use this on
an ops/lab host that can reach CH (typically `127.0.0.1:8123` on edgehost).
Field CPEs do not open ClickHouse; they only POST NDJSON to the edgehost proxy.

```bash
# Table output (default)
cpe_ctl flow_list --history --ch-password passw0rd
cpe_ctl flows --history --router-id lab-cpe-1 --limit 20 --ch-password passw0rd

# Env instead of flags
export CPE_CH_URL=http://127.0.0.1:8123
export CPE_CH_USER=default
export CPE_CH_PASSWORD=passw0rd
cpe_ctl flow_list --history --router-id cpe-42

# Raw JSONEachRow
cpe_ctl flow_list --history --raw --limit 5
```

| Flag / env | Meaning |
|------------|---------|
| `--history` | Query ClickHouse instead of the daemon |
| `--ch-url` / `CPE_CH_URL` | Base URL (default `http://127.0.0.1:8123`) |
| `--ch-user` / `CPE_CH_USER` | User (default `default`) |
| `--ch-password` / `CPE_CH_PASSWORD` | Password |
| `--ch-table` | Table (default `edgehost.cpe_flows`) |
| `--router-id` | Filter by CPE id |
| `--limit N` | Max rows (default 50) |
| `--raw` | Print JSONEachRow instead of a table |

Alias: `cpe_ctl flow_history …` is the same as `flow_list --history …`.

## Edgehost UI

- SPA: **http://127.0.0.1:18080/flows/** (lab login)
- API: `GET /api/v1/flows?router_id=…&limit=100` (employee session)

## Schema

```bash
clickhouse-client --multiquery < edgehost/sql/clickhouse/003_cpe_flows.sql
```

## Future

- Soft-join defects from `cpe_tcp` (loss_hint / RST) into samples
- Core RIB/BMP → fill `path_id` for path-impact forensics
