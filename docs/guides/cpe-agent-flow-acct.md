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

## On-box ops

```bash
cpe_ctl flow_stats
cpe_ctl flow_list
cpe_ctl flow_tick
```

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
