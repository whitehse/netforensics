# ARCHITECTURE.md — netforensics

## Goal

Retroactive root-cause analysis: reconstruct a flow path from LAN/Wi-Fi client
through CPE NAT, core IPFIX hops, and BGP egress at a historical millisecond.
Plus **CPE performance samples** for latency/loss product surfaces (Track 2).

## System diagram

```
[OpenWrt CPE x20k]                    [Core routers x25]
  forensicsd (conntrack/wifi) ──┐       IPFIX UDP/TCP ──┐
  cpe_agent  (perf NDJSON)   ───┼──▶ Vector/C gateway ──▶ ClickHouse
                                │       BMP/BGP ────────┘
                                └── NDJSON lines
```

## Module boundaries

```
cpe/
  forensicsd.c          — --demo | --netlink (ADR-002; do not break)
  sysctl/99-forensics.conf
agent/                  — Track 2 product CPE agent
  main.c                — CLI + config load
  agent_loop.c          — libuv timers/signals
  agent_core.c          — apply_config, spool, demo ping
  config_yaml.c         — libyaml load
  host_alloc.c          — malloc gate for agent buffers
  perf_sample.c         — cpe_perf NDJSON formatter
include/
  netforensics.h        — correlation / IPFIX / nfct glue
  cpe_agent.h           — agent public API
  cpe_agent_config.h
  cpe_host_alloc.h
src/
  nfct_netlink.c        — AF_NETLINK NETLINK_NETFILTER membership + recv
  ipfix_ingest.c        — libipfix collector glue
  bmp_ingest.c          — libbmp events → nf_bmp_obs_t / NDJSON
  flow_correlate.c      — pure helpers joining tuples (no I/O)
sql/
  001_schema.sql
  002_dictionary.sql
  003_cpe_perf_samples.sql   — N-A05
  queries/
vector/
  vector.yaml           — includes cpe_perf → cpe_perf_samples
config/
  forensicsd.example.yaml
  cpe_agent.example.yaml
deploy/
  forensicsd.service
tests/
  test_correlate.c
  test_host_pipeline.c
  test_cpe_agent.c
```

## Library mapping

| Design concern | Library API |
|----------------|-------------|
| IPFIX templates + 5-tuple | `ipfix_feed_*`, `ipfix_record_flow_key` |
| Conntrack NEW/DESTROY | `nfct_feed_input`, `nfct_event_forensics_tuple` |
| Wi-Fi RSSI/MCS/retries | `nl80211_parse_feed_input` |
| BMP | **libbmp** `bmp_feed_*` + app `nf_bmp_collect*` |
| Ping / perf demo | libnetdiag `ping_*` + agent spool |
| Config | libyaml |
| Agent loop | libuv (class B) |
| Agent buffers | `cpe_host_alloc` |

## CPE binaries

| Binary | Mode | Output |
|--------|------|--------|
| **forensicsd** | `--demo` / `--netlink` | `cpe_nat`, `cpe_wifi` NDJSON |
| **cpe_agent** | `--demo` / `--once` / libuv timer | `cpe_perf` NDJSON |

Agent and forensicsd may co-exist; share Vector fan-in. No production ClickHouse
client on CPE (ADR-002 / N-A05).

## Agent control plane (Track 2)

1. Load YAML → `cpe_agent_config_t` (defaults if no file).
2. `cpe_agent_apply_config` → `CONFIG_APPLIED` / `CONFIG_REJECTED`.
3. libuv timer → `cpe_agent_demo_ping_tick` (synthetic ICMP into libnetdiag).
4. Format `cpe_perf` → bounded spool → flush stdout (or spool file later).
5. SIGHUP sets reload flag (`cpe_agent_hup_take`).

## Correlation keys

- **CPE NAT**: `(timestamp, wan_src_ip, wan_src_port)` primary for reverse path
- **Core IPFIX**: `(timestamp, src_ip, dst_ip, src_port, dst_port, protocol)`
- **BGP**: `(router_id, prefix, timestamp)` with VersionedCollapsingMergeTree
- **Wi-Fi**: `(timestamp, client_mac)` / LAN IP join
- **Perf**: `(router_id, probe, ts)` in `cpe_perf_samples`

## Deliberate absences

- ClickHouse not required for unit/host tests
- Full live ICMP raw socket in agent v1 (demo uses synthetic feed)
- libharness tools (P2.6)
- OpenWrt package for agent (P2.9)
