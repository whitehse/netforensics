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
agent/                  — Track 2 + field path CPE agent
  main.c                — CLI + config load
  agent_loop.c          — libuv timers/signals + HUP reload
  agent_core.c          — apply_config, spool, emit_flush, sample_tick
  live_ping.c           — host ICMP (F4)
  tls_egress.c          — optional mbedTLS POST (F5)
  spool_util.c          — shared spool dirs (F6)
  config_yaml.c         — libyaml load
  host_alloc.c          — malloc gate for agent buffers
  perf_sample.c         — cpe_perf NDJSON formatter
  tcp_stats.c           — NFLOG TCP SYN/FIN/RST aggregate + cpe_tcp NDJSON
include/
  netforensics.h        — correlation / IPFIX / nfct glue
  cpe_agent.h           — agent public API
  cpe_agent_config.h
  cpe_agent_tls.h
  cpe_spool.h
  cpe_host_alloc.h
src/
  nfct_netlink.c        — AF_NETLINK NETLINK_NETFILTER membership + recv
  nflog_netlink.c       — NFLOG bind/recv/walk (TCP control-plane)
  ipfix_ingest.c        — libipfix collector glue
  bmp_ingest.c          — libbmp events → nf_bmp_obs_t / NDJSON
  flow_correlate.c      — pure helpers joining tuples (no I/O)
sql/
  001_schema.sql
  002_dictionary.sql
  003_cpe_perf_samples.sql   — N-A05
  006_cpe_tcp_stats.sql      — TCP NFLOG SYN/FIN/RST
  queries/                   — includes tcp_remote_loss / tcp_prefix_bandwidth
vector/
  vector.yaml           — cpe_perf + cpe_tcp → ClickHouse
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
| TCP NFLOG stats | `nflog_netlink_*` + `cpe_agent_tcp_*` / Lua `cpe.tcp_*` |
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

## Agent control plane (Track 2 + field path)

1. Load YAML → `cpe_agent_config_t` via `cpe_agent_reload_config` (defaults if no file).
2. `cpe_agent_apply_config` → `CONFIG_APPLIED` / `CONFIG_REJECTED`.
3. libuv timer → `cpe_agent_sample_tick` (demo synthetic **or** live ICMP F4).
4. Format `cpe_perf` → bounded ring → `cpe_agent_emit_flush`
   (`stdout` | `spool` file | optional `https` mTLS F5).
5. SIGHUP → re-read YAML path + re-apply CLI `router_id` override; re-arm timer
   if `interval_ms` changed (ADR-007).
6. Shared spool dir `/var/spool/netforensics` with forensicsd (F6); ring hard cap 1024.

## Correlation keys

- **CPE NAT**: `(timestamp, wan_src_ip, wan_src_port)` primary for reverse path
- **Core IPFIX**: `(timestamp, src_ip, dst_ip, src_port, dst_port, protocol)`
- **BGP**: `(router_id, prefix, timestamp)` with VersionedCollapsingMergeTree
- **Wi-Fi**: `(timestamp, client_mac)` / LAN IP join
- **Perf**: `(router_id, probe, ts)` in `cpe_perf_samples`

## Track 2 + field path extensions

| Item | API / path |
|------|------------|
| Local latency tool | `cpe_agent_get_local_latency_json` + `cpe_harness_register_tools` |
| Fuzz (no libsim) | `cpe_agent_fuzz_config_and_ndjson` / `fuzz/fuzz_cpe_agent.c` |
| Optional sim | `cpe_agent_sim_drive` (sim_clock + sim_timer; no uring) |
| nfct reuse | `cpe_agent_feed_nfct` → spool `cpe_nat` lines |
| Live ICMP (F4) | `cpe_agent_live_ping_tick` / `sample_tick` when `demo_mode=0` |
| mTLS egress (F5) | `cpe_agent_tls_post` / `emit.mode=https` (soft mbedTLS) |
| Shared spool (F6) | `cpe_spool.h` → `/var/spool/netforensics/` |
| OpenWrt | `openwrt/cpe-agent/` + `openwrt/OPKG_ROLLBACK.md` |

## Deliberate absences

- ClickHouse not required for unit/host tests
- Production requirement for mbedTLS (optional; Vector-local default)
- Live CAP_NET_ADMIN netlink inside cpe_agent (forensicsd owns that path; agent can feed bytes)
- Full reverse-proxy PKI automation (ops-owned)
