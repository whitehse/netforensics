# ARCHITECTURE.md — netforensics

## Goal

Retroactive root-cause analysis: reconstruct a flow path from LAN/Wi-Fi client
through CPE NAT, core IPFIX hops, and BGP egress at a historical millisecond.

## System diagram

```
[OpenWrt CPE x20k]                    [Core routers x25]
  conntrack netlink ──┐                 IPFIX UDP/TCP ──┐
  nl80211 station  ───┼──▶ Vector/C gateway ──▶ ClickHouse
                      │                 BMP/BGP ────────┘
                      └── NDJSON lines
```

## Module boundaries

```
cpe/
  forensicsd.c          — --demo | --netlink daemon entry
  sysctl/99-forensics.conf
src/
  nfct_netlink.c        — AF_NETLINK NETLINK_NETFILTER membership + recv
  ipfix_ingest.c        — libipfix collector glue
  bmp_ingest.c          — libbmp events → nf_bmp_obs_t / NDJSON
  flow_correlate.c      — pure helpers joining tuples (no I/O)
include/
  netforensics.h
  nfct_netlink.h
sql/
  001_schema.sql        — tables + async insert settings
  002_dictionary.sql    — IP_TRIE historical RIB
  queries/
    outbound_path.sql
    inbound_path.sql
    blast_radius.sql
vector/
  vector.yaml           — production ingest multiplexor
config/
  forensicsd.example.yaml
deploy/
  forensicsd.service    — systemd unit (CAP_NET_ADMIN)
tests/
  test_correlate.c      — unit correlate helpers
  test_host_pipeline.c  — synthetic IPFIX + nfct + wifi → NDJSON/SQL fixtures
```

## Library mapping

| Design concern | Library API |
|----------------|-------------|
| IPFIX templates + 5-tuple | `ipfix_feed_*`, `ipfix_record_flow_key`, convenience BGP/next-hop |
| Conntrack NEW/DESTROY | `nfct_feed_input`, `nfct_event_forensics_tuple` / `_v6` |
| Wi-Fi RSSI/MCS/retries | `nl80211_parse_feed_input` (synth + nested STA_INFO attrs) |
| BMP (BGP monitoring) | **libbmp** `bmp_feed_*` + app `nf_bmp_collect*` → NDJSON |
| Edge ping/ARP health | existing libnetdiag ping/arping (optional) |
| Config | libyaml (future) |
| HTTP batch ingest | librest or Vector |

## CPE daemon modes

| Mode | Behavior |
|------|----------|
| `--demo` | Synthetic nfct + nl80211 frames → stdout NDJSON (no privileges) |
| `--netlink` | Live `AF_NETLINK` / `NETLINK_NETFILTER` NEW/DESTROY → CTA decode → NDJSON |

Netlink path uses app-owned sockets (`nfct_netlink_*`) and feeds bytes into
syscall-free libnetdiag parsers. CTA decode covers IPv4/IPv6 ORIG/REPLY and
DESTROY-with-id observations.

## Correlation keys

- **CPE NAT**: `(timestamp, wan_src_ip, wan_src_port)` primary for reverse path
- **Core IPFIX**: `(timestamp, src_ip, dst_ip, src_port, dst_port, protocol)`
- **BGP**: `(router_id, prefix, timestamp)` with VersionedCollapsingMergeTree
- **Wi-Fi**: `(timestamp, client_mac)` / LAN IP join

## Host pipeline (tests)

`test_host_pipeline` validates without ClickHouse or CAP_NET_ADMIN:

1. Build synthetic IPFIX data set → `nf_ipfix_collect_flows`
2. Build synthetic nfct frame → `nfct_feed_input` → `nf_obs_from_nfct`
3. `nf_flows_correlate` on WAN 5-tuple within skew window
4. Format NDJSON + SQL INSERT fixtures matching `sql/001_schema.sql`
5. Nested nl80211 STA_INFO attrs → structured `cpe_wifi` NDJSON

## BMP ingest path

```
BMP speaker ──TCP──▶ app gateway (I/O)
                        │ bmp_feed_input / nf_bmp_collect_stream
                        ▼
                     libbmp (parse only)
                        │
                        ▼
                   nf_bmp_obs_format → NDJSON → Vector → CH bgp_updates
```

Nested BGP UPDATE NLRI decode remains opaque payload (libbmp ADR-008).
Optional: Kafka source with pre-parsed gobmp JSON still works in `vector.yaml`.

## Deliberate absences

- ClickHouse not required for unit/host tests
- Full BGP path-attribute decode (future libbgp)
- OpenWrt package is skeleton only; cross-compile in production feed
