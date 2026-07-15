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
```

## Library mapping

| Design concern | Library API |
|----------------|-------------|
| IPFIX templates + 5-tuple | `ipfix_feed_*`, `ipfix_record_flow_key`, convenience BGP/next-hop |
| Conntrack NEW/DESTROY | `nfct_feed_input`, `nfct_event_forensics_tuple` |
| Wi-Fi RSSI/MCS/retries | `nl80211_parse_feed_input`, `nl80211_event_t` |
| Edge ping/ARP health | existing libnetdiag ping/arping (optional) |
| Config | libyaml (future) |
| HTTP batch ingest | librest or Vector |

## Correlation keys

- **CPE NAT**: `(timestamp, wan_src_ip, wan_src_port)` primary for reverse path
- **Core IPFIX**: `(timestamp, src_ip, dst_ip, src_port, dst_port, protocol)`
- **BGP**: `(router_id, prefix, timestamp)` with VersionedCollapsingMergeTree
- **Wi-Fi**: `(timestamp, client_mac)` / LAN IP join

## Deliberate absences (scaffold)

- Real netlink sockets not yet opened in forensicsd (stub emit path)
- ClickHouse not required for unit tests
- BMP/BGP decoder library does not exist yet — SQL + Vector Kafka source first
