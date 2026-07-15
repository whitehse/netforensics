# TODO.md — netforensics

Further work to explore. Ordered by module.

## Scaffold

- [x] Repository under `~/apps/netforensics`
- [x] AGENTS.md + ARCHITECTURE.md library map
- [x] CMake linking libipfix + libnetdiag
- [x] ClickHouse DDL sketch + query stubs
- [x] Vector config skeleton
- [x] CPE sysctl template + daemon stub using nfct/nl80211_parse
- [x] Host integration test with synthetic IPFIX + nfct frames (`test_host_pipeline`)

## MODULE 1 — OpenWrt CPE daemon

- [x] `cpe/sysctl/99-forensics.conf` template
- [x] Daemon stub emitting NDJSON from synthetic nfct/nl80211 frames
- [x] Real `AF_NETLINK` / `NETLINK_NETFILTER` + `NETLINK_ADD_MEMBERSHIP` for NEW/DESTROY (`--netlink`)
- [x] `nfct_netlink` helper (open/recv/nonblock) in app, feed into libnetdiag `nfct`
- [x] Full CTA attribute decode in libnetdiag — live events yield LAN/WAN 5-tuples when present
- [x] NDJSON fields: event, ip_version, ct_id; IPv6 + DESTROY-id observations
- [x] IPv6 path correlation in nf_flows_correlate
- [ ] Periodic nl80211 station dump via generic netlink
- [x] Full nl80211 nested STA_INFO attr decode (libnetdiag)
- [x] Output: stdout NDJSON (`cpe_nat`, structured `cpe_wifi`) for Vector/journald
- [ ] OpenWrt package Makefile / cross-compile notes
- [ ] Resource limits for MIPS/ARM (fixed buffers, no heap on event path)
- [x] systemd unit with `AmbientCapabilities=CAP_NET_ADMIN` (`deploy/forensicsd.service`)

## MODULE 2 — Ingest gateway

- [x] `vector/vector.yaml` skeleton (HTTP/UDP CPE, IPFIX, Kafka BMP placeholders)
- [ ] Tune batch sizes / disk buffers for 20k CPE fan-in
- [ ] Optional pure-C gateway with librest + libipfix (replace Vector later?)
- [ ] Authn between CPE and gateway (mTLS — possible shared design with pqproxy)

## MODULE 3 — ClickHouse schema

- [x] Initial DDL: bgp_updates, ipfix_flows, cpe_nat_flows*, cpe_wifi_metrics
- [ ] `historical_rib_trie` dictionary validated on CH version N
- [ ] Async insert settings verified under load
- [ ] Materialized view reverse-tuple ordering for NAT
- [ ] TTL / retention policies

## MODULE 4 — Queries

- [x] Stub SQL for outbound, inbound, blast radius
- [x] Validate join keys against synthetic fixtures (host_pipeline SQL shapes)
- [ ] Parameterize router_id / time window helpers
- [ ] Grafana / notebook examples

## Cross-cutting

- [ ] Clock sync assumptions (NTP on CPE) documented
- [ ] Sampling vs full conntrack event rates
- [ ] Privacy: MAC anonymization options
- [ ] libharness tools for interactive blast-radius investigation

## Library follow-ups

- [ ] libipfix exporter path if CPE ever emits IPFIX instead of JSON
- [x] libnetdiag full nfct + nl80211 STA_INFO decoders (remaining: live gnl dump in daemon)
- [ ] New sibling: libbgp/libbmp for BGP Monitoring Protocol PDUs?
