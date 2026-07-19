# TODO.md — netforensics

## Track 2 — CPE agent (program design)

- [x] **P2.1** agent scaffold + ADRs (003 placement, 004 mbedTLS, 005/N-A05 NDJSON); forensicsd unchanged
- [x] **P2.2** libuv loop + YAML config + SIGHUP flag
- [x] **P2.3** `cpe_host_alloc` + NEED_ALLOC event path
- [x] **P2.4** libnetdiag ping demo → in-memory stats + last sample
- [x] **P2.5** perf NDJSON + spool + `sql/003_cpe_perf_samples.sql` + Vector `cpe_perf` route
- [ ] **P2.6** libharness local tool (`get_local_latency` from last sample)
- [ ] **P2.7a** fuzz config + NDJSON formatter (local stubs)
- [ ] **P2.7b** optional libsim net/timer link
- [ ] **P2.8** optional nfct path reuse from agent
- [ ] **P2.9** OpenWrt package + opkg rollback notes for agent

```bash
cmake -B build -S .
cmake --build build && ctest --test-dir build --output-on-failure
./build/cpe_agent --once --router-id cpe-lab-1
./build/forensicsd --demo --router-id cpe-lab-1   # still works
```

## Scaffold (existing)

- [x] Repository under netforensics
- [x] AGENTS.md + ARCHITECTURE.md library map
- [x] CMake linking libipfix + libnetdiag (+ libyaml/libuv for agent)
- [x] ClickHouse DDL sketch + query stubs
- [x] Vector config skeleton (+ cpe_perf)
- [x] CPE sysctl template + daemon stub using nfct/nl80211_parse
- [x] Host integration test with synthetic IPFIX + nfct frames (`test_host_pipeline`)

## MODULE 1 — OpenWrt CPE daemon (forensicsd)

- [x] `cpe/sysctl/99-forensics.conf` template
- [x] Daemon stub emitting NDJSON from synthetic nfct/nl80211 frames
- [x] Real `AF_NETLINK` / `NETLINK_NETFILTER` + `NETLINK_ADD_MEMBERSHIP` for NEW/DESTROY (`--netlink`)
- [x] `nfct_netlink` helper (open/recv/nonblock) in app, feed into libnetdiag `nfct`
- [x] Full CTA attribute decode in libnetdiag — live events yield LAN/WAN 5-tuples when present
- [x] NDJSON fields: event, ip_version, ct_id; IPv6 + DESTROY-id observations
- [x] IPv6 path correlation in nf_flows_correlate
- [x] Periodic nl80211 station dump via generic netlink (`--wifi-if`, `--wifi-interval-ms`)
- [x] Full nl80211 nested STA_INFO attr decode (libnetdiag)
- [x] Output: stdout NDJSON (`cpe_nat`, structured `cpe_wifi`) for Vector/journald
- [x] OpenWrt package Makefile / cross-compile notes (`openwrt/`)
- [ ] Resource limits for MIPS/ARM (fixed buffers, no heap on event path)
- [x] systemd unit with `AmbientCapabilities=CAP_NET_ADMIN` (`deploy/forensicsd.service`)

## MODULE 2 — Ingest gateway

- [x] `vector/vector.yaml` skeleton (HTTP/UDP CPE, IPFIX, Kafka BMP placeholders, **cpe_perf**)
- [ ] Tune batch sizes / disk buffers for 20k CPE fan-in
- [ ] Optional pure-C gateway with librest + libipfix (replace Vector later?)
- [ ] Authn between CPE and gateway (mTLS — possible shared design with pqproxy)

## MODULE 3 — ClickHouse schema

- [x] Initial DDL: bgp_updates, ipfix_flows, cpe_nat_flows*, cpe_wifi_metrics
- [x] `cpe_perf_samples` migration (`sql/003_cpe_perf_samples.sql`)
- [ ] `historical_rib_trie` dictionary validated on CH version N
- [ ] Async insert settings verified under load
- [ ] Materialized view reverse-tuple ordering for NAT
- [ ] TTL / retention policies

## MODULE 4 — Queries

- [x] Stub SQL for outbound, inbound, blast radius
- [x] Validate join keys against synthetic fixtures (host_pipeline + sql_fixtures)
- [ ] Parameterize router_id / time window helpers
- [ ] Grafana / notebook examples

## Cross-cutting

- [ ] Clock sync assumptions (NTP on CPE) documented
- [ ] Sampling vs full conntrack event rates
- [ ] Privacy: MAC anonymization options
- [ ] libharness tools for interactive blast-radius investigation (P2.6)

## Library follow-ups

- [ ] libipfix exporter path if CPE ever emits IPFIX instead of JSON
- [x] libnetdiag full nfct + nl80211 STA_INFO decoders + live gnl dump in daemon
- [x] New sibling: libbmp (ADRs applied; queue overflow, fixed reassembly, payload slots)
- [x] App glue: `bmp_ingest` + `bmp_ingest_demo` + Vector `bmp_ndjson` source
