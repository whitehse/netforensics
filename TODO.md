# TODO.md — netforensics

## Track 2 — CPE agent (program design)

- [x] **P2.1** agent scaffold + ADRs (003 placement, 004 mbedTLS, 005/N-A05 NDJSON); forensicsd unchanged
- [x] **P2.2** libuv loop + YAML config + SIGHUP flag
- [x] **P2.3** `cpe_host_alloc` + NEED_ALLOC event path
- [x] **P2.4** libnetdiag ping demo → in-memory stats + last sample
- [x] **P2.5** perf NDJSON + spool + `sql/003_cpe_perf_samples.sql` + Vector `cpe_perf` route
- [x] **P2.6** libharness local tool `get_local_latency` (`cpe_harness.h`)
- [x] **P2.7a** fuzz config + NDJSON formatter (local stubs; `cpe_agent_fuzz_*`)
- [x] **P2.7b** optional libsim net/timer drive (`cpe_agent_sim_*`, soft dep)
- [x] **P2.8** optional nfct path reuse (`cpe_agent_feed_nfct`)
- [x] **P2.9** OpenWrt package `cpe-agent` + [opkg rollback notes](openwrt/OPKG_ROLLBACK.md)

**Track 2 complete.**

## Field path (post–Track 2, OpenWrt ops)

- [x] **F1** `emit.mode=spool` append flush (`cpe_agent_emit_flush`) + path validation
- [x] **F2** SIGHUP YAML shadow reload (`cpe_agent_reload_config`) + CLI router override
- [x] **F3** libuv timer re-arm after interval change; init/docs ADR-007
- [x] **F4** Live ICMP probe path (CAP_NET_RAW / raw socket) behind `demo.enabled: false`
- [x] **F5** Optional mbedTLS mTLS egress to gateway (ADR-004; soft dep; stub without libs)
- [x] **F6** Shared spool dir helper with forensicsd; dual-daemon resource caps (MIPS/ARM)

**Field path F1–F6 complete** (ADR-007, ADR-008).

```bash
cmake -B build -S .
cmake --build build && ctest --test-dir build --output-on-failure
./build/cpe_agent --once --router-id cpe-lab-1
./build/forensicsd --demo --router-id cpe-lab-1
```

Optional:

```bash
# libFuzzer (clang)
cmake -B build-fuzz -S . -DBUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz --target fuzz_cpe_agent

# mbedTLS HTTPS egress (if libs installed)
cmake -B build -S . -DCPE_AGENT_WITH_MBEDTLS=ON
```

## Scaffold (existing)

- [x] Repository under netforensics
- [x] AGENTS.md + ARCHITECTURE.md library map
- [x] CMake linking libipfix + libnetdiag (+ libyaml/libuv/libharness/libsim for agent)
- [x] ClickHouse DDL sketch + query stubs
- [x] Vector config skeleton (+ cpe_perf)
- [x] CPE sysctl template + daemon stub using nfct/nl80211_parse
- [x] Host integration test with synthetic IPFIX + nfct frames (`test_host_pipeline`)

## MODULE 1 — OpenWrt CPE daemon (forensicsd)

- [x] Daemon stub + live netlink + nl80211
- [x] OpenWrt package Makefile / cross-compile notes (`openwrt/netforensics`)
- [x] systemd unit with `AmbientCapabilities=CAP_NET_ADMIN`
- [x] Resource limits for MIPS/ARM (fixed line buffers in daemon; MemoryMax/TasksMax/LimitNOFILE; shared spool dir)

## MODULE 2 — Ingest gateway

- [x] `vector/vector.yaml` skeleton including **cpe_perf**
- [x] Tune batch sizes / disk buffers for 20k CPE fan-in
- [x] Optional pure-C gateway stub (`gateway_stub`; lab only)
- [x] Authn between CPE and gateway (mTLS): agent F5 + terminate at reverse proxy; Vector notes

## MODULE 3 — ClickHouse schema

- [x] Initial DDL + `cpe_perf_samples` (`sql/003_cpe_perf_samples.sql`)
- [x] historical_rib_trie dictionary notes + validation checklist (`sql/002_dictionary_notes.md`)
- [x] Async insert settings documented (`sql/005_async_insert_settings.sql`)
- [x] TTL / retention policies (`sql/004_ttl_retention.sql`)

## MODULE 4 — Queries

- [x] Stub SQL for outbound, inbound, blast radius
- [x] Validate join keys against synthetic fixtures
- [x] Parameterize router_id / time window helpers (`sql/queries/helpers.sql`)
- [x] Grafana / notebook examples (`grafana/cpe_perf_dashboard.json`)

## Container / prpl (Calix u6.3 / 7u6 class)

- [x] Document LXC privilege matrix + host netns requirement (ADR-009, guide)
- [x] aarch64 cross-build path (Bootlin musl + CMake toolchains + poll loop)
- [x] prpl LCM EE package descriptor + LXC Profile A/B configs
- [ ] On-device smoke: demo + live netlink inside privileged EE (needs hardware)
- [ ] OpenWrt SDK staging_dir dry-run when vendor SDK available
