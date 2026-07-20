# AGENTS.md — netforensics

## What this is

**netforensics** is a network forensics engine that correlates:

- CPE conntrack NAT sessions + Wi-Fi telemetry (OpenWrt edge)
- Core router **IPFIX** flows
- BGP updates / historical RIB (ClickHouse)
- **CPE performance samples** (`cpe_perf` NDJSON from the agent)

across ~25 core routers and 20,000+ CPE devices for hop-by-hop path reconstruction.

Program design: `~/edge-platform-program-design.md` (Track 2).

## Modules

1. **CPE daemon** (`cpe/forensicsd`) — netlink conntrack + nl80211; emits `cpe_nat` / `cpe_wifi` NDJSON
2. **CPE agent** (`agent/cpe_agent`) — libuv host; libnetdiag ping demo; emits `cpe_perf` NDJSON (Track 2)
3. **Ingest gateway** (`vector/`) — multiplex to ClickHouse
4. **ClickHouse schema** (`sql/`) — tables, dictionaries, MVs
5. **Query pack** (`sql/queries/`) — path tracers + blast-radius analysis

## Language / build

- C11 CPE daemons + agent
- CMake ≥ 3.20
- Siblings: **libipfix**, **libnetdiag**, **libbmp**, **libyaml**; host **libuv** for agent

```bash
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure

# forensicsd (NAT/wifi) — unchanged
./build/forensicsd --demo --router-id cpe-lab-1

# cpe_agent (perf) — Track 2
./build/cpe_agent --once --router-id cpe-lab-1
./build/cpe_agent --config config/cpe_agent.example.yaml
```

## Directives

- **Must** keep netlink sockets and ClickHouse HTTP out of pure libraries; libraries only parse buffers.
- **Must** use `nfct` forensics 5-tuple fields for CPE NAT correlation keys.
- **Must not** break `forensicsd` when extending the agent.
- **Must** emit CPE performance as **NDJSON** `type=cpe_perf` → Vector → `forensics.cpe_perf_samples` (N-A05 / ADR-005). **No** production ClickHouse client on CPE.
- **Must** use **libuv** for the agent loop (class B); not io_uring on OpenWrt baseline.
- **Prefer** mbedTLS if/when agent TLS is needed (ADR-004); edgehost uses OpenSSL separately.
- **Local tool**: `get_local_latency` via libharness registration + `cpe_harness_invoke_local` (P2.6).
- **Never** allocate on forensicsd hot path after startup (fixed buffers).

## Definition of done

- [x] CPE daemon builds for host and documents OpenWrt cross-compile
- [x] CPE agent builds; `--once` emits `cpe_perf`; unit tests pass
- [x] Synthetic nfct + ipfix dialectic tests pass
- [x] SQL DDL includes `cpe_perf_samples`
- [ ] TODO.md updated when module boundaries change

## Related libraries

| Path | Use |
|------|-----|
| `~/libipfix` | Core IPFIX decode + flow keys |
| `~/libnetdiag` | nfct + nl80211_parse + ping/arping diagnostics |
| `~/libyaml` | Agent + future daemon config |
| `~/librest` | Optional C HTTP ingest (vs Vector) |
| `~/libharness` | Future AI-assisted blast-radius tooling (P2.6) |
| `libuv` | Agent event loop (P2.2) |

## Track 2 status

**Track 2 complete (P2.1–P2.9):** harness `get_local_latency`, fuzz stubs,
optional libsim drive, nfct reuse, OpenWrt `cpe-agent` package + opkg rollback.

**Field path (F1–F3):** `cpe_agent_emit_flush` (spool file), SIGHUP YAML
reload via `cpe_agent_reload_config`, ADR-007. Next: live ICMP (F4), mTLS (F5).
