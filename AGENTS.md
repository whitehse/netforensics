# AGENTS.md — netforensics

## What this is

**netforensics** is a network forensics engine that correlates:

- CPE conntrack NAT sessions + Wi-Fi telemetry (OpenWrt edge)
- Core router **IPFIX** flows
- BGP updates / historical RIB (ClickHouse)

across ~25 core routers and 20,000+ CPE devices for hop-by-hop path reconstruction.

Design source: `~/new_design3.txt`.

## Modules (aligned with design)

1. **CPE daemon** (`cpe/`) — netlink conntrack + nl80211; emits NDJSON
2. **Ingest gateway** (`vector/` or future C gateway with librest) — multiplex to ClickHouse
3. **ClickHouse schema** (`sql/`) — tables, dictionaries, MVs
4. **Query pack** (`sql/queries/`) — path tracers + blast-radius analysis

## Language / build

- C11 CPE daemon + optional C ingest helpers
- CMake ≥ 3.20
- Sibling: **libipfix**, **libnetdiag** (nfct, nl80211_parse), **libyaml**

```bash
cmake -B build -S . \
  -DIPFIX_ROOT=$HOME/libipfix \
  -DNETDIAG_ROOT=$HOME/libnetdiag
cmake --build build
ctest --test-dir build
```

## Directives

- **Must** keep netlink sockets and ClickHouse HTTP in the app; libraries only parse buffers.
- **Must** use `nfct` forensics 5-tuple fields for CPE NAT correlation keys.
- **Must** use `ipfix_record_flow_key` / convenience BGP fields for core flow joins.
- **Must** use **libbmp** for BMP framing (`bmp_feed_*`); app owns TCP and maps events via `nf_bmp_collect*` / `nf_bmp_obs_format`.
- **Prefer** ClickHouse native types (`IPv4`, `DateTime64(3)`, `LowCardinality`) as in design.
- **Never** allocate on CPE hot path after startup (fixed buffers).

## Definition of done

- [ ] CPE daemon builds for host and documents OpenWrt cross-compile
- [ ] Synthetic nfct + ipfix dialectic tests pass
- [ ] SQL DDL applies on a ClickHouse dev instance
- [ ] TODO.md updated when module boundaries change

## Related libraries

| Path | Use |
|------|-----|
| `~/libipfix` | Core IPFIX decode + flow keys |
| `~/libnetdiag` | nfct + nl80211_parse + edge diagnostics |
| `~/libyaml` | Daemon config |
| `~/librest` | Optional C HTTP ingest (vs Vector) |
| `~/libharness` | Future AI-assisted blast-radius tooling |
