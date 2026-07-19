# ADR 003: CPE agent under `netforensics/agent/` (class B / libuv)

## Status

Accepted (P2.1)

## Date

2026-07-18

## Context

Program Track 2 needs a product CPE edge agent that drives libnetdiag, reuses
netforensics telemetry lineage, and emits performance samples. Placement and
event-loop class were open.

## Decision

1. **Location**: `netforensics/agent/` (binary `cpe_agent`), not a new repo and
   not inside pure-C `libnetdiag`.
2. **Loop**: **libuv** (class B). No io_uring on OpenWrt kernel ≥ 5.4 baseline.
3. **forensicsd**: remains the conntrack/nl80211 NDJSON daemon (ADR-002). The
   agent co-exists; it does not break or replace forensicsd.
4. **Public API**: `include/cpe_agent.h` — create, apply_config, demo tick,
   spool, run_uv.
5. **TLS (when needed later)**: **mbedTLS** on CPE (see ADR-004). Independent
   of edgehost OpenSSL.

## Consequences

- Packaging/SQL/Vector stay in netforensics.
- Dual daemons on CPE is documented; later merge modes possible.
- Fuzz/sim: local stubs first (P2.7a); optional libsim net/timer (P2.7b).

## Alternatives considered

| Option | Why not |
|--------|---------|
| Agent inside libnetdiag | Pollutes pure parsers with host loop |
| io_uring on CPE | Baseline OpenWrt 5.4; class A reserved for edgehost |
| Replace forensicsd in P2.1 | Breaks existing NAT/wifi pipeline |
