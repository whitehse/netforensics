# ADR 005 (N-A05): CPE performance samples extend NDJSON types

## Status

Accepted (P2.1 / P2.5) — program name **N-A05**

## Date

2026-07-18

## Context

CPE needs performance probes (ping, etc.) as a product surface without a
direct ClickHouse client on device. netforensics ADR-002 already defines
NDJSON → Vector → ClickHouse for `cpe_nat` / `cpe_wifi`.

## Decision

1. **New NDJSON type** `cpe_perf` (does **not** supersede ADR-002 fan-in).
2. **Line shape**:
   ```json
   {"type":"cpe_perf","ts":"…","router_id":"…","probe":"ping","target":"…",
    "rtt_ms":12.4,"loss":0.0,"meta":{}}
   ```
3. **ClickHouse**: `forensics.cpe_perf_samples` (`sql/003_cpe_perf_samples.sql`).
4. **Vector**: route `type == "cpe_perf"` → that table (see `vector/vector.yaml`).
5. **On-device path**: format → bounded **spool** → stdout/file; **no**
   production `clickhouse_io.c` on CPE.
6. Optional lab-only HTTP CH client may exist behind compile flag later; not
   packaged for field images.

## Consequences

- Schema evolution coordinates Vector transforms + SQL (same as ADR-002).
- Agent demo emits valid lines without CAP_NET_ADMIN.
- forensicsd continues to emit only NAT/wifi types.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Direct CH client on CPE | Design ADR-002; dual ingest plane |
| Reuse `cpe_nat` type | Wrong semantics; pollutes NAT tables |
