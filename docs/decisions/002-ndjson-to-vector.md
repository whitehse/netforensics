# ADR 002: CPE emits NDJSON; Vector multiplexes to ClickHouse

## Status

Accepted

## Context

20k CPE devices cannot each speak native ClickHouse protocol reliably.
A fan-in tier is required.

## Decision

- CPE daemon writes one NDJSON object per line (`cpe_nat`, `cpe_wifi`).
- Vector (or a future pure-C gateway) batches into ClickHouse tables defined
  in `sql/001_schema.sql`.
- Correlation keys are documented in ARCHITECTURE.md (WAN 5-tuple, MAC, time).

## Consequences

- Schema evolution requires coordinated Vector transforms + SQL.
- Optional later: replace Vector with librest HTTP ingest without changing CPE.
