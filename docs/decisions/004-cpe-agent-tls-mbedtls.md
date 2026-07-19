# ADR 004: CPE agent TLS = mbedTLS

## Status

Accepted (P2.1; aligns program Key Decision 21)

## Date

2026-07-18

## Context

edgehost uses OpenSSL non-blocking with io_uring. CPE flash size and OpenWrt
packaging favor a smaller TLS stack. Production v1 ingest is NDJSON → Vector
and may not require TLS inside the agent binary.

## Decision

- When the agent needs TLS (HTTPS egress, lab tools, future mTLS to gateways),
  use **mbedTLS**, not OpenSSL.
- v1 field path: NDJSON lines to stdout/spool; Vector (or gateway) owns fan-in.
- No multi-backend TLS abstraction shared with edgehost.

## Consequences

- Dependency set on OpenWrt stays smaller for optional TLS builds.
- Documented split: edgehost=OpenSSL, CPE=mbedTLS, pqproxy=OpenSSL side-car.

## Alternatives considered

| Option | Why not |
|--------|---------|
| OpenSSL on CPE | Larger footprint; unnecessary skill match with edgehost |
| Always TLS in v1 agent | Ingest is NDJSON/Vector; TLS optional |
