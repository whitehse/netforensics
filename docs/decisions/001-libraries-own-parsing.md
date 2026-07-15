# ADR 001: Libraries own parsing; app owns I/O

## Status

Accepted

## Context

netforensics needs conntrack, nl80211, and IPFIX decoding at CPE and core
scale. Sibling pure-C libraries must remain syscall-free and callback-free.

## Decision

- **libnetdiag** / **libipfix** parse caller-supplied buffers into events.
- **forensicsd** and ingest tools own netlink/UDP sockets, privilege dropping,
  NDJSON emission, and deployment units.
- Correlation helpers in the app stay pure (no I/O).

## Consequences

- Unit and host-pipeline tests run without CAP_NET_ADMIN or ClickHouse.
- New protocol coverage lands in libraries first; apps only wire I/O.
