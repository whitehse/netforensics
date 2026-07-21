# ADR 008: Live ICMP, optional mTLS egress, shared spool caps

## Status

Accepted (field path F4–F6)

## Date

2026-07-20

## Context

After F1–F3 (spool file + HUP reload), field OpenWrt still needed real probes,
optional gateway auth, and dual-daemon resource discipline.

## Decision

1. **F4 Live ICMP** — When `demo.enabled: false`, host opens
   `SOCK_DGRAM/IPPROTO_ICMP` (preferred) or `SOCK_RAW` (CAP_NET_RAW), measures
   RTT, emits `cpe_perf` with `meta.demo=false`. libnetdiag stays syscall-free.
2. **F5 mTLS** — Soft-dep mbedTLS (`CPE_AGENT_WITH_MBEDTLS`). `emit.mode=https`
   POSTs NDJSON batch with optional client certs. Without mbedTLS, stubs return
   -1; Vector-local stdout/spool remains default.
3. **F6 Shared spool** — Default dir `/var/spool/netforensics/` with distinct
   filenames for agent vs forensicsd; `cpe_spool_ensure_*`; hard cap
   `spool_max_lines ≤ 1024`; OpenWrt soft default 128.

## Consequences

- Field images can probe without synthetic feed; tests tolerate missing ICMP.
- HTTPS egress is opt-in; does not replace ADR-002 Vector path.
- Dual daemons share directory conventions without interleaving one file.

## Alternatives considered

| Option | Why not |
|--------|---------|
| ICMP inside libnetdiag | Violates syscall-free library rule |
| Always require mbedTLS | Flash size; Vector-local needs no TLS |
| Single merged daemon now | Still dual-daemon (ADR-006) until ops demands merge |
