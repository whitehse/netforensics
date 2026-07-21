# ADR 009: LXC / prpl containerization and host privileges

## Status

Accepted

## Date

2026-07-21

## Context

Field hardware targets include Calix GigaSpire **u6.3** and **7u6**, expected to
run prpl/EXOS-class software with **LXC** (prpl LCM) for add-on applications.
Operators asked whether the netforensics CPE build supports containerization
**when low-level system functions can be accessed**.

## Decision

1. **Ship two privilege profiles** (documented in
   [`guides/lxc-prpl-containerization.md`](../guides/lxc-prpl-containerization.md)):
   - **Profile B (unprivileged):** demo agent + demo forensicsd only.
   - **Profile A (privileged EE):** host network namespace +
     `CAP_NET_ADMIN` (forensicsd) and optional `CAP_NET_RAW` (live ICMP).
2. **Keep libraries syscall-free**; never hide netlink/raw sockets inside
   libnetdiag. Container policy remains a host/LCM concern.
3. **Sysctl** (`99-forensics.conf`) is **host-applied**, not container-assumed.
4. **Cross-compile** is required for device ABI; x86_64 lab binaries are not
   field artifacts.
5. Prefer **Profile C** (privileged netlink side-car + unprivileged agent) if
   LCM policy forbids CAP_NET_ADMIN inside app EEs.

## Consequences

- Full path reconstruction data plane can run in LXC **with** host net access.
- Without host netns/caps, only synthetic NDJSON is guaranteed.
- Packaging work moves from “opkg only” toward prpl LCM EE descriptors.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Always require host install (no container) | Conflicts with prpl LCM / Calix app model |
| Always unprivileged only | Loses live conntrack/Wi‑Fi value |
| Put CAP_NET_ADMIN inside library | Breaks ADR-001 and fuzz story |
