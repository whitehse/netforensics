# ADR 006: Track 2 remainder (harness, fuzz, sim, nfct, OpenWrt)

## Status

Accepted (P2.6–P2.9)

## Date

2026-07-19

## Context

P2.1–P2.5 delivered the agent vertical slice (libuv, YAML, host_alloc, demo
ping, cpe_perf spool). Remaining Track 2 items need stable local APIs without
pulling edgehost class-A uring or a ClickHouse client onto CPE.

## Decision

1. **P2.6** — Register OpenAI-style tool `get_local_latency` on libharness;
   host invokes via `cpe_harness_invoke_local` reading in-memory last sample.
   Soft dep: build without harness if sibling missing.
2. **P2.7a** — `cpe_agent_fuzz_config_and_ndjson` exercises YAML load/apply +
   NDJSON format with arbitrary bytes; no libsim required. Optional
   `BUILD_FUZZ` libFuzzer binary.
3. **P2.7b** — `cpe_agent_sim_drive` uses libsim clock+timer only (`LIBSIM_NO_URING`).
4. **P2.8** — `cpe_agent_feed_nfct` reuses libnetdiag nfct + `nf_obs_format` to
   enqueue `cpe_nat` on the agent spool (byte feed; forensicsd keeps live
   netlink).
5. **P2.9** — OpenWrt package `cpe-agent` + `OPKG_ROLLBACK.md` dual-daemon
   rollback notes.

## Consequences

- Track 2 marked complete in TODO/AGENTS.
- Field images can ship forensicsd and/or cpe_agent independently.
- Fuzz CI can enable BUILD_FUZZ without class-A uring.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Full LLM loop on CPE for tools | Flash/CPU; local tool invoke is enough for v1 |
| Require libsim always | Soft dep; P2.7a must work alone |
| Merge agent into forensicsd now | Dual-daemon documented; merge later if needed |
