# ADR 007: Field spool emit + SIGHUP config reload

## Status

Accepted (post–Track 2 field path)

## Date

2026-07-20

## Context

Track 2 delivered demo NDJSON to stdout and a HUP *flag* only. OpenWrt
`procd` reload and offline Vector tail need:

1. Append-to-file emit (`emit.mode=spool`) without a second ingest plane.
2. Real YAML shadow reload on SIGHUP while keeping CLI `--router-id`.

## Decision

1. **`cpe_agent_emit_flush`** — host flushes the in-memory ring according to
   `emit.mode`: `stdout` → stdout; `spool` → append-open of `spool_path`.
2. **Validate** — `emit.mode=spool` requires a non-empty path.
3. **`cpe_agent_reload_config`** — load YAML path (optional), apply router
   override (optional), then `apply_config`. Used by main and the libuv loop.
4. **`cpe_agent_run_uv(opts)`** — options carry `config_path` and
   `router_id_override` for HUP; timer interval re-arms when reload changes it.

Production ingest remains NDJSON → Vector (ADR-002 / N-A05). No mTLS or
ClickHouse client on device in this ADR.

## Consequences

- Field images can spool to `/var/spool/...` for local Vector file sources.
- `service cpe_agent reload` re-applies `/etc/cpe_agent/cpe_agent.yaml`.
- Tests cover spool path validation, file flush, and override-preserving reload.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Only HUP flag forever | OpenWrt ops expect config reload |
| Always stdout | Spool needed when procd does not pipe to Vector |
| Merge into forensicsd | Still dual-daemon (ADR-006) |
