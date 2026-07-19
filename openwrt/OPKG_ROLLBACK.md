# opkg rollback notes (P2.9)

These notes cover **cpe-agent** and **netforensics-cpe** (forensicsd) on OpenWrt.
Always keep a last-known-good `.ipk` on the device or staging server before
upgrading fleet images.

## Pin previous package version

```sh
# List installed
opkg list-installed | grep -E 'cpe-agent|netforensics-cpe'

# Prefer explicit reinstall of a known-good ipk over "upgrade latest"
opkg install --force-reinstall /tmp/cpe-agent_0.2.0-1_*.ipk
opkg install --force-reinstall /tmp/netforensics-cpe_0.1.0-1_*.ipk
```

## Safe upgrade sequence (lab)

1. Copy new + previous `.ipk` to `/tmp`.
2. `opkg install /tmp/cpe-agent_<new>.ipk` (or `opkg upgrade` from feed).
3. `logread -e cpe_agent` / `logread -e forensicsd` — confirm NDJSON still flows.
4. If broken within observation window: reinstall previous ipk (commands above),
   then ` /etc/init.d/cpe_agent restart` and `/etc/init.d/forensicsd restart`.

## Dual-daemon interaction

| Package | Binary | Failure mode if removed |
|---------|--------|-------------------------|
| `netforensics-cpe` | `forensicsd` | Lose `cpe_nat` / `cpe_wifi` |
| `cpe-agent` | `cpe_agent` | Lose `cpe_perf` samples only |

They share Vector fan-in, **not** process state. Rolling back one package does
**not** require rolling back the other unless you changed shared Vector schema
in the same change window.

## Config preservation

- `cpe-agent` conffile: `/etc/cpe_agent/cpe_agent.yaml` (opkg conffiles).
- On upgrade conflict, opkg keeps `.yaml-opkg` / asks; restore known-good YAML
  before restarting.
- `forensicsd` sysctl: `/etc/sysctl.d/99-forensics.conf`.

## Version policy

- Bump `PKG_VERSION` in the OpenWrt `Makefile` when agent wire format or
  required config keys change.
- Keep last two field versions in the feed or offline store for at least one
  maintenance cycle.
- Schema-breaking NDJSON changes require coordinated Vector + ClickHouse
  deploy **before** CPE upgrade (N-A05 / ADR-005).

## Host verification before packaging

```bash
cmake -B build -S .
cmake --build build && ctest --test-dir build --output-on-failure
./build/cpe_agent --once --router-id lab-1 | grep cpe_perf
./build/forensicsd --demo --router-id lab-1 | grep cpe_nat
```
