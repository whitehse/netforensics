# OpenWrt packaging

## Layout

```
openwrt/
  OPKG_ROLLBACK.md           # P2.9 rollback procedure
  netforensics/              # forensicsd (conntrack / wifi)
    Makefile
    files/
      99-forensics.conf
      forensicsd.init
  cpe-agent/                 # cpe_agent (perf NDJSON; Track 2)
    Makefile
    files/
      cpe_agent.yaml
      cpe_agent.init
```

## Packages

| Package | Binary | Caps | Output |
|---------|--------|------|--------|
| `netforensics-cpe` | `forensicsd` | CAP_NET_ADMIN (netlink) | `cpe_nat`, `cpe_wifi` |
| `cpe-agent` | `cpe_agent` | none for demo mode | `cpe_perf` (stdout or spool file) |

Both may be installed on the same CPE. See [OPKG_ROLLBACK.md](OPKG_ROLLBACK.md).

**cpe-agent field notes:** `emit.mode=spool` + `emit.path` appends NDJSON for
local Vector file sources. `service cpe_agent reload` sends SIGHUP and re-reads
`/etc/cpe_agent/cpe_agent.yaml` (CLI `--router-id` override is preserved).

## Cross-compile tips

1. **Static deps**: vendor `libnetdiag` / `libyaml` sources into package `deps/`
   so the image does not need shared sibling libs.
2. **Flags**: `-Os -ffunction-sections -fdata-sections` and link with
   `-Wl,--gc-sections` for MIPS/ARM flash budgets.
3. **libuv**: declare `DEPENDS:=+libuv` for `cpe-agent`.
4. **Capabilities**: procd can grant `CAP_NET_ADMIN` for forensicsd only.
5. **Vector agent**: point local Vector (or syslog) at daemon stdout.

## Host build check

```bash
cmake -B build -S ../..
cmake --build build
ctest --test-dir build --output-on-failure
./build/forensicsd --demo --router-id lab-1
./build/cpe_agent --once --router-id lab-1
```
