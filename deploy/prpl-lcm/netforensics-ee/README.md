# prpl LCM Execution Environment — netforensics

Profile **A** (live) and **B** (demo) packaging for Calix u6.3 / 7u6 class
gateways using prpl LCM (cthulhu-lxc) or plain LXC.

## Layout

```
netforensics-ee/
  manifest.yaml                      # LCM-oriented package contract
  container-config-profile-a.json    # OCI-ish config, host net + caps
  container-config-profile-b.json    # isolated net, demo only
  files/entrypoint.sh
  rootfs/                            # produced by stage_lxc_rootfs.sh
```

Sibling LXC configs: `deploy/lxc/netforensics-profile-{a,b}.conf`.

## Build aarch64 **musl** rootfs

Field boards (Calix u6.3 / 7u6 class) are **musl**. Binaries must use
`/lib/ld-musl-aarch64.so.1` — not glibc (`ld-linux-aarch64.so.1`).

```bash
# 1) Bootlin aarch64--musl toolchain (no root)
./scripts/fetch_bootlin_aarch64.sh
export BOOTLIN_TOOLCHAIN=$HOME/toolchains/aarch64--musl--stable-2025.08-1

# 2) Cross-build field profile (fails if output is not musl)
./scripts/cross_build_aarch64.sh

# 3) Stage EE rootfs
DEST=deploy/prpl-lcm/netforensics-ee/rootfs \
  ./scripts/stage_lxc_rootfs.sh build-aarch64

# 4) Sanity
file build-aarch64/cpe_agent
# expect: ARM aarch64 ... interpreter /lib/ld-musl-aarch64.so.1
```

Do **not** use `gcc-aarch64-linux-gnu` (Debian glibc) for field images.
OpenWrt SDK path is fine when the SDK is musl (`STAGING_DIR` + `TOOLCHAIN_DIR`).

## Host preparation (Profile A)

```sh
mkdir -p /var/spool/netforensics
sysctl -p /path/to/99-forensics.conf   # from rootfs etc/netforensics/
```

## Install notes

Map `manifest.yaml` privileges into your vendor’s InstallDU / EE policy so that:

| Need | Value |
|------|--------|
| Network | **host** (no private netns) |
| Caps | `CAP_NET_ADMIN`, `CAP_NET_RAW` |
| Bind | `/var/spool/netforensics` RW |
| Memory | ≤ 48 MiB |
| Entry | `/usr/sbin/netforensics-entrypoint` |

Vendor cthulhu versions differ in JSON field names; use the privilege **contract**
in `manifest.yaml` as the source of truth if OCI keys need renaming.

## Profile B

Use `container-config-profile-b.json` and entrypoint `--demo` when LCM policy
forbids privileged EEs. Live conntrack/Wi‑Fi will not work.

## Smoke

```sh
# inside EE or on host after install
/usr/sbin/cpe_agent --once --router-id lab | grep cpe_perf
/usr/sbin/forensicsd --demo --router-id lab | grep cpe_nat
# Profile A only:
/usr/sbin/forensicsd --netlink --router-id lab
```
