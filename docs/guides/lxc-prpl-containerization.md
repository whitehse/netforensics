# LXC / prpl LCM containerization on Calix-class CPE

| Field | Value |
|-------|-------|
| **Audience** | Platform + field engineering |
| **Targets** | Calix GigaSpire **u6.3**, **7u6** (and similar prpl/EXOS-class gateways with LXC) |
| **Code** | `cpe_agent`, `forensicsd` in this tree |
| **Date** | 2026-07-21 |

## Executive verdict

| Question | Answer |
|----------|--------|
| Does the **software design** support LXC containerization? | **Yes** — libraries are syscall-free; the host binaries own sockets/netlink and degrade cleanly without privilege. |
| Can **full** telemetry (conntrack + Wi‑Fi + live ICMP) run **inside** LXC? | **Yes only if** the container is granted **host network namespace** (or equivalent device/netlink access) **and** Linux capabilities below. |
| Does today’s **default build artifact** run on u6.3/7u6 as-is? | **No** — current CI/host binaries are **x86_64 glibc PIE**. Field images need **SoC-matched cross-compile** (typically aarch64/musl or vendor SDK) + prpl **LCM / LXC** packaging. |
| Can we ship a **useful** container without low-level host access? | **Yes** — `cpe_agent --once` / `demo.enabled: true` and `forensicsd --demo` need **no** CAP_NET_* and emit valid NDJSON. |

Calix markets EXOS/prpl-aligned gateways with **containerized applications** and lifecycle control; prpl **LCM** uses **LXC** (and increasingly OCI/crun) as the execution environment for add-on services. That matches our dual-daemon model: package the agent as an LCM “execution environment package,” not as a full firmware flash.

---

## What the binaries need from the kernel

### `cpe_agent` (perf NDJSON)

| Mode | Syscalls / kernel APIs | Capability | Works in unprivileged LXC? |
|------|------------------------|------------|----------------------------|
| `demo.enabled: true` (default) | timers, files, stdout; **no** raw net | none | **Yes** |
| `demo.enabled: false` (live ICMP) | `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` preferred | often none if `ping_group_range` allows | **Often yes** with host netns |
| live ICMP fallback | `SOCK_RAW` ICMP | **CAP_NET_RAW** | only if cap kept + host netns |
| `emit.mode=spool` | open/append file under `/var/spool/netforensics` | filesystem mount RW | yes with volume mount |
| `emit.mode=https` | TCP + mbedTLS (optional build) | none beyond normal net | yes with host or routed net |

Code: `agent/live_ping.c`, `agent/agent_core.c`, `deploy/cpe_agent.service`.

### `forensicsd` (NAT / Wi‑Fi NDJSON)

| Mode | Syscalls / kernel APIs | Capability | Works in unprivileged LXC? |
|------|------------------------|------------|----------------------------|
| `--demo` | none privileged | none | **Yes** |
| `--netlink` conntrack | `AF_NETLINK` + `NETLINK_NETFILTER`, ct event groups | **CAP_NET_ADMIN** (or root) | **No** unless privileged + **host netns** |
| `--wifi-if` station dump | `AF_NETLINK` + `NETLINK_GENERIC` / **nl80211** | typically **CAP_NET_ADMIN** | **No** without host wireless netns + nl80211 visible |
| sysctl template `99-forensics.conf` | write `net.netfilter.*` | host root / CAP_SYS_ADMIN path | **Host-side only** (not inside app EE) |

Code: `cpe/forensicsd.c`, `src/nfct_netlink.c`, `src/nl80211_netlink.c`, `cpe/sysctl/99-forensics.conf`.

### Shared design properties that help containers

1. **Syscall-free cores** (`libnetdiag`, libipfix, libyaml parsers) — feed buffers only; no baked-in “must be host PID 1.”
2. **Privilege is explicit** — `--demo` / `demo.enabled` paths never open netlink/raw sockets.
3. **Bounded rings** — spool hard cap 1024; OpenWrt soft 128; systemd `MemoryMax` / procd limits.
4. **No kernel modules** loaded by our code — only existing nf_conntrack / nl80211.
5. **PIE** binaries — relocatable in LXC rootfs.

---

## LXC configuration matrix (recommended)

### Profile A — telemetry EE with full forensics (field target)

Use when the container must see **host** NAT and Wi‑Fi.

```
# Conceptual LXC / prpl EE flags (names vary by LCM backend)
lxc.namespace.share = net          # or: network = host / share netns with host
# Keep user/pid/mount/uts isolated for process isolation
lxc.cap.keep = net_admin net_raw   # or drop nothing for net_admin/raw
# Mounts
lxc.mount.entry = /var/spool/netforensics var/spool/netforensics none bind,create=dir 0 0
# Optional: expose only needed netlink (host netns already does this)
```

| Process | Caps in EE | Notes |
|---------|------------|-------|
| `forensicsd --netlink` | `CAP_NET_ADMIN` | Conntrack + nl80211 |
| `cpe_agent` live probe | `CAP_NET_RAW` if DGRAM ICMP blocked | Prefer DGRAM first |
| both | RW spool volume | Shared F6 path |

**Sysctl** (`nf_conntrack_events=1`, table sizes) must be applied on the **host** (or a privileged init), not assumed inside the EE.

### Profile B — unprivileged app EE (safe default)

```
# Separate network namespace (default LXC)
# No CAP_NET_ADMIN / CAP_NET_RAW
```

| Process | Works? |
|---------|--------|
| `cpe_agent` demo mode → NDJSON | yes |
| `forensicsd --demo` | yes |
| live ICMP / live netlink | **no** (or incomplete) |

Use Profile B for lab CI images and for packaging validation without operator privilege grants.

### Profile C — split: privileged helper + unprivileged agent

- Small **host or privileged** side-car runs `forensicsd --netlink` (or a future netlink shim).
- Unprivileged container runs `cpe_agent` demo/live-if-allowed and only **spools/forwards** NDJSON.
- Aligns with prpl “constrained EE” goals while keeping CAP_NET_ADMIN surface minimal.

---

## Build / packaging gaps for u6.3 / 7u6

| Item | Host lab (current) | Field Calix-class |
|------|--------------------|-------------------|
| ISA | x86_64 | **SoC-specific** (confirm with board: often aarch64) |
| libc | glibc | often **musl** / vendor rootfs |
| init | systemd unit examples | **procd** and/or **prpl LCM (cthulhu-lxc)** |
| package | OpenWrt `opkg` skeleton | LCM **DU/package** + LXC config, not only opkg |
| deps | libuv shared | static link or EE rootfs with libuv |
| kernel | ≥ 5.4 assumed in program design | use **device’s** kernel (containers share host kernel) |

Cross-compile is required before claiming “runs on u6.3.” Containerization does **not** remove the need for the correct ABI.

Suggested CMake flow (illustrative):

```bash
# Example only — replace toolchain file with Calix/prpl SDK or OpenWrt SDK
cmake -B build-arm -S . \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/aarch64-openwrt-linux.cmake \
  -DCPE_AGENT_WITH_HARNESS=OFF \
  -DCPE_AGENT_WITH_LIBSIM=OFF \
  -DCPE_AGENT_WITH_MBEDTLS=ON   # if mbedTLS in EE
cmake --build build-arm
```

OpenWrt package Makefiles under `openwrt/` already target process + caps; for prpl LCM, add an EE descriptor that sets Profile A or B flags above.

---

## Runtime verification checklist (on device or EE)

Run inside the candidate LXC:

```sh
# 1) Demo path (must pass without caps)
cpe_agent --once --router-id lab | grep cpe_perf
forensicsd --demo --router-id lab | grep cpe_nat

# 2) Capability / netns probes
grep CapEff /proc/self/status
ip link show          # expect host ifaces if Profile A
ls /proc/net/nf_conntrack 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count

# 3) Live agent
# demo.enabled: false in yaml
cpe_agent --config /etc/cpe_agent/cpe_agent.yaml

# 4) Live forensics
forensicsd --netlink --router-id lab --wifi-if wlan0
# Expect: no "netlink open failed"; NDJSON on stdout/spool
```

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `netlink open failed` / EPERM | missing CAP_NET_ADMIN or isolated netns | Profile A caps + host netns |
| live ping always timeout / socket fail | no ICMP in netns or no CAP_NET_RAW | host netns; DGRAM or raw cap |
| empty Wi‑Fi metrics | no nl80211 / wrong ifindex in netns | share host net; correct `wifi-if` |
| sysctl ignored | written in container only | apply on host |
| wrong arch exec format | x86_64 binary on aarch64 | cross-build |

---

## Security notes

- Profile A is **powerful**: CAP_NET_ADMIN + host netns ≈ host networking privileges. Treat the EE as a **trusted operator app**, sign LCM packages, and keep attack surface small (no shell if possible).
- Prefer **Profile C** if operator policy forbids privileged app EEs: keep netlink on a tiny host daemon.
- Do not enable `emit.mode=https` client certs without secure EE secret storage (LCM secret / mount).

---

## Concrete package templates (in tree)

| Artifact | Path |
|----------|------|
| LXC Profile A | `deploy/lxc/netforensics-profile-a.conf` |
| LXC Profile B | `deploy/lxc/netforensics-profile-b.conf` |
| prpl LCM manifest | `deploy/prpl-lcm/netforensics-ee/manifest.yaml` |
| OCI-ish config A/B | `deploy/prpl-lcm/netforensics-ee/container-config-profile-*.json` |
| EE entrypoint | `deploy/prpl-lcm/netforensics-ee/files/entrypoint.sh` |
| Stage rootfs | `scripts/stage_lxc_rootfs.sh` |

## aarch64 cross-build path

```bash
./scripts/fetch_bootlin_aarch64.sh          # musl toolchain → ~/toolchains
./scripts/cross_build_aarch64.sh            # build-aarch64/{cpe_agent,forensicsd}
DEST=deploy/prpl-lcm/netforensics-ee/rootfs \
  ./scripts/stage_lxc_rootfs.sh build-aarch64
```

CMake toolchains: `cmake/toolchains/aarch64-bootlin.cmake`,
`aarch64-linux-gnu.cmake`, `openwrt-generic.cmake`. Field profile uses the
**poll loop** when libuv is not in the sysroot (`agent_loop_poll.c`).

## Conclusion

1. **Architecture**: already container-ready (demo paths + optional privilege).
2. **Full forensics in LXC**: supported **if and only if** low-level host networking is exposed (host netns + CAP_NET_ADMIN / CAP_NET_RAW as above).
3. **Calix u6.3 / 7u6**: expect prpl/EXOS-style LXC LCM; package templates ship under `deploy/`.
4. **Cross-build**: Bootlin aarch64 musl path verified on CI host; swap OpenWrt SDK via `openwrt-generic.cmake` when available.

Related ADRs: [001](../decisions/001-libraries-own-parsing.md), [002](../decisions/002-ndjson-to-vector.md), [004](../decisions/004-cpe-agent-tls-mbedtls.md), [008](../decisions/008-field-live-icmp-mtls-spool.md), [009](../decisions/009-lxc-prpl-host-privileges.md).
