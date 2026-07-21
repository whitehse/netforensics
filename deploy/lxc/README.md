# LXC configs for netforensics CPE EE

| File | Profile | Network | Caps |
|------|---------|---------|------|
| `netforensics-profile-a.conf` | A (live) | **share host** | NET_ADMIN, NET_RAW |
| `netforensics-profile-b.conf` | B (demo) | isolated | none of the above |

See also:

- `../prpl-lcm/netforensics-ee/` — prpl LCM / OCI-style packaging
- `../../docs/guides/lxc-prpl-containerization.md`

## Quick path

```bash
./scripts/fetch_bootlin_aarch64.sh
./scripts/cross_build_aarch64.sh
DEST=deploy/prpl-lcm/netforensics-ee/rootfs \
  ./scripts/stage_lxc_rootfs.sh build-aarch64

# Point profile-a rootfs.path at the staged tree (or copy to /srv/lxc/...)
# Then on device (privileged host):
#   lxc-start -n netforensics -f deploy/lxc/netforensics-profile-a.conf
```
