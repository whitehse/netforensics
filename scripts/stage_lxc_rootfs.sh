#!/usr/bin/env bash
# Populate an LXC / prpl LCM rootfs tree from a build directory.
# Usage:
#   DEST=deploy/prpl-lcm/netforensics-ee/rootfs ./scripts/stage_lxc_rootfs.sh build-aarch64
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-${ROOT}/build-aarch64}"
DEST="${DEST:-${ROOT}/deploy/prpl-lcm/netforensics-ee/rootfs}"

if [[ ! -x "${BUILD}/cpe_agent" && ! -x "${BUILD}/forensicsd" ]]; then
  echo "error: no binaries in ${BUILD} (run cross_build_aarch64.sh first)" >&2
  exit 1
fi

rm -rf "${DEST}"
mkdir -p \
  "${DEST}/usr/sbin" \
  "${DEST}/etc/cpe_agent" \
  "${DEST}/etc/sysctl.d" \
  "${DEST}/etc/init.d" \
  "${DEST}/var/spool/netforensics" \
  "${DEST}/etc/netforensics"

install -m 0755 "${BUILD}/cpe_agent" "${DEST}/usr/sbin/cpe_agent" 2>/dev/null || true
install -m 0755 "${BUILD}/forensicsd" "${DEST}/usr/sbin/forensicsd" 2>/dev/null || true

install -m 0644 "${ROOT}/openwrt/cpe-agent/files/cpe_agent.yaml" \
  "${DEST}/etc/cpe_agent/cpe_agent.yaml"
# Field profile defaults: enable live probe when EE has host net
if grep -q 'enabled: true' "${DEST}/etc/cpe_agent/cpe_agent.yaml"; then
  sed -i 's/enabled: true/enabled: false/' "${DEST}/etc/cpe_agent/cpe_agent.yaml" || true
fi

install -m 0644 "${ROOT}/cpe/sysctl/99-forensics.conf" \
  "${DEST}/etc/sysctl.d/99-forensics.conf"
# Sysctl is host-applied; keep a copy for docs inside EE
install -m 0644 "${ROOT}/cpe/sysctl/99-forensics.conf" \
  "${DEST}/etc/netforensics/99-forensics.conf.HOST_APPLY"

install -m 0755 "${ROOT}/openwrt/cpe-agent/files/cpe_agent.init" \
  "${DEST}/etc/init.d/cpe_agent"
install -m 0755 "${ROOT}/openwrt/netforensics/files/forensicsd.init" \
  "${DEST}/etc/init.d/forensicsd"
install -m 0755 "${ROOT}/deploy/prpl-lcm/netforensics-ee/files/entrypoint.sh" \
  "${DEST}/usr/sbin/netforensics-entrypoint"

# Minimal /etc/passwd for unprivileged shells (optional)
if [[ ! -f "${DEST}/etc/passwd" ]]; then
  printf 'root:x:0:0:root:/root:/bin/sh\n' > "${DEST}/etc/passwd"
fi

echo "Staged rootfs: ${DEST}"
find "${DEST}" -type f | sort
