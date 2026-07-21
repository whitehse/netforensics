#!/usr/bin/env bash
# Cross-build netforensics for aarch64 (field profile).
#
# Modes (first matching):
#   1) BOOTLIN_TOOLCHAIN or ~/toolchains/aarch64--*  → Bootlin
#   2) aarch64-linux-gnu-gcc on PATH                 → Debian cross
#   3) STAGING_DIR + TOOLCHAIN_DIR                   → OpenWrt SDK
#
# Usage:
#   ./scripts/fetch_bootlin_aarch64.sh
#   ./scripts/cross_build_aarch64.sh
#   ./scripts/cross_build_aarch64.sh --fetch   # download toolchain first
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-${ROOT}/build-aarch64}"
FETCH=0
for arg in "$@"; do
  case "$arg" in
    --fetch) FETCH=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
  esac
done

if [[ "${FETCH}" -eq 1 ]]; then
  "${ROOT}/scripts/fetch_bootlin_aarch64.sh"
fi

TOOLCHAIN_FILE=""
EXTRA=()

if [[ -n "${BOOTLIN_TOOLCHAIN:-}" && -d "${BOOTLIN_TOOLCHAIN}" ]]; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/aarch64-bootlin.cmake"
  EXTRA+=(-DBOOTLIN_TOOLCHAIN="${BOOTLIN_TOOLCHAIN}")
elif compgen -G "${HOME}/toolchains/aarch64--*" >/dev/null; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/aarch64-bootlin.cmake"
elif command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/aarch64-linux-gnu.cmake"
elif [[ -n "${STAGING_DIR:-}" && -n "${TOOLCHAIN_DIR:-}" ]]; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/openwrt-generic.cmake"
  EXTRA+=(-DSTAGING_DIR="${STAGING_DIR}" -DTOOLCHAIN_DIR="${TOOLCHAIN_DIR}")
else
  echo "No aarch64 toolchain found." >&2
  echo "  ./scripts/fetch_bootlin_aarch64.sh   # recommended (no root)" >&2
  echo "  or: apt install gcc-aarch64-linux-gnu" >&2
  echo "  or: set STAGING_DIR + TOOLCHAIN_DIR for OpenWrt SDK" >&2
  exit 1
fi

echo "Using toolchain file: ${TOOLCHAIN_FILE}"
# Wipe stale host-libuv cache when reconfiguring
rm -rf "${BUILD}/CMakeCache.txt" "${BUILD}/CMakeFiles" 2>/dev/null || true

cmake -B "${BUILD}" -S "${ROOT}" \
  -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
  -DCPE_AGENT_FIELD=ON \
  -DCPE_AGENT_WITH_HARNESS=OFF \
  -DCPE_AGENT_WITH_LIBSIM=OFF \
  -DCPE_AGENT_WITH_MBEDTLS=OFF \
  -DCPE_AGENT_WITH_LIBUV=OFF \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DBUILD_TESTING=OFF \
  "${EXTRA[@]}"

cmake --build "${BUILD}" -j"$(nproc 2>/dev/null || echo 2)" \
  --target forensicsd cpe_agent

echo
echo "Artifacts:"
file "${BUILD}/forensicsd" "${BUILD}/cpe_agent" 2>/dev/null || true
readelf -h "${BUILD}/cpe_agent" 2>/dev/null | grep -E 'Machine|Class' || true
echo
echo "Stage into LXC rootfs:"
echo "  DEST=./deploy/prpl-lcm/netforensics-ee/rootfs ./scripts/stage_lxc_rootfs.sh ${BUILD}"
