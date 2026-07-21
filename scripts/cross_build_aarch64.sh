#!/usr/bin/env bash
# Cross-build netforensics for aarch64 **musl** (field profile).
#
# Field boards (Calix u6.3 / 7u6 class, prpl/OpenWrt) are musl-based.
# Default path: Bootlin aarch64--musl. Do not use Debian aarch64-linux-gnu
# (glibc) for field images unless you explicitly pass --allow-glibc.
#
# Modes (first matching):
#   1) BOOTLIN_TOOLCHAIN or ~/toolchains/aarch64--musl--*  → Bootlin musl
#   2) STAGING_DIR + TOOLCHAIN_DIR                         → OpenWrt SDK (musl)
#   3) --allow-glibc + aarch64-linux-gnu-gcc               → lab only
#
# Usage:
#   ./scripts/fetch_bootlin_aarch64.sh
#   ./scripts/cross_build_aarch64.sh
#   ./scripts/cross_build_aarch64.sh --fetch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-${ROOT}/build-aarch64}"
FETCH=0
ALLOW_GLIBC=0
for arg in "$@"; do
  case "$arg" in
    --fetch) FETCH=1 ;;
    --allow-glibc) ALLOW_GLIBC=1 ;;
    -h|--help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
  esac
done

if [[ "${FETCH}" -eq 1 ]]; then
  BOOTLIN_VARIANT=musl "${ROOT}/scripts/fetch_bootlin_aarch64.sh"
fi

TOOLCHAIN_FILE=""
EXTRA=()
EXPECT_MUSL=1

pick_musl_bootlin() {
  local c
  if [[ -n "${BOOTLIN_TOOLCHAIN:-}" && -d "${BOOTLIN_TOOLCHAIN}" ]]; then
    if [[ "${BOOTLIN_TOOLCHAIN}" == *musl* ]] || [[ "${ALLOW_GLIBC}" -eq 1 ]]; then
      echo "${BOOTLIN_TOOLCHAIN}"
      return 0
    fi
    echo "error: BOOTLIN_TOOLCHAIN is not musl: ${BOOTLIN_TOOLCHAIN}" >&2
    echo "  Field boards are musl. Use aarch64--musl--* or pass --allow-glibc." >&2
    return 1
  fi
  # Prefer musl only
  for c in "${HOME}"/toolchains/aarch64--musl--*; do
    if [[ -d "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

if musl_tc=$(pick_musl_bootlin 2>/dev/null); then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/aarch64-bootlin.cmake"
  EXTRA+=(-DBOOTLIN_TOOLCHAIN="${musl_tc}")
  echo "Field toolchain (musl): ${musl_tc}"
elif [[ -n "${STAGING_DIR:-}" && -n "${TOOLCHAIN_DIR:-}" ]]; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/openwrt-generic.cmake"
  EXTRA+=(-DSTAGING_DIR="${STAGING_DIR}" -DTOOLCHAIN_DIR="${TOOLCHAIN_DIR}")
  echo "OpenWrt SDK (expect musl on board): STAGING_DIR=${STAGING_DIR}"
elif [[ "${ALLOW_GLIBC}" -eq 1 ]] && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  TOOLCHAIN_FILE="${ROOT}/cmake/toolchains/aarch64-linux-gnu.cmake"
  EXPECT_MUSL=0
  echo "WARNING: building with glibc cross (--allow-glibc). Not for field musl boards." >&2
else
  echo "No aarch64 musl toolchain found." >&2
  echo "  ./scripts/fetch_bootlin_aarch64.sh   # Bootlin musl (recommended)" >&2
  echo "  or: set STAGING_DIR + TOOLCHAIN_DIR for OpenWrt musl SDK" >&2
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

# Enforce musl for field builds
for bin in cpe_agent forensicsd; do
  path="${BUILD}/${bin}"
  [[ -x "${path}" ]] || continue
  info=$(file "${path}")
  if [[ "${EXPECT_MUSL}" -eq 1 ]]; then
    if ! echo "${info}" | grep -qi musl; then
      echo "error: ${bin} is not musl-linked (board requires musl):" >&2
      echo "  ${info}" >&2
      exit 1
    fi
    # Interpreter check when readelf available
    if command -v readelf >/dev/null 2>&1; then
      interp=$(readelf -l "${path}" 2>/dev/null | awk '/Requesting program interpreter/ {print $NF}' | tr -d ']')
      if [[ -n "${interp}" && "${interp}" != *musl* ]]; then
        echo "error: ${bin} interpreter is not musl: ${interp}" >&2
        exit 1
      fi
    fi
  fi
done

echo
echo "musl aarch64 field build OK"
echo "Stage into LXC rootfs:"
echo "  DEST=./deploy/prpl-lcm/netforensics-ee/rootfs ./scripts/stage_lxc_rootfs.sh ${BUILD}"
