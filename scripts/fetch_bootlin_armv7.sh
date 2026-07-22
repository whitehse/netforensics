#!/usr/bin/env bash
# Download a Bootlin armv7-eabihf **musl** toolchain into $HOME/toolchains (no root).
# Field default for OpenWrt-class **ipq807x_32** (arm_cortex-a7_neon-vfpv4 ABI).
#
# Override:
#   BOOTLIN_VARIANT=glibc   # not for field musl boards
#   BOOTLIN_RELEASE=stable-2025.08-1
#   DEST=$HOME/toolchains
set -euo pipefail

VARIANT="${BOOTLIN_VARIANT:-musl}"
RELEASE="${BOOTLIN_RELEASE:-stable-2025.08-1}"
DEST="${DEST:-${HOME}/toolchains}"
ARCH="armv7-eabihf"
NAME="${ARCH}--${VARIANT}--${RELEASE}"
URL="https://toolchains.bootlin.com/downloads/releases/toolchains/${ARCH}/tarballs/${NAME}.tar.xz"
TARBALL="${DEST}/${NAME}.tar.xz"

if [[ "${VARIANT}" != "musl" ]]; then
  echo "WARNING: VARIANT=${VARIANT} — field boards are musl. Prefer default." >&2
fi

mkdir -p "${DEST}"
if [[ -d "${DEST}/${NAME}" && -x "${DEST}/${NAME}/bin"/*-gcc ]]; then
  echo "Already present: ${DEST}/${NAME}"
  echo "export BOOTLIN_TOOLCHAIN=${DEST}/${NAME}"
  exit 0
fi

echo "Fetching ${URL}"
if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 -o "${TARBALL}" "${URL}"
else
  wget -O "${TARBALL}" "${URL}"
fi

echo "Extracting to ${DEST}"
tar -C "${DEST}" -xf "${TARBALL}"
if [[ ! -d "${DEST}/${NAME}" ]]; then
  top=$(tar -tf "${TARBALL}" | head -1 | cut -d/ -f1)
  if [[ -n "${top}" && -d "${DEST}/${top}" && "${top}" != "${NAME}" ]]; then
    mv "${DEST}/${top}" "${DEST}/${NAME}"
  fi
fi

GCC=$(echo "${DEST}/${NAME}"/bin/*-linux-*-gcc)
if [[ ! -x ${GCC} ]]; then
  echo "error: gcc not found after extract" >&2
  exit 1
fi
echo "OK: ${GCC}"
echo "export BOOTLIN_TOOLCHAIN=${DEST}/${NAME}"
echo "Field ABI: armv7-eabihf + ${VARIANT} (ipq807x_32 / arm_cortex-a7_neon-vfpv4)"
echo "  interpreter /lib/ld-musl-armhf.so.1 (musl hard-float)"
