#!/usr/bin/env bash
# Download a Bootlin aarch64 musl toolchain into $HOME/toolchains (no root).
# Override:
#   BOOTLIN_VARIANT=glibc|musl (default musl)
#   BOOTLIN_RELEASE=stable-2025.08-1
#   DEST=$HOME/toolchains
set -euo pipefail

VARIANT="${BOOTLIN_VARIANT:-musl}"
RELEASE="${BOOTLIN_RELEASE:-stable-2025.08-1}"
DEST="${DEST:-${HOME}/toolchains}"
NAME="aarch64--${VARIANT}--${RELEASE}"
URL="https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/tarballs/${NAME}.tar.xz"
TARBALL="${DEST}/${NAME}.tar.xz"

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
# Bootlin tarballs usually extract to aarch64--variant--release/
if [[ ! -d "${DEST}/${NAME}" ]]; then
  # fallback: single top-level dir
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
