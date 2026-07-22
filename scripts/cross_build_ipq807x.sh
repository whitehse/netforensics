#!/usr/bin/env bash
# Cross-build netforensics CPE agent for Qualcomm IPQ807x OpenWrt boards.
#
# Variants:
#   ipq807x / ipq807x_64  → aarch64 musl  (OpenWrt qualcommax/ipq807x)
#   ipq807x_32            → armv7-eabihf musl (arm_cortex-a7_neon-vfpv4 ABI)
#
# Usage:
#   ./scripts/cross_build_ipq807x.sh              # both (default)
#   ./scripts/cross_build_ipq807x.sh --32         # ipq807x_32 only
#   ./scripts/cross_build_ipq807x.sh --64         # aarch64 only
#   ./scripts/cross_build_ipq807x.sh --fetch      # download missing toolchains
#   ./scripts/cross_build_ipq807x.sh --32 --fetch
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD32="${BUILD_DIR_32:-${ROOT}/build-ipq807x_32}"
BUILD64="${BUILD_DIR_64:-${ROOT}/build-ipq807x}"
FETCH=0
DO32=1
DO64=1

for arg in "$@"; do
  case "$arg" in
    --fetch) FETCH=1 ;;
    --32|--ipq807x_32) DO32=1; DO64=0 ;;
    --64|--ipq807x|--ipq807x_64) DO32=0; DO64=1 ;;
    --both) DO32=1; DO64=1 ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 1
      ;;
  esac
done

# If both flags were set by repeating --32/--64, allow --both or default both.
# Re-scan: last exclusive flag wins unless --both was used. Already handled above
# when only one exclusive flag is given; default is both.

field_cmake() {
  local build="$1" toolchain_file="$2"
  shift 2
  rm -rf "${build}/CMakeCache.txt" "${build}/CMakeFiles" 2>/dev/null || true
  cmake -B "${build}" -S "${ROOT}" \
    -DCMAKE_TOOLCHAIN_FILE="${toolchain_file}" \
    -DCPE_AGENT_FIELD=ON \
    -DCPE_AGENT_WITH_HARNESS=OFF \
    -DCPE_AGENT_WITH_LIBSIM=OFF \
    -DCPE_AGENT_WITH_MBEDTLS=OFF \
    -DCPE_AGENT_WITH_LIBUV=OFF \
    -DCPE_AGENT_WITH_LUA=ON \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DBUILD_TESTING=OFF \
    "$@"
  cmake --build "${build}" -j"$(nproc 2>/dev/null || echo 2)" \
    --target cpe_agent
  # Strip for flash budgets (keep unstripped in build tree copy if strip fails)
  if command -v "${STRIP:-}" >/dev/null 2>&1; then
    :
  fi
  local strip_bin=""
  # Prefer toolchain strip when present next to gcc
  if [[ -n "${CMAKE_C_COMPILER:-}" && -x "${CMAKE_C_COMPILER%gcc}strip" ]]; then
    strip_bin="${CMAKE_C_COMPILER%gcc}strip"
  fi
  # Discover strip from build dir's linked compiler via file path heuristics
  if [[ -z "${strip_bin}" ]]; then
    for s in "${HOME}"/toolchains/*/bin/*-strip; do
      if [[ -x "$s" ]]; then
        # match arch of this build by checking binary later; try any that work
        if "$s" --version >/dev/null 2>&1; then
          strip_bin="$s"
          # Prefer matching arch name if possible
          if echo "$s" | grep -qi arm && echo "${build}" | grep -qi '32\|arm'; then
            break
          fi
          if echo "$s" | grep -qi aarch64 && echo "${build}" | grep -qi 'ipq807x$\|aarch64\|build-ipq807x$'; then
            break
          fi
        fi
      fi
    done
  fi
  if [[ -n "${strip_bin}" && -x "${build}/cpe_agent" ]]; then
    "${strip_bin}" "${build}/cpe_agent" 2>/dev/null || true
  fi
}

verify_field_bin() {
  local path="$1" label="$2" expect_machine="$3" expect_static="${4:-0}"
  [[ -x "${path}" ]] || { echo "error: missing ${path}" >&2; exit 1; }
  local info
  info=$(file "${path}")
  echo "  ${label}: ${info}"

  if [[ "${expect_static}" -eq 1 ]]; then
    if ! echo "${info}" | grep -qi 'statically linked'; then
      echo "error: ${label} must be statically linked for OpenWrt time64 compat:" >&2
      echo "  ${info}" >&2
      exit 1
    fi
    # No dynamic time64 deps allowed
    if nm -D "${path}" 2>/dev/null | grep -qE '__nanosleep_time64|__clock_gettime64|__gmtime64'; then
      echo "error: ${label} still has dynamic time64 undefs" >&2
      nm -D "${path}" 2>/dev/null | grep -E 'time64| U ' | head -20 >&2
      exit 1
    fi
  else
    if ! echo "${info}" | grep -qi musl; then
      echo "error: ${label} is not musl-linked:" >&2
      echo "  ${info}" >&2
      exit 1
    fi
  fi

  if command -v readelf >/dev/null 2>&1; then
    local interp machine class
    interp=$(readelf -l "${path}" 2>/dev/null | awk '/Requesting program interpreter/ {print $NF}' | tr -d ']')
    machine=$(readelf -h "${path}" 2>/dev/null | awk '/Machine:/ {$1=""; print}' | xargs)
    class=$(readelf -h "${path}" 2>/dev/null | awk '/Class:/ {print $2}')
    echo "    ELF ${class}  Machine=${machine}  interp=${interp:-none (static)}"
    if [[ "${expect_static}" -eq 0 && -n "${interp}" && "${interp}" != *musl* ]]; then
      echo "error: interpreter is not musl: ${interp}" >&2
      exit 1
    fi
    if [[ -n "${expect_machine}" ]] && ! echo "${machine}" | grep -qi "${expect_machine}"; then
      echo "error: expected Machine ~ ${expect_machine}, got: ${machine}" >&2
      exit 1
    fi
  fi
}

pick_bootlin() {
  local pattern="$1"
  local c
  if [[ -n "${BOOTLIN_TOOLCHAIN:-}" && -d "${BOOTLIN_TOOLCHAIN}" ]]; then
    echo "${BOOTLIN_TOOLCHAIN}"
    return 0
  fi
  for c in ${HOME}/toolchains/${pattern}; do
    if [[ -d "$c" && -d "$c/bin" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

echo "=== IPQ807x CPE agent field build ==="
echo "  32-bit (ipq807x_32): $([[ ${DO32} -eq 1 ]] && echo yes || echo no)"
echo "  64-bit (ipq807x):    $([[ ${DO64} -eq 1 ]] && echo yes || echo no)"
echo

if [[ "${DO32}" -eq 1 ]]; then
  if [[ "${FETCH}" -eq 1 ]] || ! pick_bootlin 'armv7-eabihf--musl--*' >/dev/null 2>&1; then
    if [[ "${FETCH}" -eq 1 ]] || [[ ! -d "${HOME}/toolchains"/armv7-eabihf--musl--* ]]; then
      BOOTLIN_VARIANT=musl "${ROOT}/scripts/fetch_bootlin_armv7.sh"
    fi
  fi
  tc32=$(pick_bootlin 'armv7-eabihf--musl--*') || {
    echo "No armv7-eabihf musl toolchain. Run:" >&2
    echo "  ./scripts/fetch_bootlin_armv7.sh" >&2
    echo "  or: ./scripts/cross_build_ipq807x.sh --32 --fetch" >&2
    exit 1
  }
  echo "ipq807x_32 toolchain: ${tc32}"
  echo "  (static musl — avoids OpenWrt missing __*time64 symbols)"
  field_cmake "${BUILD32}" \
    "${ROOT}/cmake/toolchains/armv7-eabihf-bootlin.cmake" \
    -DBOOTLIN_TOOLCHAIN="${tc32}" \
    -DCPE_AGENT_STATIC=ON
  # Use matching strip
  STRIP32="${tc32}/bin/arm-buildroot-linux-musleabihf-strip"
  [[ -x "${STRIP32}" ]] && "${STRIP32}" "${BUILD32}/cpe_agent" || true
  echo
  verify_field_bin "${BUILD32}/cpe_agent" "ipq807x_32 cpe_agent" "ARM" 1
  mkdir -p "${ROOT}/deploy/ipq807x_32"
  cp -f "${BUILD32}/cpe_agent" "${ROOT}/deploy/ipq807x_32/cpe_agent"
  echo "Staged: deploy/ipq807x_32/cpe_agent"
  echo
fi

if [[ "${DO64}" -eq 1 ]]; then
  if [[ "${FETCH}" -eq 1 ]] || ! pick_bootlin 'aarch64--musl--*' >/dev/null 2>&1; then
    if ! pick_bootlin 'aarch64--musl--*' >/dev/null 2>&1; then
      BOOTLIN_VARIANT=musl "${ROOT}/scripts/fetch_bootlin_aarch64.sh"
    fi
  fi
  tc64=$(pick_bootlin 'aarch64--musl--*') || {
    echo "No aarch64 musl toolchain. Run:" >&2
    echo "  ./scripts/fetch_bootlin_aarch64.sh" >&2
    echo "  or: ./scripts/cross_build_ipq807x.sh --64 --fetch" >&2
    exit 1
  }
  echo "ipq807x (aarch64) toolchain: ${tc64}"
  field_cmake "${BUILD64}" \
    "${ROOT}/cmake/toolchains/aarch64-bootlin.cmake" \
    -DBOOTLIN_TOOLCHAIN="${tc64}"
  STRIP64="${tc64}/bin/aarch64-buildroot-linux-musl-strip"
  [[ -x "${STRIP64}" ]] && "${STRIP64}" "${BUILD64}/cpe_agent" || true
  echo
  verify_field_bin "${BUILD64}/cpe_agent" "ipq807x cpe_agent" "AArch64" 0
  mkdir -p "${ROOT}/deploy/ipq807x"
  cp -f "${BUILD64}/cpe_agent" "${ROOT}/deploy/ipq807x/cpe_agent"
  echo "Staged: deploy/ipq807x/cpe_agent"
  echo
fi

echo "IPQ807x field build OK"
echo "Artifacts:"
if [[ "${DO32}" -eq 1 ]]; then
  ls -la "${BUILD32}/cpe_agent" "${ROOT}/deploy/ipq807x_32/cpe_agent"
fi
if [[ "${DO64}" -eq 1 ]]; then
  ls -la "${BUILD64}/cpe_agent" "${ROOT}/deploy/ipq807x/cpe_agent"
fi
