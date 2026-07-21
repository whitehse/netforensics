# OpenWrt SDK / staging_dir external toolchain.
#
# Required env or cache vars:
#   STAGING_DIR   — OpenWrt staging_dir (e.g. .../staging_dir/target-aarch64_...)
#   TOOLCHAIN_DIR — .../staging_dir/toolchain-aarch64_...
#
# cmake -B build-owrt -S . \
#   -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/openwrt-generic.cmake \
#   -DSTAGING_DIR=$HOME/openwrt/staging_dir/target-... \
#   -DTOOLCHAIN_DIR=$HOME/openwrt/staging_dir/toolchain-... \
#   -DCPE_AGENT_FIELD=ON

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

if(DEFINED ENV{STAGING_DIR} AND NOT STAGING_DIR)
    set(STAGING_DIR "$ENV{STAGING_DIR}")
endif()
if(DEFINED ENV{TOOLCHAIN_DIR} AND NOT TOOLCHAIN_DIR)
    set(TOOLCHAIN_DIR "$ENV{TOOLCHAIN_DIR}")
endif()

if(NOT STAGING_DIR OR NOT EXISTS "${STAGING_DIR}")
    message(FATAL_ERROR "Set -DSTAGING_DIR=... to OpenWrt target staging_dir")
endif()
if(NOT TOOLCHAIN_DIR OR NOT EXISTS "${TOOLCHAIN_DIR}")
    message(FATAL_ERROR "Set -DTOOLCHAIN_DIR=... to OpenWrt toolchain dir")
endif()

file(GLOB _cc "${TOOLCHAIN_DIR}/bin/*-openwrt-linux*-gcc"
              "${TOOLCHAIN_DIR}/bin/*-openwrt-linux-gcc"
              "${TOOLCHAIN_DIR}/bin/*-linux-gcc")
list(LENGTH _cc _n)
if(_n EQUAL 0)
    message(FATAL_ERROR "No OpenWrt gcc under ${TOOLCHAIN_DIR}/bin")
endif()
list(GET _cc 0 CMAKE_C_COMPILER)

set(CMAKE_FIND_ROOT_PATH "${STAGING_DIR}" "${TOOLCHAIN_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(ENV{PKG_CONFIG_SYSROOT_DIR} "${STAGING_DIR}")
set(ENV{PKG_CONFIG_LIBDIR}
    "${STAGING_DIR}/usr/lib/pkgconfig:${STAGING_DIR}/usr/share/pkgconfig")

set(CPE_AGENT_FIELD ON CACHE BOOL "Field build defaults" FORCE)
