# Bootlin prebuilt armv7-eabihf toolchain — **musl field default**
# for OpenWrt-class **ipq807x_32** (package arch arm_cortex-a7_neon-vfpv4).
#
# Expected layout after scripts/fetch_bootlin_armv7.sh:
#   $ENV{HOME}/toolchains/armv7-eabihf--musl--stable-*/bin/*-gcc
#
# Override:
#   -DBOOTLIN_TOOLCHAIN=/path/to/armv7-eabihf--musl--stable-...
#
# cmake -B build-ipq807x_32 -S . \
#   -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/armv7-eabihf-bootlin.cmake \
#   -DCPE_AGENT_FIELD=ON

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

if(NOT DEFINED BOOTLIN_TOOLCHAIN OR BOOTLIN_TOOLCHAIN STREQUAL "")
    if(DEFINED ENV{BOOTLIN_TOOLCHAIN} AND NOT "$ENV{BOOTLIN_TOOLCHAIN}" STREQUAL "")
        set(BOOTLIN_TOOLCHAIN "$ENV{BOOTLIN_TOOLCHAIN}")
    else()
        file(GLOB _bootlin_candidates "$ENV{HOME}/toolchains/armv7-eabihf--musl--*")
        list(SORT _bootlin_candidates)
        list(REVERSE _bootlin_candidates)
        foreach(_c IN LISTS _bootlin_candidates)
            if(IS_DIRECTORY "${_c}" AND EXISTS "${_c}/bin")
                set(BOOTLIN_TOOLCHAIN "${_c}")
                break()
            endif()
        endforeach()
    endif()
endif()

if(NOT BOOTLIN_TOOLCHAIN OR NOT EXISTS "${BOOTLIN_TOOLCHAIN}")
    message(FATAL_ERROR
        "Bootlin armv7-eabihf musl toolchain not found. "
        "Run scripts/fetch_bootlin_armv7.sh "
        "or set -DBOOTLIN_TOOLCHAIN=/path/to/armv7-eabihf--musl--...")
endif()

get_filename_component(BOOTLIN_TOOLCHAIN "${BOOTLIN_TOOLCHAIN}" ABSOLUTE)
if(NOT IS_DIRECTORY "${BOOTLIN_TOOLCHAIN}")
    message(FATAL_ERROR
        "BOOTLIN_TOOLCHAIN is not a directory (is a tarball selected?): "
        "${BOOTLIN_TOOLCHAIN}")
endif()
message(STATUS "Bootlin toolchain (ipq807x_32 musl): ${BOOTLIN_TOOLCHAIN}")
if(NOT BOOTLIN_TOOLCHAIN MATCHES "musl")
    message(WARNING
        "BOOTLIN_TOOLCHAIN path does not contain 'musl': ${BOOTLIN_TOOLCHAIN}. "
        "Field boards are musl-based; glibc binaries will not run there.")
endif()

file(GLOB _cc "${BOOTLIN_TOOLCHAIN}/bin/*-linux-*-gcc")
file(GLOB _cxx "${BOOTLIN_TOOLCHAIN}/bin/*-linux-*-g++")
list(LENGTH _cc _cc_n)
if(_cc_n EQUAL 0)
    message(FATAL_ERROR "No *-gcc under ${BOOTLIN_TOOLCHAIN}/bin")
endif()
list(GET _cc 0 CMAKE_C_COMPILER)
if(_cxx)
    list(GET _cxx 0 CMAKE_CXX_COMPILER)
endif()

# OpenWrt arm_cortex-a7_neon-vfpv4 ABI flags (compatible with A53 AArch32).
set(CMAKE_C_FLAGS_INIT "-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard")
set(CMAKE_CXX_FLAGS_INIT "-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard")

# Sysroot name varies slightly by Bootlin release
file(GLOB _sysroots
    "${BOOTLIN_TOOLCHAIN}/arm-buildroot-linux-musleabihf/sysroot"
    "${BOOTLIN_TOOLCHAIN}/armv7-eabihf-buildroot-linux-musleabihf/sysroot")
if(_sysroots)
    list(GET _sysroots 0 _sysroot)
    set(CMAKE_FIND_ROOT_PATH "${_sysroot}" "${BOOTLIN_TOOLCHAIN}")
else()
    set(CMAKE_FIND_ROOT_PATH "${BOOTLIN_TOOLCHAIN}")
endif()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Field cross builds: no host libuv — use poll loop.
set(CPE_AGENT_FIELD ON CACHE BOOL "Field build: no harness/sim; libuv optional" FORCE)
set(CPE_AGENT_WITH_LIBUV OFF CACHE BOOL "No libuv on Bootlin field cross" FORCE)

# Static-link musl by default for ipq807x_32.
#
# Bootlin musl 1.2.x on 32-bit redirects time APIs to __*time64 symbols
# (nanosleep → __nanosleep_time64, etc.). Many OpenWrt / QSDK boards ship an
# older musl that only exports nanosleep / clock_gettime / gmtime_r, which
# produces: "Error relocating ./cpe_agent: __nanosleep_time64: symbol not found".
# A fully static binary carries its own libc and runs on those boards.
#
# Override: -DCPE_AGENT_STATIC=OFF (only if the board musl is ≥ the toolchain).
if(NOT DEFINED CPE_AGENT_STATIC)
    set(CPE_AGENT_STATIC ON CACHE BOOL "Static-link cpe_agent (recommended for ipq807x_32)")
endif()
if(CPE_AGENT_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    message(STATUS "ipq807x_32: static musl link (avoids board time64 ABI mismatch)")
endif()
