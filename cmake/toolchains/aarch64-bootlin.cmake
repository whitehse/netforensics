# Bootlin prebuilt aarch64 toolchain — **musl is the field default**
# (Calix u6.3 / 7u6 / prpl OpenWrt-class boards).
#
# Expected layout after scripts/fetch_bootlin_aarch64.sh:
#   $ENV{HOME}/toolchains/aarch64--musl--stable-*/bin/*-gcc
#
# Override:
#   -DBOOTLIN_TOOLCHAIN=/path/to/aarch64--musl--stable-...
#
# cmake -B build-aarch64 -S . \
#   -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-bootlin.cmake \
#   -DCPE_AGENT_FIELD=ON

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

if(NOT DEFINED BOOTLIN_TOOLCHAIN OR BOOTLIN_TOOLCHAIN STREQUAL "")
    if(DEFINED ENV{BOOTLIN_TOOLCHAIN} AND NOT "$ENV{BOOTLIN_TOOLCHAIN}" STREQUAL "")
        set(BOOTLIN_TOOLCHAIN "$ENV{BOOTLIN_TOOLCHAIN}")
    else()
        # Field boards are musl — never auto-pick glibc or .tar.xz archives.
        file(GLOB _bootlin_candidates "$ENV{HOME}/toolchains/aarch64--musl--*")
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
        "Bootlin musl toolchain not found. Run scripts/fetch_bootlin_aarch64.sh "
        "or set -DBOOTLIN_TOOLCHAIN=/path/to/aarch64--musl--...")
endif()

get_filename_component(BOOTLIN_TOOLCHAIN "${BOOTLIN_TOOLCHAIN}" ABSOLUTE)
if(NOT IS_DIRECTORY "${BOOTLIN_TOOLCHAIN}")
    message(FATAL_ERROR
        "BOOTLIN_TOOLCHAIN is not a directory (is a tarball selected?): "
        "${BOOTLIN_TOOLCHAIN}")
endif()
message(STATUS "Bootlin toolchain (musl field): ${BOOTLIN_TOOLCHAIN}")
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

set(CMAKE_FIND_ROOT_PATH
    "${BOOTLIN_TOOLCHAIN}/aarch64-buildroot-linux-musl/sysroot"
    "${BOOTLIN_TOOLCHAIN}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Field cross builds: no host libuv for aarch64 — use poll loop.
set(CPE_AGENT_FIELD ON CACHE BOOL "Field build: no harness/sim; libuv optional" FORCE)
set(CPE_AGENT_WITH_LIBUV OFF CACHE BOOL "No libuv on Bootlin field cross" FORCE)
