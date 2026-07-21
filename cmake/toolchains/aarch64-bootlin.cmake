# Bootlin prebuilt aarch64 toolchain (glibc or musl).
# Expected layout after scripts/fetch_bootlin_aarch64.sh:
#   $ENV{HOME}/toolchains/aarch64--*/bin/*-gcc
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
        file(GLOB _bootlin_candidates
            "$ENV{HOME}/toolchains/aarch64--musl--*"
            "$ENV{HOME}/toolchains/aarch64--glibc--*")
        list(SORT _bootlin_candidates)
        list(REVERSE _bootlin_candidates)
        if(_bootlin_candidates)
            list(GET _bootlin_candidates 0 BOOTLIN_TOOLCHAIN)
        endif()
    endif()
endif()

if(NOT BOOTLIN_TOOLCHAIN OR NOT EXISTS "${BOOTLIN_TOOLCHAIN}")
    message(FATAL_ERROR
        "Bootlin toolchain not found. Run scripts/fetch_bootlin_aarch64.sh "
        "or set -DBOOTLIN_TOOLCHAIN=/path/to/toolchain")
endif()

get_filename_component(BOOTLIN_TOOLCHAIN "${BOOTLIN_TOOLCHAIN}" ABSOLUTE)
message(STATUS "Bootlin toolchain: ${BOOTLIN_TOOLCHAIN}")

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
    "${BOOTLIN_TOOLCHAIN}/aarch64-buildroot-linux-gnu/sysroot"
    "${BOOTLIN_TOOLCHAIN}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Field cross builds: no host libuv for aarch64 — use poll loop.
set(CPE_AGENT_FIELD ON CACHE BOOL "Field build: no harness/sim; libuv optional" FORCE)
set(CPE_AGENT_WITH_LIBUV OFF CACHE BOOL "No libuv on Bootlin field cross" FORCE)
