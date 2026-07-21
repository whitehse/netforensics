cmake_minimum_required(VERSION 3.20)
project(netforensics LANGUAGES C VERSION 0.3.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # poll, netlink, clock_gettime, libuv

if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Sibling libraries default under $HOME (or SIBLING_ROOT)
if(NOT DEFINED SIBLING_ROOT OR SIBLING_ROOT STREQUAL "")
    if(DEFINED ENV{HOME} AND NOT "$ENV{HOME}" STREQUAL "")
        set(SIBLING_ROOT "$ENV{HOME}")
    else()
        set(SIBLING_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
    endif()
endif()

set(IPFIX_ROOT "${SIBLING_ROOT}/libipfix" CACHE PATH "libipfix root")
set(NETDIAG_ROOT "${SIBLING_ROOT}/libnetdiag" CACHE PATH "libnetdiag root")
set(BMP_ROOT "${SIBLING_ROOT}/libbmp" CACHE PATH "libbmp root")
set(YAML_ROOT "${SIBLING_ROOT}/libyaml" CACHE PATH "libyaml root")
set(HARNESS_ROOT "${SIBLING_ROOT}/libharness" CACHE PATH "libharness root")
set(LIBSIM_ROOT "${SIBLING_ROOT}/libsim" CACHE PATH "libsim root")

option(CPE_AGENT_FIELD "Field/OpenWrt profile: no harness/sim; libuv optional" OFF)
option(CPE_AGENT_WITH_HARNESS "Build libharness local tools (P2.6)" ON)
option(CPE_AGENT_WITH_LIBSIM "Optional libsim class-B drive (P2.7b)" ON)
option(CPE_AGENT_WITH_MBEDTLS "Optional mbedTLS HTTPS egress (F5)" ON)
option(CPE_AGENT_WITH_LIBUV "Use libuv host loop (else poll/nanosleep)" ON)
option(BUILD_FUZZ "Build libFuzzer harness (clang)" OFF)

if(CPE_AGENT_FIELD)
    set(CPE_AGENT_WITH_HARNESS OFF CACHE BOOL "" FORCE)
    set(CPE_AGENT_WITH_LIBSIM OFF CACHE BOOL "" FORCE)
    # Keep mbedTLS optional; do not force OFF (site may enable)
endif()

if(NOT EXISTS "${IPFIX_ROOT}/include/ipfix.h")
    message(FATAL_ERROR "libipfix not found at ${IPFIX_ROOT}")
endif()
if(NOT EXISTS "${NETDIAG_ROOT}/include/netdiag.h")
    message(FATAL_ERROR "libnetdiag not found at ${NETDIAG_ROOT}")
endif()
if(NOT EXISTS "${BMP_ROOT}/include/bmp.h")
    message(FATAL_ERROR "libbmp not found at ${BMP_ROOT}")
endif()
if(NOT EXISTS "${YAML_ROOT}/include/yaml.h")
    message(FATAL_ERROR "libyaml not found at ${YAML_ROOT}")
endif()

set(CPE_HAVE_LIBUV 0)
if(CPE_AGENT_WITH_LIBUV)
    # Host pkg-config is wrong when cross-compiling; only use it natively.
    if(NOT CMAKE_CROSSCOMPILING)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(LIBUV libuv)
        endif()
    endif()
    if(NOT LIBUV_FOUND)
        find_path(LIBUV_INCLUDE_DIR uv.h
            PATHS ${CMAKE_FIND_ROOT_PATH}
            PATH_SUFFIXES include
            NO_CMAKE_FIND_ROOT_PATH)
        # Retry with root path modes for cross sysroot
        if(NOT LIBUV_INCLUDE_DIR)
            find_path(LIBUV_INCLUDE_DIR uv.h)
        endif()
        find_library(LIBUV_LIBRARY uv
            PATHS ${CMAKE_FIND_ROOT_PATH}
            PATH_SUFFIXES lib lib64
            NO_DEFAULT_PATH)
        if(NOT LIBUV_LIBRARY)
            find_library(LIBUV_LIBRARY uv)
        endif()
        if(LIBUV_INCLUDE_DIR AND LIBUV_LIBRARY)
            # Reject host /usr/lib when cross-compiling
            if(CMAKE_CROSSCOMPILING AND LIBUV_LIBRARY MATCHES "^/usr/lib")
                message(STATUS "  libuv       ignoring host ${LIBUV_LIBRARY}")
                unset(LIBUV_LIBRARY CACHE)
                unset(LIBUV_INCLUDE_DIR CACHE)
            else()
                set(LIBUV_FOUND TRUE)
                set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
                set(LIBUV_LIBRARIES ${LIBUV_LIBRARY})
            endif()
        endif()
    endif()
    if(LIBUV_FOUND)
        set(CPE_HAVE_LIBUV 1)
    elseif(CPE_AGENT_FIELD OR CMAKE_CROSSCOMPILING)
        message(STATUS "  libuv       not found — using poll loop (field/cross)")
        set(CPE_AGENT_WITH_LIBUV OFF)
    else()
        message(FATAL_ERROR "libuv required (install libuv1-dev) or -DCPE_AGENT_FIELD=ON")
    endif()
endif()

add_library(ipfix STATIC ${IPFIX_ROOT}/src/ipfix.c)
target_include_directories(ipfix PUBLIC ${IPFIX_ROOT}/include)

add_library(netdiag STATIC
    ${NETDIAG_ROOT}/src/netdiag.c
    ${NETDIAG_ROOT}/src/ping.c
    ${NETDIAG_ROOT}/src/arping.c
    ${NETDIAG_ROOT}/src/traceroute.c
    ${NETDIAG_ROOT}/src/dnsdiag.c
    ${NETDIAG_ROOT}/src/arprecon.c
    ${NETDIAG_ROOT}/src/nfct.c
    ${NETDIAG_ROOT}/src/nl80211_parse.c
)
target_include_directories(netdiag PUBLIC ${NETDIAG_ROOT}/include)

add_library(bmp STATIC ${BMP_ROOT}/src/bmp.c)
target_include_directories(bmp PUBLIC ${BMP_ROOT}/include)

add_library(yaml_sib STATIC ${YAML_ROOT}/src/yaml.c)
target_include_directories(yaml_sib PUBLIC ${YAML_ROOT}/include)

add_library(netforensics_core STATIC
    src/flow_correlate.c
    src/ipfix_ingest.c
    src/bmp_ingest.c
    src/nfct_netlink.c
    src/nl80211_netlink.c
)
target_include_directories(netforensics_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(netforensics_core PUBLIC ipfix netdiag bmp)

# --- optional libharness (P2.6) ---
set(CPE_HAVE_HARNESS 0)
if(CPE_AGENT_WITH_HARNESS AND EXISTS "${HARNESS_ROOT}/include/harness.h")
    add_library(harness_sib STATIC
        ${HARNESS_ROOT}/src/harness.c
        ${HARNESS_ROOT}/src/harness_extra.c
        ${HARNESS_ROOT}/src/harness_policy.c
        ${HARNESS_ROOT}/src/lua_bindings.c
        ${HARNESS_ROOT}/src/openai_processor.c
        ${HARNESS_ROOT}/src/honcho_interface.c
        ${HARNESS_ROOT}/src/pique_integration.c
    )
    target_include_directories(harness_sib PUBLIC ${HARNESS_ROOT}/include)
    # No Lua/pique required for tool registration + local invoke
    set(CPE_HAVE_HARNESS 1)
    message(STATUS "  libharness  ${HARNESS_ROOT}")
else()
    message(STATUS "  libharness  OFF")
endif()

# --- optional libsim class B (P2.7b) ---
set(CPE_HAVE_LIBSIM 0)
if(CPE_AGENT_WITH_LIBSIM AND EXISTS "${LIBSIM_ROOT}/include/sim.h")
    add_library(sim_sib STATIC
        ${LIBSIM_ROOT}/src/sim_clock.c
        ${LIBSIM_ROOT}/src/sim_timer.c
        ${LIBSIM_ROOT}/src/sim_net.c
        ${LIBSIM_ROOT}/src/sim_fuzz.c
    )
    target_include_directories(sim_sib PUBLIC ${LIBSIM_ROOT}/include)
    target_compile_definitions(sim_sib PUBLIC LIBSIM_NO_URING=1)
    set(CPE_HAVE_LIBSIM 1)
    message(STATUS "  libsim      ${LIBSIM_ROOT} (no uring)")
else()
    message(STATUS "  libsim      OFF")
endif()

# --- optional mbedTLS (F5 / ADR-004) ---
set(CPE_HAVE_MBEDTLS 0)
if(CPE_AGENT_WITH_MBEDTLS)
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
    find_library(MBEDTLS_LIBRARY mbedtls)
    find_library(MBEDX509_LIBRARY mbedx509)
    find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
    if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY AND MBEDX509_LIBRARY AND MBEDCRYPTO_LIBRARY)
        set(CPE_HAVE_MBEDTLS 1)
        message(STATUS "  mbedTLS     FOUND")
    else()
        message(STATUS "  mbedTLS     not found (HTTPS egress stubbed)")
    endif()
endif()

# --- CPE agent (Track 2 + field path) ---
set(CPE_AGENT_SOURCES
    agent/host_alloc.c
    agent/config_defaults.c
    agent/config_yaml.c
    agent/perf_sample.c
    agent/agent_core.c
    agent/agent_fuzz.c
    agent/live_ping.c
    agent/spool_util.c
    agent/tls_egress.c
)
if(CPE_HAVE_LIBUV)
    list(APPEND CPE_AGENT_SOURCES agent/agent_loop.c)
else()
    list(APPEND CPE_AGENT_SOURCES agent/agent_loop_poll.c)
endif()
if(CPE_HAVE_HARNESS)
    list(APPEND CPE_AGENT_SOURCES agent/harness_driver.c)
endif()
if(CPE_HAVE_LIBSIM)
    list(APPEND CPE_AGENT_SOURCES agent/agent_sim.c)
endif()

add_library(cpe_agent_lib STATIC ${CPE_AGENT_SOURCES})
target_include_directories(cpe_agent_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(CPE_HAVE_LIBUV)
    target_include_directories(cpe_agent_lib PUBLIC ${LIBUV_INCLUDE_DIRS})
    target_link_libraries(cpe_agent_lib PUBLIC ${LIBUV_LIBRARIES})
    target_compile_definitions(cpe_agent_lib PUBLIC CPE_AGENT_HAVE_LIBUV=1)
endif()
target_link_libraries(cpe_agent_lib PUBLIC
    netforensics_core
    netdiag
    yaml_sib
)
target_compile_definitions(cpe_agent_lib PRIVATE _POSIX_C_SOURCE=200809L)
if(CPE_HAVE_HARNESS)
    target_link_libraries(cpe_agent_lib PUBLIC harness_sib)
    target_compile_definitions(cpe_agent_lib PUBLIC CPE_AGENT_HAVE_HARNESS=1)
endif()
if(CPE_HAVE_LIBSIM)
    target_link_libraries(cpe_agent_lib PUBLIC sim_sib)
    target_compile_definitions(cpe_agent_lib PUBLIC CPE_AGENT_HAVE_LIBSIM=1)
endif()
if(CPE_HAVE_MBEDTLS)
    target_include_directories(cpe_agent_lib PUBLIC ${MBEDTLS_INCLUDE_DIR})
    target_link_libraries(cpe_agent_lib PUBLIC
        ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
    target_compile_definitions(cpe_agent_lib PUBLIC CPE_AGENT_HAVE_MBEDTLS=1)
endif()

add_executable(forensicsd cpe/forensicsd.c)
target_link_libraries(forensicsd PRIVATE netforensics_core)

add_executable(cpe_agent agent/main.c)
target_link_libraries(cpe_agent PRIVATE cpe_agent_lib)

add_executable(ipfix_ingest_demo src/ipfix_ingest_main.c)
target_link_libraries(ipfix_ingest_demo PRIVATE netforensics_core)

add_executable(bmp_ingest_demo src/bmp_ingest_main.c)
target_link_libraries(bmp_ingest_demo PRIVATE netforensics_core)

# Lab-only pure-C HTTP NDJSON sink (MODULE 2); production uses Vector.
add_executable(gateway_stub src/gateway_stub_main.c)

enable_testing()
add_executable(test_correlate tests/test_correlate.c)
target_link_libraries(test_correlate PRIVATE netforensics_core)
add_test(NAME correlate COMMAND test_correlate)

add_executable(test_host_pipeline tests/test_host_pipeline.c)
target_link_libraries(test_host_pipeline PRIVATE netforensics_core)
add_test(NAME host_pipeline COMMAND test_host_pipeline)

add_executable(test_sql_fixtures tests/test_sql_fixtures.c)
target_link_libraries(test_sql_fixtures PRIVATE netforensics_core)
add_test(NAME sql_fixtures COMMAND test_sql_fixtures)

add_executable(test_bmp_ingest tests/test_bmp_ingest.c)
target_link_libraries(test_bmp_ingest PRIVATE netforensics_core)
add_test(NAME bmp_ingest COMMAND test_bmp_ingest)

add_executable(test_cpe_agent tests/test_cpe_agent.c)
target_link_libraries(test_cpe_agent PRIVATE cpe_agent_lib)
add_test(NAME cpe_agent COMMAND test_cpe_agent)

add_executable(test_cpe_agent_track2 tests/test_cpe_agent_track2.c)
target_link_libraries(test_cpe_agent_track2 PRIVATE cpe_agent_lib)
add_test(NAME cpe_agent_track2 COMMAND test_cpe_agent_track2)

# Smoke: forensicsd --demo still works (must not break)
add_test(NAME forensicsd_demo
  COMMAND ${CMAKE_COMMAND} -E env
  bash -c "$<TARGET_FILE:forensicsd> --demo --router-id cpe-ci-1 | grep -q '\"type\":\"cpe_nat\"'")

# Smoke: cpe_agent --once emits cpe_perf
add_test(NAME cpe_agent_once
  COMMAND ${CMAKE_COMMAND} -E env
  bash -c "$<TARGET_FILE:cpe_agent> --once --router-id cpe-ci-1 | grep -q '\"type\":\"cpe_perf\"'")

if(BUILD_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(WARNING "BUILD_FUZZ=ON recommended with clang")
    endif()
    add_executable(fuzz_cpe_agent fuzz/fuzz_cpe_agent.c)
    target_link_libraries(fuzz_cpe_agent PRIVATE cpe_agent_lib)
    target_compile_options(fuzz_cpe_agent PRIVATE -fsanitize=fuzzer,address -g -O1)
    target_link_options(fuzz_cpe_agent PRIVATE -fsanitize=fuzzer,address)
endif()

message(STATUS "netforensics dependency map:")
message(STATUS "  SIBLING_ROOT=${SIBLING_ROOT}")
message(STATUS "  libipfix   ${IPFIX_ROOT}")
message(STATUS "  libnetdiag  ${NETDIAG_ROOT}")
message(STATUS "  libbmp      ${BMP_ROOT}")
message(STATUS "  libyaml     ${YAML_ROOT}")
message(STATUS "  libuv       ${CPE_HAVE_LIBUV}")
message(STATUS "  harness     ${CPE_HAVE_HARNESS}")
message(STATUS "  libsim      ${CPE_HAVE_LIBSIM}")
message(STATUS "  mbedTLS     ${CPE_HAVE_MBEDTLS}")
message(STATUS "  field       ${CPE_AGENT_FIELD}")
