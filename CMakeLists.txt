cmake_minimum_required(VERSION 3.20)
project(netforensics LANGUAGES C VERSION 0.2.0)

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

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBUV libuv)
endif()
if(NOT LIBUV_FOUND)
    find_path(LIBUV_INCLUDE_DIR uv.h)
    find_library(LIBUV_LIBRARY uv)
    if(LIBUV_INCLUDE_DIR AND LIBUV_LIBRARY)
        set(LIBUV_FOUND TRUE)
        set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
        set(LIBUV_LIBRARIES ${LIBUV_LIBRARY})
    endif()
endif()
if(NOT LIBUV_FOUND)
    message(FATAL_ERROR "libuv required for cpe_agent (install libuv1-dev)")
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
# Avoid target name clash with system; expose as yaml for agent
add_library(yaml ALIAS yaml_sib)

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

# --- CPE agent (Track 2) ---
add_library(cpe_agent_lib STATIC
    agent/host_alloc.c
    agent/config_defaults.c
    agent/config_yaml.c
    agent/perf_sample.c
    agent/agent_core.c
    agent/agent_loop.c
)
target_include_directories(cpe_agent_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBUV_INCLUDE_DIRS}
)
target_link_libraries(cpe_agent_lib PUBLIC
    netdiag
    yaml_sib
    ${LIBUV_LIBRARIES}
)
target_compile_definitions(cpe_agent_lib PRIVATE _POSIX_C_SOURCE=200809L)

add_executable(forensicsd cpe/forensicsd.c)
target_link_libraries(forensicsd PRIVATE netforensics_core)

add_executable(cpe_agent agent/main.c)
target_link_libraries(cpe_agent PRIVATE cpe_agent_lib)

add_executable(ipfix_ingest_demo src/ipfix_ingest_main.c)
target_link_libraries(ipfix_ingest_demo PRIVATE netforensics_core)

add_executable(bmp_ingest_demo src/bmp_ingest_main.c)
target_link_libraries(bmp_ingest_demo PRIVATE netforensics_core)

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

# Smoke: forensicsd --demo still works (must not break)
add_test(NAME forensicsd_demo
  COMMAND ${CMAKE_COMMAND} -E env
  bash -c "$<TARGET_FILE:forensicsd> --demo --router-id cpe-ci-1 | grep -q '\"type\":\"cpe_nat\"'")

# Smoke: cpe_agent --once emits cpe_perf
add_test(NAME cpe_agent_once
  COMMAND ${CMAKE_COMMAND} -E env
  bash -c "$<TARGET_FILE:cpe_agent> --once --router-id cpe-ci-1 | grep -q '\"type\":\"cpe_perf\"'")

message(STATUS "netforensics dependency map:")
message(STATUS "  SIBLING_ROOT=${SIBLING_ROOT}")
message(STATUS "  libipfix   ${IPFIX_ROOT}")
message(STATUS "  libnetdiag  ${NETDIAG_ROOT}")
message(STATUS "  libbmp      ${BMP_ROOT}")
message(STATUS "  libyaml     ${YAML_ROOT}")
message(STATUS "  libuv       FOUND=${LIBUV_FOUND}")
