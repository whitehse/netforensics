cmake_minimum_required(VERSION 3.20)
project(netforensics LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

set(IPFIX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../libipfix" CACHE PATH "libipfix root")
set(NETDIAG_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../libnetdiag" CACHE PATH "libnetdiag root")

if(NOT EXISTS "${IPFIX_ROOT}/include/ipfix.h")
    message(FATAL_ERROR "libipfix not found at ${IPFIX_ROOT}")
endif()
if(NOT EXISTS "${NETDIAG_ROOT}/include/netdiag.h")
    message(FATAL_ERROR "libnetdiag not found at ${NETDIAG_ROOT}")
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

add_library(netforensics_core STATIC
    src/flow_correlate.c
    src/ipfix_ingest.c
)
target_include_directories(netforensics_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(netforensics_core PUBLIC ipfix netdiag)

add_executable(forensicsd cpe/forensicsd.c)
target_link_libraries(forensicsd PRIVATE netforensics_core)

add_executable(ipfix_ingest_demo src/ipfix_ingest_main.c)
target_link_libraries(ipfix_ingest_demo PRIVATE netforensics_core)

enable_testing()
add_executable(test_correlate tests/test_correlate.c)
target_link_libraries(test_correlate PRIVATE netforensics_core)
add_test(NAME correlate COMMAND test_correlate)
