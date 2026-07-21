# Debian/Ubuntu multiarch or system cross package:
#   apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
# Optional arm64 libs:
#   dpkg --add-architecture arm64 && apt install libuv1-dev:arm64
#
# cmake -B build-aarch64 -S . \
#   -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
#   -DCPE_AGENT_FIELD=ON

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Multiarch paths (Debian)
list(APPEND CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
set(ENV{PKG_CONFIG_LIBDIR}
    "/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/aarch64-linux-gnu/lib/pkgconfig")
