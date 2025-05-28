cmake_minimum_required(VERSION 3.10)
project(TXE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ─────────────────────────────────────────────────────────────────────────────
# 1) TELL MONERO WHAT TO BUILD (ONLY CORE + CRYPTONOTE + RINGCT)
# ─────────────────────────────────────────────────────────────────────────────
# Disable everything except the static core libs
set(BUILD_DAEMON           OFF CACHE BOOL "" FORCE)
set(BUILD_SIMPLE_WALLET    OFF CACHE BOOL "" FORCE)
set(BUILD_TESTS            OFF CACHE BOOL "" FORCE)
set(BUILD_BENCHMARKS       OFF CACHE BOOL "" FORCE)
set(BUILD_GUI_DEPS         OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS      OFF CACHE BOOL "" FORCE)
set(BUILD_TAG              ""  CACHE STRING "" FORCE)
set(STATIC                 ON  CACHE BOOL "" FORCE)
set(ARCH                   "native" CACHE STRING "" FORCE)

# Don’t need the P2P layers:
set(ENABLE_SYSTEMD         OFF CACHE BOOL "" FORCE)
set(USE_USB_HID            OFF CACHE BOOL "" FORCE)  # hidapi
set(USE_DEVICE_TREZOR      OFF CACHE BOOL "" FORCE)

# ─────────────────────────────────────────────────────────────────────────────
# 2) IMPORT MONERO SUBMODULE
# ─────────────────────────────────────────────────────────────────────────────
add_subdirectory(monero EXCLUDE_FROM_ALL)

# ─────────────────────────────────────────────────────────────────────────────
# 3) FIND OTHER DEPENDENCIES
# ─────────────────────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(Threads  REQUIRED)
find_package(Boost    REQUIRED COMPONENTS system filesystem thread)

# ─────────────────────────────────────────────────────────────────────────────
# 4) DEFINE EXECUTABLES
# ─────────────────────────────────────────────────────────────────────────────
add_executable(TXE
  ${CMAKE_SOURCE_DIR}/TXE-core/src/main.cpp
  ${CMAKE_SOURCE_DIR}/TXE-core/src/wallet.cpp
  ${CMAKE_SOURCE_DIR}/TXE-core/src/tx.cpp
  ${CMAKE_SOURCE_DIR}/TXE-core/src/block.cpp
  ${CMAKE_SOURCE_DIR}/TXE-core/src/db.cpp
)

# ─────────────────────────────────────────────────────────────────────────────
# 5) INCLUDE MONERO HEADERS
# ─────────────────────────────────────────────────────────────────────────────
target_include_directories(TXE PRIVATE
  ${CMAKE_SOURCE_DIR}/monero/src
  ${CMAKE_SOURCE_DIR}/monero/contrib/epee/include
  ${CMAKE_SOURCE_DIR}/monero/external/easylogging++
  ${CMAKE_SOURCE_DIR}/monero/external/db_drivers/liblmdb
  ${CMAKE_SOURCE_DIR}/monero/external/randomx/src
)

# ─────────────────────────────────────────────────────────────────────────────
# 6) LINK EXACT LIBRARIES NEEDED
# ─────────────────────────────────────────────────────────────────────────────
target_link_libraries(TXE PRIVATE
  # Monero
  randomx
  cryptonote_basic
  cryptonote_core
  crypto
  ringct
  common
  epee
  device

  # Other
  OpenSSL::Crypto
  Threads::Threads
  Boost::system
  Boost::filesystem
  Boost::thread
)
