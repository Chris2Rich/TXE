cmake_minimum_required(VERSION 3.10)
project(TXE LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ==================== RingCT Library ====================
# Build the extracted Monero RingCT code into a static library
# Point these to where you placed the Monero folders: common/, crypto/, crypto-ops.c/h, ringct/, and optional boost/
set(RINGCT_ROOT ${PROJECT_SOURCE_DIR}/ringct)
set(CRYPTO_ROOT ${PROJECT_SOURCE_DIR}/crypto)
set(COMMON_ROOT ${PROJECT_SOURCE_DIR}/common)
set(BOOST_ROOT ${PROJECT_SOURCE_DIR}/boost)  # remove or adjust if using system Boost

# Include directories for ringct lib
include_directories(
    ${COMMON_ROOT}
    ${CRYPTO_ROOT}
    ${RINGCT_ROOT}
    ${BOOST_ROOT}   # optional
)

# Gather RingCT sources
file(GLOB_RECURSE RINGCT_COMMON_SOURCES
    ${COMMON_ROOT}/*.cpp
    ${COMMON_ROOT}/*.c
)
file(GLOB_RECURSE RINGCT_CRYPTO_SOURCES
    ${CRYPTO_ROOT}/*.cpp
    ${CRYPTO_ROOT}/*.c
)
file(GLOB_RECURSE RINGCT_CT_SOURCES
    ${RINGCT_ROOT}/*.cpp
    ${RINGCT_ROOT}/*.c
)

add_library(ringct STATIC
    ${RINGCT_COMMON_SOURCES}
    ${RINGCT_CRYPTO_SOURCES}
    ${RINGCT_CT_SOURCES}
)

target_include_directories(ringct PUBLIC
    $<BUILD_INTERFACE:${COMMON_ROOT}>
    $<BUILD_INTERFACE:${CRYPTO_ROOT}>
    $<BUILD_INTERFACE:${RINGCT_ROOT}>
)

# Link pthreads for threading/random utilities
find_package(Threads REQUIRED)
target_link_libraries(ringct PRIVATE Threads::Threads)

# Optionally link system Boost
find_package(Boost 1.65 REQUIRED COMPONENTS system)
if(Boost_FOUND)
    target_include_directories(ringct PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(ringct PUBLIC ${Boost_LIBRARIES})
endif()

# Explicitly list source files
set(SOURCES
    src/main.cpp
)

# Create the executable
add_executable(TXE ${SOURCES})

# Add include directories
# This makes headers like "tx.h" (in include/) and "core/block.h" (in include/core/) findable
target_include_directories(TXE PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(TXE PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Find and link RocksDB
find_library(ROCKSDB_LIB rocksdb)
find_path(ROCKSDB_INCLUDE_DIR rocksdb/db.h)

if (ROCKSDB_LIB AND ROCKSDB_INCLUDE_DIR)
    target_include_directories(TXE PRIVATE ${ROCKSDB_INCLUDE_DIR})
    target_link_libraries(TXE PRIVATE ${ROCKSDB_LIB})
else()
    message(FATAL_ERROR "RocksDB not found! Ensure RocksDB is installed.")
endif()

# Find and link GNU MP (GMP)
find_library(GMP_LIB NAMES gmp libgmp)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)

if(GMP_LIB AND GMP_INCLUDE_DIR)
    target_include_directories(TXE PRIVATE ${GMP_INCLUDE_DIR})
    target_link_libraries(TXE PRIVATE ${GMP_LIB})
else()
    message(FATAL_ERROR "GNU MP not found! Ensure GNU MP is installed.")
endif()

# Add compiler options for GCC and Clang
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(TXE PRIVATE
        $<$<CONFIG:Debug>:-Wall -Wextra -Werror>
    )
endif()

# Optional: Install rules
install(TARGETS TXE DESTINATION bin)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include)