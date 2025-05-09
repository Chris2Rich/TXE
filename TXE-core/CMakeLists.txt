cmake_minimum_required(VERSION 3.10)
project(TXE LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Find and link Relic
find_library(RELIC_LIB relic)
find_path(RELIC_INCLUDE_DIR relic/relic.h)

if (RELIC_LIB AND RELIC_INCLUDE_DIR)
    target_include_directories(TXE PRIVATE ${RELIC_INCLUDE_DIR})
    target_link_libraries(TXE PRIVATE ${RELIC_LIB})
else()
    message(FATAL_ERROR "Relic library not found! Ensure Relic is installed.")
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