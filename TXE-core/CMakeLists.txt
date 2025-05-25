cmake_minimum_required(VERSION 3.10)
project(TXE LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Explicitly list source files
set(SOURCES
    src/main.cpp
)

# === Build the ringct library ===
set(XMR_RINGCT_ROOT ${PROJECT_SOURCE_DIR}/include/xmr-ringct)

# Grab every .cpp, .cc and .c file
file(GLOB_RECURSE RINGCT_SRCS
  ${XMR_RINGCT_ROOT}/common/*.cpp
  ${XMR_RINGCT_ROOT}/common/*.c
  ${XMR_RINGCT_ROOT}/common/*.cc
  ${XMR_RINGCT_ROOT}/crypto/*.cpp
  ${XMR_RINGCT_ROOT}/crypto/*.c
  ${XMR_RINGCT_ROOT}/crypto/*.cc
  ${XMR_RINGCT_ROOT}/ringct/*.cpp
  ${XMR_RINGCT_ROOT}/ringct/*.c
  ${XMR_RINGCT_ROOT}/ringct/*.cc
)
add_library(ringct STATIC ${RINGCT_SRCS})

target_include_directories(ringct PUBLIC
  ${XMR_RINGCT_ROOT}
  ${XMR_RINGCT_ROOT}/common
  ${XMR_RINGCT_ROOT}/crypto
  ${XMR_RINGCT_ROOT}/ringct
)

# === RINGCT DEPENDENCIES ===
find_package(Threads REQUIRED)
target_link_libraries(ringct PRIVATE Threads::Threads)

find_package(Boost 1.65 REQUIRED COMPONENTS system)
target_include_directories(ringct PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(ringct PUBLIC ${Boost_LIBRARIES})

file(GLOB_RECURSE EPEE_SOURCES
  ${PROJECT_SOURCE_DIR}/src/epee/*.cpp
)
add_library(epee_static STATIC ${EPEE_SOURCES})
target_include_directories(epee_static PUBLIC
  ${PROJECT_SOURCE_DIR}/include/xmr-ringct/epee/include
)
target_link_libraries(ringct PUBLIC epee_static)

# === MAIN ===
# Create the executable
add_executable(TXE ${SOURCES})

target_include_directories(TXE PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(TXE PRIVATE ringct)

# === MAIN DEPENDENCIES ===
# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(TXE PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Find and link boost
find_package(Boost 1.65 REQUIRED)
target_include_directories(TXE PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(TXE PUBLIC ${Boost_LIBRARIES})

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