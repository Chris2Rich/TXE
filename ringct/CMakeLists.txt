cmake_minimum_required(VERSION 3.10)
project(ringct-lib LANGUAGES C CXX)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Position‑independent code for static/shared libs
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/ringct
)

# Gather source files
file(GLOB COMMON_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/common/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/common/*.c
)
file(GLOB CRYPTO_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/*.cc
)
file(GLOB RINGCT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ringct/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ringct/*.c
)

set(RINGCT_SOURCES
    ${COMMON_SOURCES}
    ${CRYPTO_SOURCES}
    ${RINGCT_SOURCES}
)

# Build static library
add_library(ringct STATIC ${RINGCT_SOURCES})

target_include_directories(ringct PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/common>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/crypto>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ringct>
)

find_package(Boost 1.65 REQUIRED COMPONENTS system)
if(Boost_FOUND)
    target_include_directories(ringct PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(ringct PUBLIC ${Boost_LIBRARIES})
endif()

# Link pthread if needed
find_package(Threads REQUIRED)
target_link_libraries(ringct PRIVATE Threads::Threads)

# Installation (optional)
install(TARGETS ringct
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(DIRECTORY common/ crypto/ ringct/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)
