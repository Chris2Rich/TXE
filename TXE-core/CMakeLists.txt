cmake_minimum_required(VERSION 3.10)
project(TXE LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Explicitly list source files
set(SOURCES
    src/main.cpp
    src/blockchain/block.cpp
    src/crypto/sha512.cpp
    src/crypto/tcrs.cpp
    src/tx/tx.cpp
)

# Create the executable
add_executable(TXE ${SOURCES})

# Add include directories
target_include_directories(TXE PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(TXE PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Add compiler options for GCC and Clang
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(TXE PRIVATE
        $<$<CONFIG:Debug>:-Wall -Wextra -Werror>
    )
endif()

# Optional: Install rules
install(TARGETS TXE DESTINATION bin)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include)