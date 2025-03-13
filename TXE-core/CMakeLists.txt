cmake_minimum_required(VERSION 3.10)
project(TXE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TXE
    src/main.cpp
)
target_include_directories(TXE PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(TXE PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(TXE PRIVATE -Wall -Wextra -Werror)
endif()