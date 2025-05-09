# Install script for directory: /workspaces/ecc/relic

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE FILE FILES
    "/workspaces/ecc/relic/include/relic.h"
    "/workspaces/ecc/relic/include/relic_alloc.h"
    "/workspaces/ecc/relic/include/relic_arch.h"
    "/workspaces/ecc/relic/include/relic_bc.h"
    "/workspaces/ecc/relic/include/relic_bench.h"
    "/workspaces/ecc/relic/include/relic_bn.h"
    "/workspaces/ecc/relic/include/relic_conf.h"
    "/workspaces/ecc/relic/include/relic_core.h"
    "/workspaces/ecc/relic/include/relic_cp.h"
    "/workspaces/ecc/relic/include/relic_dv.h"
    "/workspaces/ecc/relic/include/relic_eb.h"
    "/workspaces/ecc/relic/include/relic_ec.h"
    "/workspaces/ecc/relic/include/relic_ed.h"
    "/workspaces/ecc/relic/include/relic_ep.h"
    "/workspaces/ecc/relic/include/relic_epx.h"
    "/workspaces/ecc/relic/include/relic_err.h"
    "/workspaces/ecc/relic/include/relic_fb.h"
    "/workspaces/ecc/relic/include/relic_fbx.h"
    "/workspaces/ecc/relic/include/relic_fp.h"
    "/workspaces/ecc/relic/include/relic_fpx.h"
    "/workspaces/ecc/relic/include/relic_label.h"
    "/workspaces/ecc/relic/include/relic_md.h"
    "/workspaces/ecc/relic/include/relic_mpc.h"
    "/workspaces/ecc/relic/include/relic_multi.h"
    "/workspaces/ecc/relic/include/relic_pc.h"
    "/workspaces/ecc/relic/include/relic_pp.h"
    "/workspaces/ecc/relic/include/relic_rand.h"
    "/workspaces/ecc/relic/include/relic_test.h"
    "/workspaces/ecc/relic/include/relic_types.h"
    "/workspaces/ecc/relic/include/relic_util.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic/low" TYPE FILE FILES
    "/workspaces/ecc/relic/include/low/relic_bn_low.h"
    "/workspaces/ecc/relic/include/low/relic_dv_low.h"
    "/workspaces/ecc/relic/include/low/relic_fb_low.h"
    "/workspaces/ecc/relic/include/low/relic_fp_low.h"
    "/workspaces/ecc/relic/include/low/relic_fpx_low.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic" TYPE DIRECTORY FILES "/workspaces/ecc/relic/include/")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/cmake" TYPE FILE FILES "/workspaces/ecc/relic/cmake/relic-config.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/workspaces/ecc/relic/src/cmake_install.cmake")
  include("/workspaces/ecc/relic/test/cmake_install.cmake")
  include("/workspaces/ecc/relic/bench/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/workspaces/ecc/relic/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
