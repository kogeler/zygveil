# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: LGPL-3.0-or-later

cmake_minimum_required(VERSION 3.31)
project(zygveil LANGUAGES C CXX ASM)

option(ZYGVEIL_LOCATION_APP_POC "Select non-attestable fail-open application POC semantics" OFF)
option(ZYGVEIL_SERVER_VPN_FEATURE "Compile the feature-isolated server-VPN foundation" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT ANDROID)
  add_executable(location_model_test model.cpp model_test.cpp)
  target_compile_options(location_model_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
  find_package(Threads REQUIRED)
  target_link_libraries(location_model_test PRIVATE Threads::Threads)
  add_executable(location_control_test model.cpp control_protocol.cpp control_protocol_test.cpp)
  target_compile_options(location_control_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
  target_link_libraries(location_control_test PRIVATE Threads::Threads)
  add_executable(locationctl_test
    model.cpp control_protocol.cpp locationctl_core.cpp locationctl_test.cpp
  )
  target_compile_options(locationctl_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
  add_executable(location_process_liveness_test
    model.cpp control_protocol.cpp locationctl_core.cpp process_liveness.cpp
    process_liveness_test.cpp
  )
  target_compile_options(location_process_liveness_test PRIVATE
    -Wall -Wextra -Werror -Wpedantic
  )
  add_executable(location_application_delivery_test application_delivery_policy_test.cpp)
  target_compile_options(location_application_delivery_test PRIVATE
    -Wall -Wextra -Werror -Wpedantic
  )
  return()
endif()

if(NOT DEFINED VENDOR_SOURCE_ROOT)
  message(FATAL_ERROR "VENDOR_SOURCE_ROOT is required")
endif()

set(LSPLANT_ROOT "${VENDOR_SOURCE_ROOT}/lsplant/lsplant/src/main/jni")
set(SHADOWHOOK_ROOT "${VENDOR_SOURCE_ROOT}/shadowhook/shadowhook/src/main/cpp")
set(ZYGISK_INCLUDE "${VENDOR_SOURCE_ROOT}/zygisk-api/module/jni")

add_compile_options(
  $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
  $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
  $<$<COMPILE_LANGUAGE:CXX>:-fvisibility-inlines-hidden>
)
add_compile_definitions(
  _LIBCPP_NO_EXCEPTIONS
  _LIBCPP_NO_RTTI
  __STDC_FORMAT_MACROS
)

set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
add_subdirectory("${LSPLANT_ROOT}" "${CMAKE_BINARY_DIR}/lsplant")

file(GLOB SHADOWHOOK_SOURCES CONFIGURE_DEPENDS
  "${SHADOWHOOK_ROOT}/*.c"
  "${SHADOWHOOK_ROOT}/arch/arm64/*.c"
  "${SHADOWHOOK_ROOT}/arch/arm64/*.S"
  "${SHADOWHOOK_ROOT}/common/*.c"
  "${SHADOWHOOK_ROOT}/third_party/*/*.c"
)
set_source_files_properties("${SHADOWHOOK_ROOT}/sh_linker.c" PROPERTIES
  COMPILE_OPTIONS "-include;${CMAKE_CURRENT_SOURCE_DIR}/shadowhook_loader.h"
)
add_library(shadowhook_static STATIC ${SHADOWHOOK_SOURCES})
set_target_properties(shadowhook_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(shadowhook_static PRIVATE c_std_11)
target_compile_options(shadowhook_static PRIVATE -Os -ffunction-sections -fdata-sections)
target_include_directories(shadowhook_static PRIVATE
  "${SHADOWHOOK_ROOT}"
  "${SHADOWHOOK_ROOT}/include"
  "${SHADOWHOOK_ROOT}/arch/arm64"
  "${SHADOWHOOK_ROOT}/common"
  "${SHADOWHOOK_ROOT}/third_party/xdl"
  "${SHADOWHOOK_ROOT}/third_party/bsd"
  "${SHADOWHOOK_ROOT}/third_party/lss"
)
target_link_libraries(shadowhook_static PRIVATE log)

add_library(shadowhook_nothing SHARED "${SHADOWHOOK_ROOT}/nothing/sh_nothing.c")
set_target_properties(shadowhook_nothing PROPERTIES OUTPUT_NAME shadowhook_nothing)
target_compile_features(shadowhook_nothing PRIVATE c_std_11)
target_compile_options(shadowhook_nothing PRIVATE
  -Oz
  -fno-ident
  -fno-stack-protector
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
  -fvisibility=hidden
)
target_link_options(shadowhook_nothing PRIVATE
  -nostdlib
  -nostartfiles
  -nodefaultlibs
  -Wl,--as-needed
  -Wl,--build-id=none
  -Wl,--hash-style=sysv
  -Wl,--strip-all
  -Wl,-z,max-page-size=16384
)

add_library(zygveil SHARED
  model.cpp control_protocol.cpp hook_host.cpp locationctl_core.cpp process_liveness.cpp runtime.cpp
  module.cpp
)
add_dependencies(zygveil shadowhook_nothing)
if(ZYGVEIL_LOCATION_APP_POC)
  target_compile_definitions(zygveil PRIVATE ZYGVEIL_LOCATION_APP_POC=1)
endif()
if(ZYGVEIL_SERVER_VPN_FEATURE)
  target_sources(zygveil PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../server-vpn/runtime/native/config.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../server-vpn/runtime/native/runtime.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../server-vpn/runtime/native/sha256.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../server-vpn/runtime/native/status.cpp"
  )
  target_include_directories(zygveil PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../server-vpn/runtime/native"
  )
  target_compile_definitions(zygveil PRIVATE ZYGVEIL_SERVER_VPN_FEATURE=1)
endif()
target_compile_options(zygveil PRIVATE
  -Wall -Wextra -Werror -Wpedantic -ffunction-sections -fdata-sections
)
target_include_directories(zygveil PRIVATE
  "${ZYGISK_INCLUDE}"
  "${LSPLANT_ROOT}/include"
  "${SHADOWHOOK_ROOT}/include"
)
target_link_libraries(zygveil PRIVATE lsplant_static shadowhook_static log dl)
target_link_options(zygveil PRIVATE
  -Wl,--gc-sections
  -Wl,--exclude-libs,ALL
  -Wl,-Bsymbolic
  -Wl,-z,max-page-size=16384
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map
)

add_executable(locationctl model.cpp control_protocol.cpp locationctl_core.cpp locationctl.cpp)
target_compile_options(locationctl PRIVATE
  -Wall -Wextra -Werror -Wpedantic -ffunction-sections -fdata-sections
)
target_link_options(locationctl PRIVATE
  -Wl,--gc-sections
  -Wl,--exclude-libs,ALL
  -Wl,-z,max-page-size=16384
)
