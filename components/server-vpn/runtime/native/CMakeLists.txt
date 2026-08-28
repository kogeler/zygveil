# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: LGPL-3.0-or-later

cmake_minimum_required(VERSION 3.31)
project(zygveil_server_vpn_config LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(server_vpn_config STATIC config.cpp sha256.cpp status.cpp)
target_include_directories(server_vpn_config PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(server_vpn_config PRIVATE -Wall -Wextra -Werror -Wpedantic)

if(NOT ANDROID)
  add_executable(server_vpn_config_test config_test.cpp)
  target_link_libraries(server_vpn_config_test PRIVATE server_vpn_config)
  target_compile_options(server_vpn_config_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
  add_executable(server_vpn_status_test status_test.cpp)
  target_link_libraries(server_vpn_status_test PRIVATE server_vpn_config)
  target_compile_options(server_vpn_status_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
endif()
