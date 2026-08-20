cmake_minimum_required(VERSION 3.16)

# 原生 ESP-IDF 固件工程入口；Arduino fallback 已移除。
file(READ "${CMAKE_CURRENT_LIST_DIR}/firmware-version.json" FIRMWARE_VERSION_JSON)
string(JSON FIRMWARE_RELEASE_VERSION GET "${FIRMWARE_VERSION_JSON}" releaseVersion)
set(PROJECT_VER "${FIRMWARE_RELEASE_VERSION}")
if(DEFINED ENV{FIRMWARE_IS_RELEASE})
  set(FIRMWARE_IS_RELEASE_DEFAULT "$ENV{FIRMWARE_IS_RELEASE}")
else()
  set(FIRMWARE_IS_RELEASE_DEFAULT "0")
endif()
set(FIRMWARE_IS_RELEASE "${FIRMWARE_IS_RELEASE_DEFAULT}" CACHE STRING "Use the release firmware display version")
if(NOT FIRMWARE_IS_RELEASE MATCHES "^[01]$")
  message(FATAL_ERROR "FIRMWARE_IS_RELEASE must be 0 or 1")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(sms_forwarding_idf)
add_compile_definitions(FIRMWARE_IS_RELEASE=${FIRMWARE_IS_RELEASE})
