cmake_minimum_required(VERSION 3.16)
project(tls_certificate_dates C)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_USER_CONFIG_FILE "${DATE_CONFIG}" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "${DATE_CONFIG}" CACHE FILEPATH "" FORCE)
add_subdirectory("$ENV{IDF_PATH}/components/mbedtls/mbedtls" mbedtls)
# Espressif 的 MPI 相容 header 位於 port；native 測試不啟用硬體加速。
get_filename_component(date_config_dir "${DATE_CONFIG}" DIRECTORY)
target_include_directories(builtin BEFORE PRIVATE
    "$ENV{IDF_PATH}/components/mbedtls/port/include" "${date_config_dir}")

add_executable(verify_dates verify_dates.c)
target_link_libraries(verify_dates PRIVATE mbedx509)
target_link_options(verify_dates PRIVATE -Wl,--wrap=time)
target_compile_options(verify_dates PRIVATE -Wall -Wextra -Werror)
