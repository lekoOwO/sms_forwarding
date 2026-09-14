cmake_minimum_required(VERSION 3.16)
project(tls_certificate_bundle C ASM)

if(NOT PATCHED_CRT_BUNDLE_DIR)
    message(FATAL_ERROR "PATCHED_CRT_BUNDLE_DIR is required")
endif()
if(NOT EXISTS "${PATCHED_CRT_BUNDLE_DIR}/esp_crt_bundle.c")
    message(FATAL_ERROR "prepared ESP-IDF certificate-bundle source is missing")
endif()
if(NOT CROSS_SIGNED_CERT_DIR)
    message(FATAL_ERROR "CROSS_SIGNED_CERT_DIR is required")
endif()
if(NOT EXISTS "${CROSS_SIGNED_CERT_DIR}/server_root.pem")
    message(FATAL_ERROR "official cross-signed root fixture is missing")
endif()
if(NOT INTERMEDIATE_CERT_DIR)
    message(FATAL_ERROR "INTERMEDIATE_CERT_DIR is required")
endif()
if(NOT EXISTS "${INTERMEDIATE_CERT_DIR}/root.pem")
    message(FATAL_ERROR "generated intermediate root fixture is missing")
endif()

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h" CACHE FILEPATH "" FORCE)
set(TF_PSA_CRYPTO_USER_CONFIG_FILE "mbedtls/esp_config.h" CACHE FILEPATH "" FORCE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# esp_config.h includes the generated sdkconfig.h. Add the temporary native
# Kconfig directory before configuring every pinned Mbed TLS target.
add_compile_options("-I${BUNDLE_CONFIG_DIR}")
include_directories("${IDF_MBEDTLS}/port/include")
add_subdirectory("${IDF_MBEDTLS}/mbedtls" mbedtls)

set(BUNDLE_GENERATOR "${IDF_MBEDTLS}/esp_crt_bundle/gen_crt_bundle.py")
set(BUNDLE_DIR "${CMAKE_CURRENT_BINARY_DIR}/bundles")

function(make_bundle name root)
    set(bundle_dir "${BUNDLE_DIR}/${name}")
    set(bundle "${bundle_dir}/x509_crt_bundle")
    add_custom_command(
        OUTPUT "${bundle}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${bundle_dir}"
        COMMAND "${CMAKE_COMMAND}" -E chdir "${bundle_dir}"
                "${Python3_EXECUTABLE}" "${BUNDLE_GENERATOR}"
                --input "${root}" "${GSMA_CERT}" --quiet --max-certs 200
        DEPENDS "${root}" "${GSMA_CERT}" "${BUNDLE_GENERATOR}"
        VERBATIM
    )
    add_custom_target("${name}_bundle" DEPENDS "${bundle}")

    set(asm "${CMAKE_CURRENT_BINARY_DIR}/${name}_bundle.S")
    set(asm_content
        ".section .rodata\n"
        ".global _binary_x509_crt_bundle_start\n"
        ".global _binary_x509_crt_bundle_end\n"
        "_binary_x509_crt_bundle_start:\n"
        ".incbin \"${bundle}\"\n"
        "_binary_x509_crt_bundle_end:\n"
        ".byte 0\n"
    )
    string(CONCAT asm_content ${asm_content})
    file(GENERATE OUTPUT "${asm}" CONTENT "${asm_content}")
    set_source_files_properties("${asm}" PROPERTIES GENERATED TRUE)

    # Keep the generated .S input in an OBJECT target.  CMake compiles the
    # assembly when it is listed directly on the executable, but some pinned
    # native toolchains omit that generated object from the final link.  The
    # object-library expression makes the bundle bytes an explicit link input.
    add_library("${name}_bundle_data" OBJECT "${asm}")
    add_dependencies("${name}_bundle_data" "${name}_bundle")
    add_executable("${name}" verify_bundle.c
        $<TARGET_OBJECTS:${name}_bundle_data>)
    add_dependencies("${name}" "${name}_bundle")
    target_include_directories("${name}" PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${PATCHED_CRT_BUNDLE_DIR}"
        "${BUNDLE_CONFIG_DIR}"
        "${IDF_MBEDTLS}/port/include"
        "${IDF_MBEDTLS}/esp_crt_bundle"
        "${IDF_MBEDTLS}/esp_crt_bundle/include"
        "${IDF_MBEDTLS}/mbedtls/include"
        "${IDF_MBEDTLS}/mbedtls/library"
        "${IDF_MBEDTLS}/mbedtls/tf-psa-crypto/core"
        "${IDF_MBEDTLS}/mbedtls/tf-psa-crypto/include"
        "${IDF_MBEDTLS}/mbedtls/tf-psa-crypto/drivers/builtin/include"
        "${IDF_MBEDTLS}/mbedtls/tf-psa-crypto/drivers/builtin/src"
        "${IDF_MBEDTLS}/mbedtls/tf-psa-crypto/extras"
        "${IDF_MBEDTLS}/../esp_common/include"
        "${IDF_MBEDTLS}/../log/include"
    )
    target_link_libraries("${name}" PRIVATE mbedtls mbedx509 tfpsacrypto)
    target_link_options("${name}" PRIVATE -Wl,--wrap=time)
    target_compile_definitions("${name}" PRIVATE
        MBEDTLS_MAJOR_VERSION=4
        ESP_CRT_BUNDLE_SOURCE=\"${PATCHED_CRT_BUNDLE_DIR}/esp_crt_bundle.c\"
    )
    if(name STREQUAL "verify_cross_signed")
        target_compile_definitions("${name}" PRIVATE CROSS_SIGNED_FIXTURE=1)
    endif()
    target_compile_options("${name}" PRIVATE -Wall -Wextra -Wno-unused-parameter)
endfunction()

make_bundle(verify_bundle "${SYNTHETIC_CERT_DIR}/root.pem")
make_bundle(verify_bundle_untrusted "${SYNTHETIC_CERT_DIR}/other-root.pem")
make_bundle(verify_cross_signed "${CROSS_SIGNED_CERT_DIR}/server_root.pem")
make_bundle(verify_intermediate "${INTERMEDIATE_CERT_DIR}/root.pem")
