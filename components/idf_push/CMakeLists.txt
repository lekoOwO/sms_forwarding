idf_component_register(
  SRCS "idf_push.cpp" "idf_push_core.cpp" "idf_push_transport.cpp" "idf_push_cellular.cpp"
       "idf_push_ca.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    esp_http_client
    esp_timer
    esp-tls
    idf_config
    idf_inbox
    idf_logbuf
    idf_modem
    idf_wifi
    lwip
    mbedtls
)

idf_build_get_property(idf_path IDF_PATH)
idf_build_get_property(python PYTHON)
set(ca_bundle "${idf_path}/components/mbedtls/esp_crt_bundle/cacrt_all.pem")
set(ca_allowlist "${CMAKE_CURRENT_BINARY_DIR}/idf_push_ca_allowlist_generated.h")
add_custom_command(
  OUTPUT "${ca_allowlist}"
  COMMAND "${python}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_ca_allowlist.py"
          --input "${ca_bundle}" --output "${ca_allowlist}"
  DEPENDS "${ca_bundle}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_ca_allowlist.py"
  VERBATIM
)
target_sources(${COMPONENT_LIB} PRIVATE "${ca_allowlist}")
target_include_directories(${COMPONENT_LIB} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
