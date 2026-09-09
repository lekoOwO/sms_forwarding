set(OTA_PUBLIC_KEY_FILE "ota_public_key.der.b64")
if(SMS_OTA_TEST_KEY)
  set(OTA_PUBLIC_KEY_FILE "${SMS_OTA_TEST_PUBLIC_KEY}")
endif()

idf_component_register(
  SRCS "idf_web.cpp" "idf_web_core.cpp" "idf_web_crypto.cpp"
       "idf_web_ota_core.cpp" "idf_web_ota.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    esp_partition
    espcoredump
    esp_driver_tsens
    esp_timer
    heap
    esp_http_server
    app_update
    idf_config
    idf_esim
    idf_lpa
    idf_inbox
    idf_logbuf
    idf_modem
    idf_push
    idf_sms
    idf_wifi
    mbedtls
    nvs_flash
    web_assets
  EMBED_TXTFILES "${OTA_PUBLIC_KEY_FILE}"
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-fstack-usage")
add_custom_command(TARGET ${COMPONENT_LIB} POST_BUILD
  COMMAND ${PYTHON} "${PROJECT_DIR}/tools/check_web_stack.py"
    "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${COMPONENT_LIB}.dir/idf_web.cpp.su"
  VERBATIM
)
