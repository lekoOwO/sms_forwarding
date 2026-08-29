idf_component_register(
  SRCS "idf_modem.cpp" "idf_modem_https.cpp" "idf_modem_https_wire.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    driver
    esp_driver_gpio
    esp_driver_uart
    esp_timer
    idf_config
    idf_logbuf
    mbedtls
    nvs_flash
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE SMS_USB_RECOVERY=${SMS_USB_RECOVERY_VALUE})
