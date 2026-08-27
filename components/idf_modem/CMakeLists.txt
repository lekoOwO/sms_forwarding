idf_component_register(
  SRCS "idf_modem.cpp" "idf_modem_https.cpp"
  INCLUDE_DIRS "include"
  EMBED_TXTFILES "certs/gts_root_r4_7e8b80d078d3.pem"
  REQUIRES
    driver
    esp_driver_gpio
    esp_driver_uart
    esp_timer
    idf_config
    idf_logbuf
    nvs_flash
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE SMS_USB_RECOVERY=${SMS_USB_RECOVERY_VALUE})
