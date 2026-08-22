idf_component_register(
  SRCS "idf_wifi.cpp" "idf_wifi_core.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    esp_driver_gpio
    esp_event
    esp_netif
    esp_timer
    esp_wifi
    freertos
    idf_config
    idf_logbuf
    lwip
)

target_compile_options(${COMPONENT_LIB} PRIVATE "-fexceptions")
