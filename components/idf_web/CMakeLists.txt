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
    idf_inbox
    idf_logbuf
    idf_modem
    idf_push
    idf_sms
    idf_wifi
    mbedtls
    nvs_flash
    web_assets
  EMBED_TXTFILES "ota_public_key.der.b64"
)
