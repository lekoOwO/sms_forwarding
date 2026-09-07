idf_component_register(
  SRCS "idf_lpa_activation_code.cpp" "idf_lpa_rsp.cpp" "idf_lpa_es9_transport.cpp"
       "idf_lpa_bpp.cpp" "idf_lpa_install.cpp"
  INCLUDE_DIRS "include"
  REQUIRES esp-tls esp_http_client esp_timer freertos idf_esim idf_modem mbedtls
)
