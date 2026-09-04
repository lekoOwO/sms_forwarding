idf_component_register(
  SRCS "idf_lpa_activation_code.cpp" "idf_lpa_rsp.cpp"
  INCLUDE_DIRS "include"
  REQUIRES idf_esim mbedtls
)
