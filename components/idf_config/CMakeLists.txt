idf_component_register(
  SRCS "idf_config.cpp" "idf_config_storage.cpp"
  INCLUDE_DIRS "include"
  REQUIRES
    freertos
    idf_logbuf
    nvs_flash
)

# Configuration copies must stay off the FreeRTOS task stack.  Keep a hard
# frame-size guard on both codec and public update entrypoints.
target_compile_options(${COMPONENT_LIB} PRIVATE "-Werror=frame-larger-than=4096")

if(EXISTS "${PROJECT_DIR}/code/wifi_config.h")
  target_include_directories(${COMPONENT_LIB} PRIVATE "${PROJECT_DIR}/code")
  target_compile_definitions(${COMPONENT_LIB} PRIVATE IDF_HAS_WIFI_CONFIG_H=1)
endif()
