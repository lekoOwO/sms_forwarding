set(MAIN_SRCS "app_main.cpp")
set(MAIN_REQUIRES
  esp_event
  esp_netif
  idf_config
  idf_esim
  idf_inbox
  idf_logbuf
  idf_modem
  idf_push
  idf_sms
  idf_web
  idf_wifi
  nvs_flash
)
if(SMS_USB_RECOVERY)
  list(APPEND MAIN_SRCS "usb_recovery.cpp")
endif()

idf_component_register(
  SRCS ${MAIN_SRCS}
  INCLUDE_DIRS "."
  REQUIRES ${MAIN_REQUIRES}
  PRIV_REQUIRES esp_driver_usb_serial_jtag
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
  SMS_USB_RECOVERY=${SMS_USB_RECOVERY_VALUE}
)

if(SMS_USB_RECOVERY)
  target_compile_options(${COMPONENT_LIB} PRIVATE "-fstack-usage")
endif()
