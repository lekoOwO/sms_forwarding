#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "idf_config.h"
#include "idf_esim.h"
#include "idf_inbox.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_push.h"
#include "idf_sms.h"
#include "idf_web.h"
#include "idf_web_ota.h"
#include "idf_wifi.h"
#include "nvs_flash.h"
#include "web_assets.h"
#if SMS_USB_RECOVERY
#include "usb_recovery.h"
#endif

static const char* TAG = "sms_idf";
static bool s_http_live = false;

static void ota_health_task(void*)
{
    static constexpr TickType_t deadline_ticks = pdMS_TO_TICKS(60000);
    const TickType_t started = xTaskGetTickCount();
    while (true) {
        const IdfWifiStatus wifi = idf_wifi_get_status();
        const bool reachable = wifi.staConnected || wifi.apMode;
        const bool deadline = xTaskGetTickCount() - started >= deadline_ticks;
        const esp_err_t result = idf_web_ota_health_check(s_http_live, reachable, deadline);
        if (result == ESP_OK) break;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    vTaskDelete(nullptr);
}

static esp_err_t init_nvs()
{
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        // Legacy config can be the only recoverable copy in this partition.
        // Preserve it. appcfg can initialize and start independently.
        ESP_LOGE(TAG, "default NVS init failed (%s). Data preserved", esp_err_to_name(err));
    }
    return err;
}

static void log_start_result(const char* name, esp_err_t err)
{
    if (err == ESP_OK) return;
    ESP_LOGE(TAG, "%s start failed: %s", name, esp_err_to_name(err));
    idf_logf("%s start failed: %s", name, esp_err_to_name(err));
}

extern "C" void app_main(void)
{
    esp_err_t default_nvs_err = init_nvs();
    idf_log_init();
    if (default_nvs_err != ESP_OK) {
        idf_logf("default NVS init failed (%s). Data preserved", esp_err_to_name(default_nvs_err));
    }
    idf_inbox_init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // Configuration storage is fail-closed: an invalid committed slot must
    // not be replaced with administrator defaults.
    esp_err_t cfg_err = idf_config_load();
    if (cfg_err != ESP_OK) {
        ESP_LOGE(TAG, "config load failed: %s; services remain stopped", esp_err_to_name(cfg_err));
        idf_logf("config load failed (%s). Startup stopped", esp_err_to_name(cfg_err));
        (void)idf_web_ota_health_check(false, false, true);
        return;
    }

#if SMS_USB_RECOVERY
    log_start_result("USB recovery", idf_usb_recovery_start());
#endif
    // Web, config, WiFi, push, modem, and SMS use the native ESP-IDF runtime.
    ESP_LOGI(TAG, "ESP-IDF port bootstrap started");
    idf_logf("ESP-IDF migration build started: %s", IDF_FW_VERSION);
    ESP_LOGI(TAG, "web hash=%s shell=%u css=%u js=%u",
             WEB_ASSET_HASH,
             static_cast<unsigned>(WEB_INDEX.length),
             static_cast<unsigned>(WEB_APP_CSS.length),
             static_cast<unsigned>(WEB_APP_JS.length));
    idf_logf("Web assets hash=%s shell=%u css=%u js=%u",
             WEB_ASSET_HASH,
             static_cast<unsigned>(WEB_INDEX.length),
             static_cast<unsigned>(WEB_APP_CSS.length),
             static_cast<unsigned>(WEB_APP_JS.length));
    idf_esim_init();  // Register the SIM hot-swap hook and invalidate the EID cache after a swap.
    esp_err_t wifi_start_err = idf_wifi_start(idf_config_get());
    log_start_result("WiFi", wifi_start_err);
    esp_err_t push_start_err = idf_push_start();
    log_start_result("push worker", push_start_err);
    if (wifi_start_err == ESP_OK && push_start_err == ESP_OK) {
        // The helper checks STA readiness, SMTP configuration, and the live
        // config.  Keep this as the single boot call; retries belong to the
        // normal notification path, not a second scheduler.
        (void)idf_push_enqueue_startup_notification();
    }
    const esp_err_t web_start_err = idf_web_start();
    s_http_live = web_start_err == ESP_OK;
    log_start_result("HTTP server", web_start_err);
    log_start_result("modem", idf_modem_start(idf_config_get()));
    log_start_result("SMS receiver", idf_sms_start());
    if (xTaskCreate(ota_health_task, "ota_health", 4096, nullptr, 3, nullptr) != pdPASS) {
        ESP_LOGE(TAG, "OTA health task start failed");
        (void)idf_web_ota_health_check(false, false, true);
    }
}
