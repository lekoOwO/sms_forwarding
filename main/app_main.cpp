#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "idf_config.h"
#include "idf_esim.h"
#include "idf_inbox.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_push.h"
#include "idf_sms.h"
#include "idf_web.h"
#include "idf_wifi.h"
#include "nvs_flash.h"
#include "web_assets.h"

static const char* TAG = "sms_idf";

static esp_err_t init_nvs()
{
    esp_err_t err = nvs_flash_init();
    if (err != ESP_OK) {
        // 旧版配置仍可能是这个分区里唯一可恢复的副本；禁止自动擦除。
        // appcfg 可独立初始化，已有新版配置时仍可继续启动。
        ESP_LOGE(TAG, "默认 NVS 初始化失败(%s)，保留原数据", esp_err_to_name(err));
    }
    return err;
}

static void log_start_result(const char* name, esp_err_t err)
{
    if (err == ESP_OK) return;
    ESP_LOGE(TAG, "%s start failed: %s", name, esp_err_to_name(err));
    idf_logf("%s 启动失败: %s", name, esp_err_to_name(err));
}

extern "C" void app_main(void)
{
    esp_err_t default_nvs_err = init_nvs();
    idf_log_init();
    if (default_nvs_err != ESP_OK) {
        idf_logf("默认 NVS 初始化失败(%s)，已保留原数据", esp_err_to_name(default_nvs_err));
    }
    idf_inbox_init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // Configuration storage is fail-closed: an invalid committed slot must
    // not be replaced with administrator defaults.
    esp_err_t cfg_err = idf_config_load();
    if (cfg_err != ESP_OK) {
        ESP_LOGE(TAG, "config load failed: %s; services remain stopped", esp_err_to_name(cfg_err));
        idf_logf("配置加载失败(%s)，已停止启动", esp_err_to_name(cfg_err));
        return;
    }

    // 原生 ESP-IDF 启动：Web、配置、WiFi、推送、模组、短信均不依赖 Arduino runtime。
    ESP_LOGI(TAG, "ESP-IDF port bootstrap started");
    idf_logf("ESP-IDF 迁移版启动: %s", IDF_FW_VERSION);
    ESP_LOGI(TAG, "web hash=%s shell=%u css=%u js=%u",
             WEB_ASSET_HASH,
             static_cast<unsigned>(WEB_INDEX.length),
             static_cast<unsigned>(WEB_APP_CSS.length),
             static_cast<unsigned>(WEB_APP_JS.length));
    idf_logf("Web 资源 hash=%s shell=%u css=%u js=%u",
             WEB_ASSET_HASH,
             static_cast<unsigned>(WEB_INDEX.length),
             static_cast<unsigned>(WEB_APP_CSS.length),
             static_cast<unsigned>(WEB_APP_JS.length));
    idf_esim_init();  // 注册 SIM 热插拔钩子，换卡后 EID 缓存随之失效
    esp_err_t wifi_start_err = idf_wifi_start(idf_config_get());
    log_start_result("WiFi", wifi_start_err);
    esp_err_t push_start_err = idf_push_start();
    log_start_result("推送后台 worker", push_start_err);
    if (wifi_start_err == ESP_OK && push_start_err == ESP_OK) {
        // The helper checks STA readiness, SMTP configuration, and the live
        // config.  Keep this as the single boot call; retries belong to the
        // normal notification path, not a second scheduler.
        (void)idf_push_enqueue_startup_notification();
    }
    log_start_result("HTTP 服务器", idf_web_start());
    log_start_result("模组", idf_modem_start(idf_config_get()));
    log_start_result("短信接收", idf_sms_start());
}
