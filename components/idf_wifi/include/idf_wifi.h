#pragma once

#include <string>

#include "esp_err.h"
#include "idf_config.h"

struct IdfWifiStatus {
    bool staConnected = false;
    bool apMode = false;
    int rssi = 0;
    int channel = 0;
    std::string ssid;
    std::string ip;
    std::string gw;
    std::string mask;
    std::string dns;
    std::string mac;
    std::string bssid;
    std::string apSsid;
    std::string apIp;
};

struct IdfWifiScanSnapshot {
    std::string json = "[]";
    bool ready = false;
    bool busy = false;
    esp_err_t error = ESP_OK;
};

esp_err_t idf_wifi_start(const IdfConfig& config);
esp_err_t idf_wifi_reconnect(void);
// ESP-IDF uses 0.25dBm units; pass only discrete levels supported by the driver.
esp_err_t idf_wifi_set_tx_power(uint8_t quarter_dbm);
// Force an immediate NTP sync from the Web UI; returns ESP_ERR_INVALID_STATE when offline.
esp_err_t idf_wifi_resync_ntp(void);
// Start an asynchronous scan; coalesce with an active scan without waiting for radio completion.
esp_err_t idf_wifi_scan_request(void);
IdfWifiScanSnapshot idf_wifi_scan_get_snapshot(void);
// Legacy compatibility: start an async refresh and return the latest cache immediately, or [] before the first result.
esp_err_t idf_wifi_scan_json(std::string& out_json);
IdfWifiStatus idf_wifi_get_status(void);
// Lightweight AP/APSTA provisioning-mode query. Reads only the internal snapshot without esp_wifi/MAC/IP calls
// for the Web authentication fast path used by every request.
bool idf_wifi_is_ap_mode(void);
// Save WiFi and connect in place with APSTA without restarting; close the AP after a delay on success.
// Used by Web /wificonfig in AP mode while the provisioning page polls /apstatus for the assigned IP.
esp_err_t idf_wifi_provision_connect(const std::string& ssid, const std::string& pass);
