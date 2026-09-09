# 低成本簡訊轉發器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

用 ESP32-C3 與 ML307 系列 4G 模組，把 SIM 卡收到的簡訊轉發到 Email 或推送服務。日常設定、查看簡訊與診斷都可在瀏覽器完成。

[下載韌體](https://github.com/lekoOwO/sms_forwarding/releases) · [試用管理頁](https://lekoowo.github.io/sms_forwarding/) · [回報問題](https://github.com/lekoOwO/sms_forwarding/issues)

Demo 不會連接真實裝置，也不會執行備份、還原或韌體更新。

## 可以做什麼

- 將簡訊轉發到 Email，或同時使用最多五個推送通道。
  - 支援 Bark、Telegram、Discord Webhook、Gotify、ntfy、釘釘、飛書、PushPlus、Server 醬，以及自訂 GET／JSON 請求。
- 依來源號碼或內容設定轉發規則，並自訂通知標題與內容。
- 在管理頁查看、發送簡訊，查詢訊號、SIM 與模組資訊。
- 保存最多五組 WiFi，設定心跳通知，匯出加密設定備份。
- 管理相容 eSIM 卡的設定檔，實際功能依卡片、模組與電信業者而異。
- 管理頁提供繁體中文、簡體中文與英文。

Email 只透過 WiFi 傳送。使用 4G 推送前，請確認行動網路可用，並啟用通道的行動網路功能與 HTTPS 憑證。目前不支援漫遊時的 4G 推送。實際可用性取決於模組、SIM 卡與網路。

## 準備硬體

- ESP32-C3 開發板，至少 4 MB Flash。
- ML307 系列模組、可接收簡訊的 SIM 卡與合適的天線。
- 穩定電源、USB 線，以及首次設定用的 WiFi 網路。

以下接線以 ESP32-C3 Super Mini 與 ML307R-DC 轉接板為例。其他板型請先確認供電電壓，勿將裸模組直接接到 5V。

<img src="assets/photo.png" width="200" alt="ESP32-C3 與 ML307R-DC 簡訊轉發器" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 首次使用

1. 從 [Releases](https://github.com/lekoOwO/sms_forwarding/releases) 下載 `sms-forwarder-VERSION.bin`。標示 Pre-release 的版本供測試使用。
2. 使用樂鑫 [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) 或 [ESP Launchpad](https://espressif.github.io/esp-launchpad/)，將完整映像燒錄至 `0x0`。
3. 裝置找不到已保存的 WiFi 時，連線至 `SMS-Forwarder-XXXXXX`，密碼為 `sms-forwarder-setup`。
4. 開啟 `http://192.168.1.1`，選擇家中或辦公室的 WiFi 並輸入密碼。
5. 配網完成後，讓電腦或手機連回同一個區域網路。開啟配網頁顯示的裝置位址。
6. 使用帳號 `admin`、密碼 `admin123` 登入，並立即修改管理密碼。
7. 設定 Email 或推送通道，使用通道測試確認通知能送達。

## 備份與更新

管理頁可匯出加密的 `.smscfg` 設定備份。請將備份檔案與密碼片語分開保存。備份包含 WiFi、Email 與推送憑證。

Web 韌體更新只接受適用於本裝置的已簽章 `.smsota` 套件。如果下載頁只有 `.bin`，請使用 USB 燒錄方式。請勿把 `.bin` 上傳到 Web 更新頁。

目前開發版下載提供 USB 完整映像，正式簽章 OTA 套件尚未開放發佈。

## 使用前請注意

- 管理頁使用明文 HTTP。只在可信任的區域網路使用，不要直接公開到 Internet。
- 收件匣與寄件匣不會永久保存簡訊，裝置重啟後會清空。
- 裝置不會執行簡訊內容中的遠端控制命令。
- 發送簡訊或使用行動數據可能產生電信費用。

## 開發與致謝

原始碼建置、架構與測試說明統一放在 [開發文件](dev_doc/README.md)。本專案使用 [MIT 授權](LICENSE)。

本專案衍生自 [MineSunshineone/sms_forwarding](https://github.com/MineSunshineone/sms_forwarding)。感謝上游維護者與貢獻者，也感謝 [LINUX DO](https://linux.do) 社群的交流與分享。
