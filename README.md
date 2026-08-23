# 低成本簡訊轉發器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

使用 ESP32-C3 與 ML307 系列 4G 模組接收簡訊，並透過 WiFi 轉發到 Email 或推送服務。

[管理頁 Demo](https://lekoowo.github.io/sms_forwarding/)

> Demo 不會連接真實裝置，且停用備份、還原與 OTA 操作。

<p>
  <a href="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml"><img alt="CI" src="https://github.com/lekoOwO/sms_forwarding/actions/workflows/build.yml/badge.svg" /></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-green.svg" /></a>
</p>

## 主要功能

- 原生 ESP-IDF 韌體與三語 Web 管理頁，支援繁體中文、簡體中文與英文。
- 支援 PDU、Unicode、長簡訊合併、去重、黑名單、RAM 收件匣及 Web 簡訊發送。
- 可使用 SMTP，或同時啟用最多五個推送通道。
- 支援 POST JSON、Bark、GET、釘釘、PushPlus、Server 醬、自訂 JSON、飛書、Gotify、Telegram、Discord Webhook 與 ntfy。
- 每個推送通道可設定名稱、標題範本、內容範本及轉發規則，並可單獨測試。
- 可保存五組 WiFi 設定檔。裝置會自動選擇、連線並重連可用的已保存網路。
- 開發版可在設定載入成功後、WiFi 啟動前提供 USB recovery；正式版不編譯此路徑。
- USB recovery 只接受固定 17 個唯讀 modem query ID（`0x01` 至 `0x11`）與 WiFi 配網命令。一般 USB console 不等於 recovery endpoint。
- 可設定每 1 至 240 小時發送心跳通知。NTP 時間同步完成後，心跳計時才會開始。
- 可匯出加密 `.smscfg` 設定備份，並將可攜設定還原至另一台裝置。
- Web OTA 只接受已簽章的 `.smsota` 套件。Release 只有通過 readiness gate 才會發佈此套件。
- Web 頁尾會顯示韌體版本。正式版顯示 `releaseVersion (devBuild)`，開發版顯示 `devBuild`。

> 通知目前只透過 WiFi 傳送。裝置會保存 4G 與混合模式選項，但 TLS 或網路註冊未經驗證時，4G push 會 fail closed。現有實機證據沒有證明 4G 資料傳送可用。GET 與 ntfy 僅支援 WiFi。

## 快速開始

1. 從 [Releases](https://github.com/lekoOwO/sms_forwarding/releases) 下載 `sms-forwarder-VERSION.bin` 完整映像。
2. 使用樂鑫 [Flash Download Tool](https://docs.espressif.com/projects/esp-test-tools/en/latest/esp32c3/production_stage/tools/flash_download_tool.html) 或 [ESP Launchpad](https://espressif.github.io/esp-launchpad/) 將映像燒錄至位址 `0x0`。
3. 裝置找不到已保存的 WiFi 時，連線至 `SMS-Forwarder-XXXXXX`。
4. 輸入密碼 `sms-forwarder-setup`，然後開啟 `http://192.168.1.1`。
5. 裝置連線至路由器後，使用管理頁顯示的區網位址登入。
6. 使用管理帳號 `admin` 與密碼 `admin123` 登入。首次登入後立即修改密碼。
7. 設定 Email 或推送通道，並使用通道測試確認傳送結果。

### 後續 OTA 更新

從已通過 readiness gate 的 Release 下載 `sms-forwarder-VERSION.smsota`。在管理頁開啟「系統設定 → 韌體更新」，然後選擇此檔案。

**請勿將 `.bin` 檔案上傳至 Web OTA。** `.bin` 是從 `0x0` 燒錄的 USB 完整映像，`.smsota` 才是已簽章的 Web OTA 套件。
Web OTA 會寫入一個 OTA app slot，大小上限為 1,920 KiB。不會寫入 bootloader、partition table、`appcfg` 或 `coredump`，並會將 OTA metadata 寫入 `otadata` 與 NVS。

## 硬體與接線

已測試的組合是 ESP32-C3 Super Mini 與 ML307R-DC。裝置需要 4 MB Flash、Nano SIM 與適合當地網路的天線。

<img src="assets/photo.png" width="200" alt="ESP32-C3 與 ML307R-DC 簡訊轉發器" />

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 安全提醒

- 管理頁使用明文 HTTP。只可在可信任的區域網路使用，且不可直接公開至 Internet。
- 加密設定備份包含 WiFi、SMTP 與推送憑證。請分開保存備份檔案與密碼片語。
- 裝置只將收到的簡訊用於通知轉發，不會執行簡訊內容中的遠端控制命令。

## 開發文件

建置、燒錄、發佈、架構、設定格式、API 與驗證流程請見 [`dev_doc/`](dev_doc/README.md)。

## 致謝

感謝 [LINUX DO](https://linux.do) 社群提供交流與靈感。
