# 低成本簡訊轉發器

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | [English](README.en.md)

使用 ESP32-C3 與 ML307 系列 4G 模組接收簡訊，並自動轉寄到電子郵件或推送服務。

[管理頁 Demo](https://lekoowo.github.io/sms_forwarding/) · [影片教學](https://www.bilibili.com/video/BV1cSmABYEiX) · [舊版 LuatOS 分支](https://github.com/chenxuuu/sms_forwarding/tree/old-luatos)

> Demo 不會連接真實裝置，且停用備份、還原與 OTA 操作。

<img src="assets/photo.png" width="200" alt="ESP32-C3 與 ML307R-DC 簡訊轉發器" />

## 主要功能

- 透過 Web 管理頁設定及查看裝置狀態，支援繁中、簡中與英文。
- 將簡訊轉寄到電子郵件，或同時啟用最多五個推送通道。
- 每個推送通道可設定獨立名稱、標題模板與內文模板。
- 支援長簡訊合併、黑名單、Web 傳送簡訊及網路診斷。
- 可設定裝置名稱與 hostname，方便管理多台裝置。
- 可匯出加密設定備份，並還原到另一台裝置。
- 可從管理頁安裝已簽章的 OTA 更新，並在啟動失敗時回復舊版。
- 日誌只保留在 RAM 並採分頁載入，不會磨耗 flash。

裝置只將收到的簡訊用於通知轉寄，不會執行簡訊中的遠端控制指令。

## 推送服務

支援 POST JSON、Bark、GET、DingTalk、PushPlus、ServerChan、Custom JSON、Feishu、Gotify、Telegram、Discord Webhook 與 ntfy。

模板可使用傳送者、訊息、時間、裝置名稱、本機號碼、IP、hostname 與 WiFi 名稱。Custom JSON 可自訂完整 request body。

| 裝置概覽 | 推送通道與模板 |
|---|---|
| ![](assets/status.png) | ![](assets/notifications.png) |

## 硬體與接線

已驗證的組合為 ESP32-C3 Super Mini 與 ML307R-DC。裝置需要 4 MB flash、Nano SIM，以及適合當地電信網路的天線。

| ESP32-C3 | ML307R-DC |
|---|---|
| GPIO 3 (TX) | RX |
| GPIO 4 (RX) | TX |
| GPIO 5 | EN |
| GND | GND |
| 5V | VCC (5V) |

## 使用提醒

- 第一次從舊版分區升級時，請先備份設定，再透過 USB 完整清除並重刷。
- 預設管理帳號為 `admin`，密碼為 `admin123`。首次登入後請立即修改密碼。
- 管理頁使用明文 HTTP，僅適合受信任的區域網路。請勿直接公開到 Internet。
- 設定備份可能包含通知服務的 secret。請妥善保存備份檔與 passphrase。

## 開發文件

建置、燒錄、OTA 發佈、設定格式、API、架構與驗證流程請見 [`dev_doc/`](dev_doc/README.md)。
