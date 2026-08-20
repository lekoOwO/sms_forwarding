# 系統架構

## 元件地圖

```text
main/app_main.cpp
  ├─ idf_config      NVS 設定、版本相容、加密備份與還原
  ├─ idf_wifi        STA、SoftAP 配網、DNS、mDNS、SNTP 與重連
  ├─ idf_modem       UART1 owner、AT dispatcher、SIM 與行動網路操作
  ├─ idf_sms         PDU 收發、長簡訊、去重、黑名單與轉發入隊
  ├─ idf_push        SMTP、推送通道、範本、規則、重試與心跳
  ├─ idf_web         HTTP API、Web UI、背景工作、排程與 OTA
  ├─ idf_esim        eUICC APDU 與 Profile 操作
  ├─ idf_inbox       RAM 收件匣與寄件匣
  ├─ idf_logbuf      RAM 日誌環
  ├─ idf_pdu         PDU 編碼與解碼
  └─ web_assets      內嵌 gzip Web UI
```

`idf_modem` 是 UART1 的唯一 owner。其他元件透過有界 command queue 執行 AT 操作。

HTTP handler 不直接執行慢速 SMTP、推送、加密、OTA 或模組操作。這些操作使用現有 worker 與背景工作。

## 啟動流程

`app_main()` 依序執行下列動作：

1. 初始化預設 NVS、RAM 日誌、收件匣、network interface 與 event loop。
2. 從 `appcfg` NVS 載入設定。已提交但損壞的設定會 fail closed。
3. 啟動 WiFi、推送 worker、管理 HTTP、模組 task 與簡訊 task。
4. 啟動 OTA health task。新映像必須在期限內通過 HTTP 與網路可達性檢查。

設定載入失敗時，執行期服務不會使用預設管理帳密覆蓋既有資料。

## 簡訊資料流

```text
+CMT / +CMTI / AT+CMGL
  -> idf_modem UART dispatcher
  -> idf_sms PDU decode
  -> 長簡訊合併 / 去重 / 黑名單
  -> idf_inbox RAM 留存
  -> idf_push forward queue
  -> 轉發規則
  -> SMTP / 最多五個推送通道
```

接收流程同時使用 URC 與 SIM 儲存輪詢。精確去重避免雙路徑重複轉發。

收件匣與寄件匣是有界 RAM ring。裝置重啟後，電話號碼與簡訊內容不會保留在 Flash。

收到的簡訊只會進入通知流程。韌體不會解析或執行簡訊內容中的遠端控制命令。

## 通知與網路邊界

`idf_push` 支援 SMTP 與 12 種推送 provider。Provider enum 的唯一來源是 `config-schema/manifest.json`。

目前通知傳送只使用 WiFi。4G-only 模式會回傳 unsupported，混合模式在 WiFi 中斷時會 defer。

在 CA provisioning 完成前，行動網路推送會 fail closed。GET 與 ntfy 僅支援 WiFi，漫遊傳送一律 fail closed。

心跳間隔可設定為 1 至 240 小時。時間未完成 NTP 同步時，scheduler 不會開始心跳計時。

## 設定與備份

`idf_config` 將設定保存在 `appcfg` NVS 的雙槽格式。每次更新會先完成編碼與讀回驗證，再更新有效 marker。

`dev_doc/config-schema/manifest.json` 是格式的手寫來源。版本化 JSON Schema 保留舊版讀取邊界，目前版本為 v5。

可攜備份使用 `.smscfg`。檔案以 PBKDF2-SHA256 與 AES-256-GCM 加密，最大長度為 32,828 bytes。

還原會保留目標裝置的名稱、hostname、管理帳號、SIM 身分與執行期 marker。WiFi、SMTP、推送、network mode 與 heartbeat 設定可攜。

## Web 與 API

管理頁原始碼位於 `web/`。SvelteKit static build 產生單頁 bundle，再由 `web/scripts/package.mjs` 產生 `code/web_assets.{h,cpp}`。

一般管理 request 使用 HTTP Basic Auth 與 `X-CSRF-Token`。管理連線使用明文 HTTP，因此只適合可信任的區域網路。

配網 AP 使用 `192.168.1.1`。只有 AP 位址上的配網 route 可以使用 OpenAPI 所列的受限例外。

API request、response、限制與狀態碼的唯一索引是 [openapi.json](openapi.json)。不要建立第二份手動 function 或 route 目錄。

## 已簽章 OTA

正式 Release 提供 `.smsota`。USB 完整映像使用 `.bin`，且不能上傳至 Web OTA。

瀏覽器將 `.smsota` 拆成 manifest、P-256 簽章與 firmware payload。韌體依序驗證簽章、target、release counter、長度與 SHA-256。

上傳使用 `/api/ota/start`、`/api/ota/chunk` 與 `/api/ota/finish`。Web API 不提供 raw firmware upload。

新映像先進入 pending-verify 狀態。Health task 成功後才會確認映像，否則 bootloader 會回復上一版。

## 分區

預設 4 MiB Flash 使用下列分區：

| 分區 | 大小 | 用途 |
|---|---:|---|
| `nvs` | 20 KiB | ESP-IDF 與舊設定遷移來源 |
| `otadata` | 8 KiB | OTA 啟動選擇 |
| `app0` | 1,920 KiB | OTA slot 0 |
| `app1` | 1,920 KiB | OTA slot 1 |
| `appcfg` | 128 KiB | 應用程式設定 |
| `coredump` | 64 KiB | Flash coredump |

本專案沒有持久化 `smsdata` 或 `inbox` 分區。
