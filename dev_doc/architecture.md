# 系統架構

## 執行模型

韌體使用標準 Arduino 單執行緒事件迴圈。HTTP、UART、長簡訊逾時、SMTP
與推送沒有獨立工作執行緒；任何阻塞操作都會推遲其他工作。現有 AT 等待
迴圈多半穿插 `server.handleClient()`，修改時須保留這項特性。

核心全域服務由 `globals.cpp` 建立：`WebServer(80)`、NVS `Preferences`、
`PDU(4096)`、`WiFiClientSecure` 與 `SMTPClient`。

## 啟動順序

目前 `setup()` 的實際順序如下：

1. 初始化 LED、USB Serial 與 GPIO 4 RX / GPIO 3 TX 的 `Serial1`。
2. 以 GPIO 5 對模組斷電再上電。
3. 清空長簡訊緩衝、從 NVS 載入設定並計算 `configValid`。
4. 連接 WiFi；20 秒未連上就重新啟動 ESP32。
5. 掛載 LittleFS，註冊並啟動 HTTP server，因此後續慢操作期間頁面已可存取。
6. 嘗試 NTP 同步，然後將 SMTP 使用的 TLS client 設為不驗證憑證。
7. 設定有效時寄出啟動通知。
8. 執行 `modemInit()`：AT 握手、讀取型號、停用 PDP、設定簡訊 URC 與
   PDU 模式，最後等待 LTE 註冊。

AT 握手、`CGACT`（ML307Y 除外）、`CNMI` 與 `CMGF` 目前會持續重試；網路
註冊最多輪詢 30 次。這兩種策略不可在文件中混為同一種有限重試。

## 主迴圈

`loop()` 每輪依序：

1. 處理一輪 HTTP client。
2. 設定無效時，每秒輸出管理頁位址提示。
3. 轉發超過 30 秒仍不完整的長簡訊。
4. 將 USB Serial 的一個 byte 透傳到模組 UART。
5. 讀取並處理一行模組 URC。

## 簡訊資料流

```text
4G 模組 +CMT URC
  -> readSerialLine()
  -> 十六進位格式檢查
  -> pdulib decodePDU()
  -> 普通簡訊：processSmsContent()
     長簡訊：依 sender + reference number 暫存，收齊或 30 秒後合併
  -> 黑名單過濾
  -> 管理員命令（SMS:號碼:內容 或 RESET），命中後不走一般通知
  -> 所有有效推送通道
  -> SMTP 通知
```

長簡訊上限來自 `config_types.h`：同時 5 組、每組 10 段。緩衝滿時覆蓋最
舊一組；逾時輸出會用 `[缺失分段N]` 標記缺段。超過 10 段的訊息不能只靠
編譯宣稱支援，需先調整界限並用 PDU fixture 或硬體報告驗證。

## 設定資料流

`handleSave()` 只更新請求中出現的表單區塊，再由 `saveConfig()` 寫入 NVS
namespace `sms_config`。`loadConfig()` 提供預設值，並可把舊 `httpUrl`/
`barkMode` 遷移到第一個推送通道。

設定有效的條件是完整 SMTP 設定，或至少一個通過 provider 必填欄位檢查
的推送通道。最多可設定十組 Web 帳密；空白使用者名稱會停用該組帳號。
Web 帳密、管理員號碼和黑名單不影響 `configValid`。舊版單一帳密會在讀取
時遷移到第一組帳號。

任何 NVS 欄位變更都必須同時處理：型別、load、save、舊設備預設值、Web
表單，以及必要的相容遷移。

## 推送 provider

裝置最多啟用五個通道；provider enum 共十種：

| 值 | Provider | 必填設定 |
|---:|---|---|
| 1 | POST JSON | URL |
| 2 | Bark | URL |
| 3 | GET | URL |
| 4 | DingTalk | URL；secret 選填 |
| 5 | PushPlus | token；URL 與 channel 選填 |
| 6 | ServerChan | SendKey；URL 選填 |
| 7 | Custom JSON body | URL 與 body template |
| 8 | Feishu | URL；secret 選填 |
| 9 | Gotify | URL 與 token |
| 10 | Telegram | chat ID 與 bot token；base URL 選填 |

新增 provider 的完整修改點列在 `../code/AGENTS.md`。HTTP delivery 目前逐
通道同步執行、不重試，兩個通道之間固定延遲 100 ms。

## HTTP 管理面

所有已註冊 route 都由 handler 執行 HTTP Basic Auth。`/tools` 與 `/sms`
只是回傳同一份主頁的相容入口。

Machine-readable contract 位於 [`openapi.json`](openapi.json)。Route 或 payload
變更時，必須在同一個變更中更新該文件與 contract test。

操作端點統一回傳 `success`、穩定的 `code`、結構化 `data` 與錯誤用的
`detail`。前端依 `code` 顯示本地化狀態，並直接呈現 `data` 欄位；只有無法
安全解析的失敗回應才放入 `detail`，不應再從顯示字串反向解析資料。

管理頁原始碼在 `web/`。SvelteKit static build 把 JavaScript 與 CSS 全部 inline
進單一 HTML，再以 deterministic gzip 產生 `code/data/index.html.gz`。韌體不把
頁面編入 app partition，而是從 LittleFS 串流檔案；瀏覽器載入後透過 JSON
route 讀取狀態與執行操作。密碼內容不會由設定 API 回傳。

| Method | Route | 用途與副作用 |
|---|---|---|
| GET | `/`、`/tools`、`/sms` | 從 LittleFS 串流 gzip 管理頁 |
| GET | `/api/config` | 回傳裝置狀態與不含密碼內容的設定 JSON |
| POST | `/save` | 寫入 NVS、回傳 JSON；設定有效時寄通知信 |
| POST | `/sendsms` | 由模組發送簡訊並回傳 JSON |
| POST | `/ping` | 暫時啟用 PDP、Ping 8.8.8.8、再停用 PDP |
| GET | `/query?type=...` | 查 `ati`、`signal`、`siminfo`、`network`、`wifi` |
| GET | `/flight?action=...` | 查詢或變更 `CFUN` |
| GET | `/at?cmd=...` | 任意 AT 指令透傳 |
| GET | `/log` | 回傳最多 120 行裝置日誌 |
| GET | `/modem?action=...` | 重啟模組或查信號、營運商、IMEI |
| GET | `/wifi?action=restart` | 重新連接 WiFi |

這不是公開 Internet API。它使用明文 HTTP，第一組帳號預設為
`admin/admin123`，而且 AT、重啟與發送簡訊端點都有高權限副作用。僅應部署
在受信任網路，首次啟動後立即改密碼，不可將管理 port 直接暴露到 Internet。

發送介面不限制輸入字數。韌體會依 GSM-7 或 UCS-2 編碼切割長訊息，單次
請求最多 255 段；實際模組與電信網路相容性仍須用硬體驗證。

## 重要限制與敏感資料

- `code/wifi_config.h` 已被 Git 追蹤；`.gitignore` 中同名規則不會保護已
  追蹤檔案。提交前必須確認 diff 中沒有真實 WiFi 帳密。
- Compose 開發映像與 GitHub workflow 使用相同 ESP32 core、pdulib 與
  ReadyMail 版本。版本與命令以 `development.md` 為準。
- `ssl_client.setInsecure()` 會停用 SMTP TLS 憑證驗證。
- 日誌與部分 HTTP delivery debug 會包含電話號碼和簡訊內容。將 Web 日誌
  與 Serial output 視為敏感資料。
- `SERIAL_BUFFER_SIZE` 是 500 bytes；超長行目前會從頭覆寫累積位置。
- 模組資料面預設停用，但 ML307Y 因已知相容性分支會跳過啟動時的
  `AT+CGACT=0,1`。

## 變更定位

| 想改的行為 | 先看 |
|---|---|
| 啟動、WiFi、NTP、route | `code/code.ino` |
| 設定欄位或相容性 | `config_types.h`、`config.cpp`、Web 表單 |
| AT 時序或簡訊發送 | `modem.cpp` |
| PDU、長簡訊、黑名單、管理員命令 | `sms_process.cpp` |
| SMTP 或推送格式 | `push.cpp` |
| 管理端點、驗證、日誌 | `web_handlers.cpp` |
| 頁面結構、翻譯與瀏覽器互動 | `web/src/`、`web/AGENTS.md` |
