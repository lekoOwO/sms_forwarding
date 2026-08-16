# 系統架構

## 執行模型

韌體以 Arduino `loop()` 處理 UART、長簡訊逾時與有界工作佇列。HTTP 在獨立
FreeRTOS task 執行，但所有 `WebServer` 存取仍由該 task 串行處理。設定加密在
獨立 crypto task 執行，避免 PBKDF2 阻塞 UART。`modem.cpp` 的同步 dispatcher
仍是 `Serial1` 唯一 reader；一次只執行一個 transaction，並分流完整 URC。

核心全域服務由 `globals.cpp` 建立：`WebServer(80)`、NVS `Preferences`、
`PDU(4096)`、`WiFiClientSecure` 與 `SMTPClient`。

## 啟動順序

目前 `setup()` 的實際順序如下：

1. 初始化 LED、USB Serial 與 GPIO 4 RX / GPIO 3 TX 的 `Serial1`。
2. 以 GPIO 5 對模組斷電再上電。
3. 清空長簡訊緩衝，從獨立 `appcfg` NVS 的雙槽載入完整設定，再計算
   `configValid`。兩槽皆壞或 NVS 開啟失敗時管理 HTTP 不啟動，必須用 USB
   重刷或復原。
4. 連接 WiFi；20 秒未連上就重新啟動 ESP32。
5. 從 firmware 內嵌 gzip bundle 提供管理頁，註冊 HTTP route 與 CSRF header。
6. 嘗試 NTP 同步，然後將 SMTP 使用的 TLS client 設為不驗證憑證。
7. 設定有效時寄出啟動通知。
8. 執行 `modemInit()`：AT 握手、讀取型號、嘗試停用 PDP、設定簡訊 URC 與
   PDU 模式，最後等待 LTE 註冊。

AT 握手、`CNMI`、`CMGF` 與網路註冊都使用有限重試；失敗後保留管理頁並把
模組標成 degraded，而不是永久卡在啟動迴圈。ML307Y 不送已知不相容的
`CGACT=0,1`，資料面狀態呈現為 active 或 unknown。

## 主迴圈

`loop()` 每輪依序：

1. 執行一個有界 Web job，並處理 OTA 與設定傳輸逾時。
2. 設定無效時，每秒輸出管理頁位址提示。
3. 轉發超過 30 秒仍不完整的長簡訊。
4. 由 modem dispatcher 讀取並處理模組 UART。

Production build 不啟用 USB Serial 到 `Serial1` 的 raw byte bridge；開發 build
可用 compile-time flag 明確開啟。

## 簡訊資料流

```text
4G 模組 +CMT URC
  -> readSerialLine()
  -> 十六進位格式檢查
  -> pdulib decodePDU()
  -> 普通簡訊：processSmsContent()
     長簡訊：依 sender + reference number 暫存，收齊或 30 秒後合併
  -> 黑名單過濾
  -> 所有有效推送通道
  -> SMTP 通知
```

長簡訊上限來自 `config_types.h`：同時 5 組、每組 10 段。正常短信逾時時會
以缺段 marker best-effort 轉發；管理用途的短信不執行任何 `SMS:`/`RESET`
命令。緩衝滿時不驅逐仍在接收的 live message。超過 10 段的訊息不能只靠
編譯宣稱支援，需先調整界限並用 PDU fixture 或硬體報告驗證。

## 設定資料流

`handleSave()` 先複製 `Config next`，驗證請求中的完整欄位後只修改副本。
`saveConfig(next)` 將明確的 binary codec 寫到獨立 `appcfg` NVS：blob 包含
magic、schema、generation、payload length 與 CRC；`cfgA`/`cfgB` 採
blob → read-back/完整 decode → matching marker 的提交順序。marker 成功後才
替換 runtime `config`。斷電後只會選完整舊版或完整新版，不會混合多個 key。

第一次啟動會建立 generation 1。若雙槽完全不存在，loader 會讀取既有
`sms_config` multi-key 格式並遷移；舊 key 至少保留一版，但不 dual-write，
因此降級舊 firmware 只會看到遷移當時的 snapshot。兩槽存在但都無效時不會
回落到預設帳密。

設定有效的條件是完整 SMTP 設定，或至少一個通過 provider 必填欄位檢查
的推送通道。最多可設定十組 Web 帳密；空白使用者名稱會停用該組帳號。
Web 帳密、管理員號碼和黑名單不影響 `configValid`。舊版單一帳密會在讀取
時遷移到第一組帳號。

任何 NVS 欄位變更都必須同時處理：型別、load、save、舊設備預設值、Web
表單，以及必要的相容遷移。

`dev_doc/config-schema/manifest.json` 與版本化 JSON Schema 是設定格式的唯一
手寫來源。Generator 產生 firmware 常數與 Web limits。CI 會拒絕生成結果漂移。
備份檔以 PBKDF2-SHA256 與 AES-256-GCM 加密；還原會保留目標機的裝置名稱、
Hostname 與 Web 帳號。未知的新 schema 會被拒絕，不修改目前設定。

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

新增 provider 的完整修改點列在 `../code/AGENTS.md`。HTTP delivery 逐通道
同步執行、每個通道只嘗試一次、不建立持久 queue，兩個通道之間固定延遲
100 ms。2xx 只表示 provider 接受 request，不表示終端已收到通知。
DingTalk/Feishu 有 secret 時每次發送都重新檢查 epoch；時間無效即只跳過該
signed channel，不降級成 unsigned。

標題、內容與 Custom JSON 模板支援 `{sender}`、`{message}`、`{timestamp}`、
`{device}`、`{localNumber}`、`{ip}`、`{hostname}` 與 `{wifi}`。本機號碼來自
啟動時快取的 `AT+CNUM`。SIM 或營運商未提供號碼時，該值為空字串。

## 韌體版號與發佈

`firmware-version.json` 是版號的唯一手寫來源。`devBuild` 是從 1 開始遞增的
開發版號。`releaseVersion` 使用 `MAJOR.MINOR.PATCH`。Generator 產生韌體
header，CI 會拒絕來源與 header 不一致的變更。

`develop` 的成功建置會建立 GitHub Pre-release，並附上 USB 燒錄映像。此工作
不使用正式 OTA 私鑰。`master` 上相符的 `vMAJOR.MINOR.PATCH` tag 會建立含
簽章 OTA 套件的正式 Release。Dev UI 只顯示 `devBuild`。Release UI 顯示
`releaseVersion (devBuild)`。

## HTTP 管理面

所有已註冊 route 都由 handler 執行 HTTP Basic Auth。`/tools` 與 `/sms`
只是回傳同一份主頁的相容入口。

Machine-readable contract 位於 [`openapi.json`](openapi.json)。Route 或 payload
變更時，必須在同一個變更中更新該文件與 contract test。

操作端點統一回傳 `success`、穩定的 `code`、結構化 `data` 與錯誤用的
`detail`。前端依 `code` 顯示本地化狀態，並直接呈現 `data` 欄位；只有無法
安全解析的失敗回應才放入 `detail`，不應再從顯示字串反向解析資料。

管理頁原始碼在 `web/`。SvelteKit static build 把 JavaScript 與 CSS inline
進單一 HTML，再以 deterministic gzip 產生 `code/web_bundle.h`。管理頁與
firmware 使用同一個 OTA image。瀏覽器透過 JSON route 讀取狀態與執行操作。
密碼內容不會由設定 API 回傳。

| Method | Route | 用途與副作用 |
|---|---|---|
| GET | `/`、`/tools`、`/sms` | 從 firmware 串流 gzip 管理頁 |
| GET | `/api/config` | 回傳狀態、CSRF token 與不含密碼內容的設定 |
| POST/GET | `/api/config/export` | 建立並下載加密 `.smscfg` |
| POST | `/api/config/restore/start|chunk|finish` | 以不超過 8 KiB 區塊還原設定 |
| GET | `/api/jobs?id=...` | 查詢 queued、running 或完成結果 |
| POST | `/api/ota/start|chunk|finish` | 上傳並驗證已簽署 `.smsota` |
| POST | `/save` | 寫入 NVS、回傳 JSON；設定有效時寄通知信 |
| POST | `/sendsms` | 由模組發送簡訊並回傳 JSON |
| POST | `/ping` | 暫時啟用 PDP、Ping 8.8.8.8、再停用 PDP |
| GET | `/query?type=...` | 查 `ati`、`signal`、`siminfo`、`network`、`wifi` |
| GET | `/flight?action=...` | 查詢或變更 `CFUN` |
| GET | `/at?cmd=...` | bounded、單行 expert AT；不支援 prompt/data mode |
| GET | `/log?cursor=...&limit=...` | 依遞增 entry id 分頁讀取日誌 |
| GET | `/modem?action=...` | 重啟模組或查信號、營運商、IMEI |
| GET | `/wifi?action=restart` | 重新連接 WiFi |

這不是公開 Internet API。它使用明文 HTTP，第一組帳號預設為
`admin/admin123`，而且 AT、重啟與發送簡訊端點都有高權限副作用。僅應部署
在受信任網路，首次啟動後立即改密碼，不可將管理 port 直接暴露到 Internet。

patched WebServer 在配置 body/auth handler 之前限制 request line 2 KiB、headers
合計 8 KiB、body 16 KiB，超限分別回 414、431、413 並關閉連線。欄位另外
以 UTF-8 bytes 驗證；超限回 `ACTION_INPUT_TOO_LONG`，不截斷。推送頁每次只
送目前通道，避免同時提交五個大型 custom body。

所有修改狀態的 request 都必須帶 `/api/config` 取得的 `X-CSRF-Token`。大型
設定與 OTA 檔案使用單一 120 秒 upload session；每個 raw 區塊上限為 8 KiB，
HTTP body 以 Base64 傳輸，避免同步 WebServer 截斷二進位 NUL。Web job
同時最多三個 queued 或 running 項目。OTA package 以內建 P-256 public key
驗證 manifest，完成後由 bootloader 的 pending-verify 狀態決定確認或 rollback。

## 重要限制與敏感資料

- `code/wifi_config.h` 已被 Git 追蹤；`.gitignore` 中同名規則不會保護已
  追蹤檔案。提交前必須確認 diff 中沒有真實 WiFi 帳密。
- Compose 開發映像與 GitHub workflow 使用相同 ESP32 core、vendored pdulib
  與 ReadyMail 版本。版本與命令以 `development.md` 為準。
- `ssl_client.setInsecure()` 會停用 SMTP TLS 憑證驗證。
- 管理 HTTP、provider secrets 與 NVS 都不抵抗有實體存取權的攻擊者；目前不
  啟用 secure boot、flash encryption 或 NVS encryption。部署邊界必須把設備
  與 USB/serial access 視為受信任資產。
- 日誌與部分 HTTP delivery debug 會包含電話號碼和簡訊內容。將 Web 日誌
  與 Serial output 視為敏感資料。
- `SERIAL_BUFFER_SIZE` 是 500 bytes；超長行會整行丟棄，不保留截斷尾端。
- 韌體的 4G HTTP delivery 預設 fail-closed。部分 SIM／營運商會在 LTE 註冊後
  自動 attach 並重新啟用 default bearer；這不代表韌體會送出資料。以
  `CGATT=0` 強制停用 packet service 也會讓實測 ML307A 離開 LTE 註冊，因而
  無法收簡訊。ML307Y 則因已知相容性分支跳過 `AT+CGACT=0,1`。
- 2026-08-16 的同板 ML307A 私有 CA fixture 驗證顯示：NTP 同步後，嚴格
  TLS 1.2 MHTTP probe 可完成 server-auth handshake；錯誤憑證 probe 因中斷且
  沒有 server-side connection evidence，仍不得視為已驗證的拒絕路徑。測試後
  清除所有 MHTTP clients，並以 `CGATT=0` 確認 `CGACT: 1,0`；production
  firmware 仍維持 4G delivery fail-closed。

## 變更定位

| 想改的行為 | 先看 |
|---|---|
| 啟動、WiFi、NTP、route | `code/code.ino` |
| 設定欄位或相容性 | `config_types.h`、`config.cpp`、Web 表單 |
| AT 時序或簡訊發送 | `modem.cpp` |
| PDU、長簡訊、黑名單 | `sms_process.cpp` |
| SMTP 或推送格式 | `push.cpp` |
| 管理端點、驗證、日誌 | `web_handlers.cpp` |
| 頁面結構、翻譯與瀏覽器互動 | `web/src/`、`web/AGENTS.md` |
