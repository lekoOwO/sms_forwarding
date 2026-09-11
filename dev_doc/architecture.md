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
  ├─ idf_lpa         啟用碼、ES9+ 驗證、使用者確認與設定檔安裝
  ├─ idf_inbox       RAM 收件匣與寄件匣
  ├─ idf_logbuf      RAM 日誌環
  ├─ idf_pdu         PDU 編碼與解碼
  └─ web_assets      內嵌 gzip Web UI
```

開發版可選擇啟用 `main/usb_recovery.cpp`。設定載入成功後、WiFi 啟動前，韌體立即啟動
USB recovery。它是 USB Serial/JTAG 的唯一管理資料 owner，只提供狀態、WiFi 配網與
固定 18 個唯讀 modem query ID（`0x01` 至 `0x12`）。名稱依序為 `ati`、`cpin`、`cereg`、
`cops`、`cgatt`、`cgact`、`cgpaddr`、`iccid`、`csq`、`cesq`、`cfun`、`creg`、`cgreg`、
`ceer`、`cimi`、`cpol`、`cgdcont` 與 `msslcipher`。不接受任意 AT 命令。正式版不編譯
此來源。一般 USB console 輸出不等於 recovery endpoint。

The `msslcipher` query uses ID `0x12` and sends the exact command `AT+MSSLCIPHER=?`.
The 17 older queries keep their 96-byte response limit. `msslcipher` uses a separate 192-byte
response and frame budget. The owner parses the capability line incrementally, including lines longer
than its 768-byte carry, and emits only the bounded canonical summary
`+MSSLCIPHER: SUMMARY;v=1;known=0xNN;count=N;unknown=0|1` followed by `OK`.
The input grammar accepts one-to-four-digit hexadecimal IDs with an optional `0x` prefix, optional
ASCII spaces, and optional parentheses. The four known IDs are reported as bits; unknown duplicate
IDs are counted without retaining an ID set, while a token after `0xFFFF` IDs is rejected.
The host keeps the legacy bounded `+MSSLCIPHER: (...)` parser for compatibility/tests and accepts
the firmware summary with a `25+` top count bucket.
The result reports fixed support booleans, a bounded count, and `unknown_present`.
It also reports named filter telemetry booleans: `other_line_present`, `line_overflow`,
`contains_msslcipher_token`, `contains_exact_official_prefix_anywhere`,
`leading_whitespace_before_prefix`, `parentheses_present`, and `comma_present`.
`other_line_present` is `true` when the owner filter saw at least one non-final line rejected or moved by the exact response-prefix filter; the remaining fields describe only bounded line-shape observations.
An accepted overlong capability line can set `line_overflow` while leaving `other_line_present` false.
The result does not contain raw response text or unknown IDs. This change records no live hardware result.

`idf_modem` 是 UART1 的唯一 owner。其他元件透過有界 command queue 執行 AT 操作。

HTTP handler 不直接執行慢速 SMTP、推送、加密、OTA 或模組操作。這些操作使用現有 worker 與背景工作。

## Cellular data keepalive

Data keepalive uses the saved HTTP or HTTPS download URL. HTTP sends only a public GET
without credentials, custom headers, or a body. HTTP does not authenticate the server or
protect the transfer from modification. The response body is counted and discarded, never executed.
HTTP needs no CA lookup or probe. HTTPS retains its independent CA target and full certificate verification.
In the Web UI, save the URL and byte target. For HTTPS, select certificate setup. Setup needs device WiFi,
synchronized time, and browser Internet access. It reuses the Mozilla candidate selection
and device-side certificate validation used by cellular push. No push channel is required.
The existing HTTP URL remains unchanged. Support for HTTP does not enable the schedule.
URLs cannot contain login credentials, control characters, or fragments. The UI does not replace the scheme or host.

Manual execution uses the saved action even when the automatic schedule is disabled.
The first valid schedule initializes the baseline without sending data. Data execution
requires ML307A and home registration; roaming is refused. A saved eSIM selection is
restored after the action. Disabling mobile data does not prohibit keepalive: the request
can temporarily activate data, then restore its state. Other modem models fail explicitly.

The worker performs direct GET requests. HTTPS verifies the CA, hostname, and certificate dates.
The public cellular push API remains HTTPS-only. Each response allows a 64 KiB body
and separate 4 KiB headers. The worker allows eight requests and a 512 KiB target.
Requests share a two-minute budget plus bounded cleanup. Redirects and chunked responses remain unsupported. Cancellation
stops the next request; an in-flight request finishes its bounded operation and cleanup.
Received body bytes exclude headers, TLS, and network overhead. They estimate transfer
volume, not carrier billing, and do not prove that the carrier extended SIM validity.
Existing SMS/USSD actions, timestamp updates, retries, and maintenance notices remain.

The CA session uses a dedicated internal slot after the five push slots. Public push
queries still accept only channels 0–4. The keepalive CA routes accept no channel query.
Probe sessions bind the saved URL origin, configuration generation, nonce, and expiry.
Configuration changes invalidate pending installs. Stored CAs use the canonical HTTPS
origin, so paths on one origin can share a CA, but another host cannot inherit it.

Offline evidence: `components/idf_modem/test/test_keepalive.py` executes the production
bounded loop with mocked transport and clock boundaries. `test_keepalive_ca.py` executes
the production query parser and target dispatcher. The HTTPS wire fixture checks body
byte counts and synthetic plain HTTP requests with bounded cleanup. `mock_server/test/keepalive.test.mjs` checks separate CA targets, same-origin
reuse, stale nonces after URL changes, and cancellation. No hardware validation is claimed.

## 啟動流程

`app_main()` 依序執行下列動作：

1. 初始化預設 NVS、RAM 日誌、收件匣、network interface 與 event loop。
2. 從 `appcfg` NVS 載入設定。已提交但損壞的設定會 fail closed；開發版設定成功後立即啟動 USB recovery。
3. 啟動 WiFi、推送 worker、管理 HTTP、模組 task 與簡訊 task。WiFi 會自動選擇並重連已保存的設定檔。
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

### 轉發規則

新編輯器呈現純 CSV，欄位依序為 `type,pattern,action[,enabled]`。
儲存字串以前綴 `#!forward-rules-csv-v1` 加 LF 區分版本；介面自動處理此前綴。
逗號、雙引號與跨行欄位使用 CSV 雙引號，欄位內的雙引號寫成兩個。
動作清單仍以逗號分隔，因此多個動作必須放在同一個已加引號的 CSV 欄位。

沒有此前綴的設定繼續使用原有 Tab 規則，不猜測逗號代表新格式。
介面只在使用者確認後轉換，且拒絕會遺失忽略行或未知動作的轉換。
設定匯出與匯入仍保留原字串；轉換前後都受 2048-byte 上限約束。
CSV 的空比對內容或 `enabled=0` 不參與比對；空動作表示不選擇任何通道。

`kw` 區分大小寫；`from` 與 `re` 使用同一個不區分大小寫的 POSIX ERE 引擎，
並沿用 `\d`、`\w`、`\s` 轉換。第一條啟用且命中的規則決定動作，後面的規則不再執行。
沒有命中時沿用預設通知選擇；通道啟用、憑證、網路及重試限制仍由原轉發流程處理。
已標記但損壞的 CSV 不會退回全部通道，而是停止該次轉發。

`POST /api/rules/preview` 在既有有界背景工作中執行相同驗證器與比對器。
它只接受規則、來源號碼與測試文字，不儲存、不發送，也不記錄輸入文字。
結果列號是 CSV 原文的起始行號，不包含儲存前綴；跨行欄位會計入行數。
Mock 與展示模式的正規表示式只提供近似結果，不是裝置引擎的驗證證據。
[共用 fixtures](forward-rules-fixtures.json) 覆蓋 CSV 欄位與舊格式行為。

長簡訊最多同時合併五條、每條十段。十五分鐘未收到新段時先轉發含缺段標示的內容，
成功入隊後仍保留原段十五分鐘，供晚段補齊；此補齊窗口不因新段而延長。
窗口內相同 partial 不重發；補齊後發出一次標示「簡訊完整補充」的新通知，
不會修改已送出的 provider 通知。收件匣原文與轉發規則輸入不加此通知標示。
窗口結束、槽位不足或 reference 衝突時，先交付尚未交付的內容才清槽。
已交付的終結分段使用既有有界指紋 ring 去重；窗口內 partial 不進該 ring。
轉發入隊失敗時保留內容，可能延後清理；所有槽位仍是有界 RAM，重啟會丟失。
這些限制不保證恢復真正未收到的段，也不保證窗口結束後的晚段能補齊。

收件匣與寄件匣是有界 RAM ring。裝置重啟後，電話號碼與簡訊內容不會保留在 Flash。

收到的簡訊只會進入通知流程。韌體不會解析或執行簡訊內容中的遠端控制命令。

## 診斷顯示

註冊狀態與 CSQ 使用 [3GPP TS 27.007 v17.6](https://www.etsi.org/deliver/etsi_ts/127000_127099/127007/17.06.00_60/ts_127007v170600p.pdf)
的 CEREG／CSQ 定義。註冊值 5 表示漫遊註冊，不是本網註冊；它本身不能證明資料或簡訊可用。
未知值與未提供的數值保持未知，所有人話結果都保留可用鍵盤或觸控展開的原始欄位。

目前 `/query?type=signal` 的 `cesq` 是快取的 `rsrp,rsrq,csq` 三欄摘要，並非 AT+CESQ 的六欄回覆。
介面將既有 RSRP／RSRQ 標為估值，不從已換算的整數反推原始量測碼或半 dB 精度。
CSQ 0／31 表示上下界，99 與既有 `-999` sentinel 顯示未知，不換算成訊號百分比。

## 通知與網路邊界

`idf_push` 支援 SMTP 與 12 種推送 provider。Provider enum 由 `dev_doc/config-schema/v7.json` 的
`x-enumMapping` 定義，並由 `tools/generate-config-schema.py` 產生。

SMTP 僅使用 WiFi。推送在 4G-only 模式選擇 cellular 路徑。
混合模式優先使用已連線的 WiFi，否則選擇 cellular。WiFi-only 模式斷線時延後傳送。

Cellular 推送要求通道啟用 cellular 並使用 HTTPS 目標。
CA 必須綁定目標 origin，且 hash 相符。
GET 與 POST 推送都可使用符合上述條件的 cellular 路徑。
cellular GET 只接受 HTTPS、空 request body 與固定 GET method，rendered URL 上限為 4096 bytes；POST URL 上限維持 240 bytes，body 上限維持 4096 bytes。
模組、home registration 與 PDP 前置檢查仍須通過，資料與漫遊限制不因選擇路徑而放寬。

目前 `idf_modem_https` 使用 modem 的 MIP socket 提供 TCP。
ESP32 上的 Mbed TLS 執行 CA 與 hostname 驗證，並傳送 HTTPS。
此路徑與下方 Arduino 歷史紀錄中的 MHTTP 路徑不同。

[Counter42 R15](hardware-counter37.md#counter42-r15-successful-cellular-evidence) 記錄一次 cellular HTTP 200 與已確認的 cleanup。
該次 application-level success 仍為 `unknown`，不能推廣為其他目標或網路條件的成功保證。

心跳間隔可設定為 1 至 240 小時。時間未完成 NTP 同步時，scheduler 不會開始心跳計時。

## 實機證據

### 2026-08-24 ML307A 已註冊紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-24-ml307a-已註冊紀錄)。

### 2026-08-22 ML307A 未註冊歷史紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-22-ml307a-未註冊歷史紀錄)。

### 2026-08-16 Arduino 歷史 TLS 紀錄

完整觀察與證據限制見 [實機驗證紀錄](hardware-evidence.md#2026-08-16-arduino-歷史-tls-紀錄)。

## 設定與備份

`idf_config` 將設定保存在 `appcfg` NVS 的雙槽格式。每次更新會先完成編碼與讀回驗證，再更新有效 marker。

`dev_doc/config-schema/manifest.json` 是格式的手寫來源。目前 schema 為 v7，韌體可讀取 v1–v7。
只有推送通道使用非預設的 `cellularEnabled` 或 `cellularUrl` 時才寫入 v7，否則仍寫入 v6。
映像處於 pending verification 時，不允許首次從舊 schema 升為 v7。
欄位、相容寫入與大小限制見 [設定格式](config-schema/README.md)。

可攜備份使用 `.smscfg`。檔案以 PBKDF2-SHA256 與 AES-256-GCM 加密，最大長度為 32,828 bytes。

還原會保留目標裝置的名稱、hostname、管理帳號、SIM 身分與執行期 marker。WiFi、SMTP、推送、network mode 與 heartbeat 設定可攜。

## Web 與 API

管理頁原始碼位於 `web/`。SvelteKit static build 產生單頁 bundle，再由 `web/scripts/package.mjs` 產生 `code/web_assets.{h,cpp}`。

一般管理 request 使用 HTTP Basic Auth 與 `X-CSRF-Token`。管理連線使用明文 HTTP，因此只適合可信任的區域網路。

配網 AP 使用 `192.168.1.1`。只有 AP 位址上的配網 route 可以使用 OpenAPI 所列的受限例外。

API request、response、限制與狀態碼的唯一索引是 [openapi.json](openapi.json)。不要建立第二份手動 function 或 route 目錄。

### eSIM 安裝

eSIM 安裝沿用 Web 的單一背景工作與互斥准入。HTTP handler 只驗證輸入、建立工作或提交
使用者確認；ES9+ 與卡片操作由背景工作呼叫 `idf_lpa` 協調。等待網路或使用者回應時，不持有
卡片 session 或 Web 狀態鎖。安裝不會自動啟用設定檔。

伺服器驗證完成後，頁面顯示有界的設定檔名稱與電信業者名稱，並要求使用者同意。
只有業者要求時才顯示確認碼欄位。「稍後再安裝」使用非終止性的延期取消原因；逾時使用
timeout 原因。確認等待最多五分鐘，背景工作會自行逾時，不依賴瀏覽器輪詢。取消清理失敗
與安裝結果不確定各有固定狀態，不能据此自動重用啟用碼；業者訂單狀態仍由業者控制。

啟用碼與確認碼只在 RAM 中傳遞，韌體會清除擁有的字串，不寫入日誌或狀態回覆。
管理 HTTP 仍是明文，只能在可信任的區域網路提交這些資料。狀態只包含封閉階段名稱、
遮蔽的既有設定檔與確認時的顯示名稱，不回傳 EID、ICCID、伺服器位址或原始協定錯誤。
已安裝但通知未完成仍回報成功並附上提醒，避免提示使用者重複安裝。

目前只支援一般三欄啟用碼（可有 `LPA:` 前綴），拒絕額外選項與含政策規則限制的設定檔。
每個網路、卡片階段各自有界，不另設可能中斷卡片載入的整體工作 TTL。工作狀態只保留
最新一筆，直到下一工作或重新開機；瀏覽器以精確工作 ID 輪詢。Host fixture 與編譯檢查
不代表實機、電信業者或端到端安裝已通過驗證。

## 已簽章 OTA

Release workflow 只有在 readiness gate 通過時才提供 `.smsota`。USB 完整映像使用 `.bin`，且不能上傳至 Web OTA。

瀏覽器將 `.smsota` 拆成 manifest、P-256 簽章與 firmware payload。韌體依序驗證簽章、target、release counter、長度與 SHA-256。

上傳使用 `/api/ota/start`、`/api/ota/chunk` 與 `/api/ota/finish`。Web API 不提供 raw firmware upload。

新映像先進入 pending-verify 狀態。Health task 成功後才會確認映像，否則 bootloader 會回復上一版。

Web OTA 會寫入下一個 OTA app slot，大小上限為 1,920 KiB。
bootloader、partition table、`appcfg` 與 `coredump` 不由 Web OTA 寫入。
OTA metadata 會寫入 `otadata` 與 NVS。

目前 source 與 build check 已涵蓋 public-key signature、replay counter 與 rollback 設定。
只有 `SMS_OTA_TEST_KEY=1` 的非 release USB recovery build 會嵌入
ignored build profile 產生的 NON-PRODUCTION public key，並使用獨立的
`ota_test_meta` NVS namespace；正式版與一般開發版仍嵌入 production key，
並使用 `ota_meta`。
USB recovery 的使用者 `ota-state` 會顯示執行中韌體用於簽章驗證的
SubjectPublicKeyInfo DER SHA-256。這只是可觀察的 trust key identity，不是
attestation；被修改的韌體仍可回報任意值。`public_key_sha256: null` 只表示較舊韌體
無法觀察此欄位，不表示 production key。
`components/idf_web/OTA_RUNTIME_READY` 仍不存在。Production hardware rollback/replay evidence 與 matching production private key 仍不可用。
TEST-key OTA 已有 [實機驗收](hardware-evidence.md)，但 production OTA 發佈尚未開放。

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
