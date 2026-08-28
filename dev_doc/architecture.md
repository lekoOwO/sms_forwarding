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

收件匣與寄件匣是有界 RAM ring。裝置重啟後，電話號碼與簡訊內容不會保留在 Flash。

收到的簡訊只會進入通知流程。韌體不會解析或執行簡訊內容中的遠端控制命令。

## 通知與網路邊界

`idf_push` 支援 SMTP 與 12 種推送 provider。Provider enum 由 `dev_doc/config-schema/v6.json` 的
`x-enumMapping` 定義，並由 `tools/generate-config-schema.py` 產生。

目前通知傳送只使用 WiFi。4G-only 模式會回傳 unsupported，混合模式在 WiFi 中斷時會 defer。

4G push 目前不支援。TLS 或網路註冊未經驗證時，4G push 會 fail closed。
GET 與 ntfy 僅支援 WiFi，漫遊傳送與資料啟用維持 fail closed。
現有實機證據沒有證明 4G data delivery 可用。

`idf_modem_https` 依 OneMO ML307A 的 SSL context 語意使用 context 1。每次建立 MHTTP
instance 前，先刪除殘留的 `MHTTP` instance，再完成憑證、auth、version 等設定，並在
`AT+MHTTPCREATE` 前依序送出：`AT+MSSLCFG="ciphersuite",1,0`（使用全部支援的
cipher suites）與 `AT+MSSLCFG="session",1,0`（停用 TLS session reuse/cache）。這讓
共用 context 1 在不同 host 間不沿用未明載的設定。這是 OneMO 指令語意與 host transcript
所證明的 wire 設定，不是 provider push 成功證據。

心跳間隔可設定為 1 至 240 小時。時間未完成 NTP 同步時，scheduler 不會開始心跳計時。

## 實機證據

### 2026-08-24 ML307A 已註冊紀錄

這是單次去識別化的唯讀硬體紀錄，不是通用的 modem protocol fact：

- 板型與韌體版本：去識別化摘要未記錄。`device.py doctor` 回報 `ready=true` 與 `host_read_write=true`。
- 模組與輸入：ML307A；唯讀輸入為 `CPIN`、`CEREG`、`COPS`、`CGATT`、`CGACT` 與 `CGPADDR` 查詢。
- 結果：`CPIN` ready；`CEREG stat=1` 是 home registered、E-UTRAN 且 `roaming=false`。
  `COPS` 是 automatic，operator present，且 access technology 是 E-UTRAN。
  `CGATT` 是 attached；`CGACT` 只有一個 active context。
- `CGPADDR` 結構只有一個有效回覆行與一個 CID。該 CID 同時有 IPv4 與 IPv6。
- `cc10c2a` 提供 `CGPADDR` sanitizer 結構；`41d3708` 提供 runtime dual-stack parser。

文件不記錄 operator、ICCID、IMSI、IMEI、address、APN 或 credential 值。
此次操作沒有使用 write AT、manual `COPS`，也沒有執行 `CFUN`、`CGATT`、`CGACT` 或 PDP 狀態變更。
這份紀錄不證明 Internet、TLS 或 provider delivery 可用。4G push 維持 fail closed。

### 2026-08-22 ML307A 未註冊歷史紀錄

這是較早的單次去識別化硬體紀錄，不是通用的 modem protocol fact：

- 板型：去識別化報告未記錄。
- 模組：ML307A。
- 輸入：`CPIN`、`CSQ`、`CESQ`、`CEREG`、`COPS`、`CGATT`、`CGACT`、`CGPADDR` 與 `ICCID` 查詢。
- 結果：`CPIN` ready；`CSQ=31`；`CESQ` 約為 RSRP -70 dBm；`COPS` 使用 auto 選擇但 operator absent；原始註冊回覆只記錄 `+CEREG: 0,11`。
  依 3GPP 定義，`stat=11` 是 RLOS-only；`n=0` 只控制 URC 詳細度。它不是 home、roaming 或 data-ready 狀態。
  另見 `CGATT=0`、PDP inactive、no IP；ICCID 只保留 hash。
- 識別資料已去識別化保存。

這次結果表示 SIM 與 RF 路徑有回應，但尚未完成標準網路註冊與資料啟用。
它不證明 4G 可用；韌體因此不會把 4G push、roaming 或 data activation 視為已成功。

### 2026-08-16 Arduino 歷史 TLS 紀錄

這份去識別化紀錄來自 `origin/develop` 的 Arduino 韌體，不是目前原生 ESP-IDF runtime 的實機證據：

- 板型、模組與輸入：ESP32-C3、ML307A，以及 NTP 同步後的嚴格 TLS 1.2 MHTTP private-CA probe。
- 結果：伺服器端確認正向 server-auth handshake 完成。
- 證據邊界：wrong-certificate、hostname mismatch 與 expired-certificate rejection 都沒有可信的負向證據。

此紀錄不證明目前原生 ESP-IDF 的 4G provider delivery 或 readiness。4G push 維持 fail closed。

## 設定與備份

`idf_config` 將設定保存在 `appcfg` NVS 的雙槽格式。每次更新會先完成編碼與讀回驗證，再更新有效 marker。

`dev_doc/config-schema/manifest.json` 是格式的手寫來源。版本化 JSON Schema 保留 v1-v5 相容讀取邊界。目前版本為 v6，並追加 `kaTrafficKB`。

可攜備份使用 `.smscfg`。檔案以 PBKDF2-SHA256 與 AES-256-GCM 加密，最大長度為 32,828 bytes。

還原會保留目標裝置的名稱、hostname、管理帳號、SIM 身分與執行期 marker。WiFi、SMTP、推送、network mode 與 heartbeat 設定可攜。

## Web 與 API

管理頁原始碼位於 `web/`。SvelteKit static build 產生單頁 bundle，再由 `web/scripts/package.mjs` 產生 `code/web_assets.{h,cpp}`。

一般管理 request 使用 HTTP Basic Auth 與 `X-CSRF-Token`。管理連線使用明文 HTTP，因此只適合可信任的區域網路。

配網 AP 使用 `192.168.1.1`。只有 AP 位址上的配網 route 可以使用 OpenAPI 所列的受限例外。

API request、response、限制與狀態碼的唯一索引是 [openapi.json](openapi.json)。不要建立第二份手動 function 或 route 目錄。

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
因此目前不能宣稱 signed OTA 已達到 READY。

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
